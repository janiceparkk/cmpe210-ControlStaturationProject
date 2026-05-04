#!/usr/bin/env python3
import csv
import io
import json
import os
import time
import xml.etree.ElementTree as ET
from collections import defaultdict, deque

from ryu.app import simple_switch_13
from ryu.app.wsgi import WSGIApplication
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4

from app.api import RestApiController


class MitigationEngine(simple_switch_13.SimpleSwitch13):
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(MitigationEngine, self).__init__(*args, **kwargs)

        self.switches = {}

        self.start_time = time.time()
        self.config = {
            "window_seconds": 5,
            "packet_in_rate_threshold": 200.0,
            "table_miss_rate_threshold": 200.0,
            "consecutive_windows": 2,
            "alert_cooldown_seconds": 5,
            "mitigation_mode": "auto",
        }

        self.metrics = {}
        self.alerts = deque(maxlen=200)
        self.mitigation_log = deque(maxlen=500)

        self.reports = {}
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)

        self.detection_enabled = True

        self._pktin_times = defaultdict(lambda: deque(maxlen=200000))
        self._miss_times = defaultdict(lambda: deque(maxlen=200000))
        self._src_ip_times = defaultdict(lambda: defaultdict(lambda: deque(maxlen=50000)))

        self._streak = defaultdict(int)
        self._last_alert_ts = defaultdict(lambda: 0.0)

        self._TABLE_MISS_COOKIE = 0xA11CE
        self._mitigation_cookie = 0xD00D
        self._meter_id = 1

        self._port_bytes_prev = defaultdict(dict)
        self._flow_count_prev = defaultdict(lambda: (0, 0.0))

        wsgi = kwargs["wsgi"]
        wsgi.register(RestApiController, {"engine": self})

        self._monitor_thread = hub.spawn(self._monitor_loop)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        self.switches[dp.id] = dp
        self.mac_to_port.setdefault(dp.id, {})

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=0,
            match=match,
            instructions=inst,
            cookie=self._TABLE_MISS_COOKIE
        )
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        now = time.time()
        dpid = str(dp.id)

        self._pktin_times[dpid].append(now)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip4 = pkt.get_protocol(ipv4.ipv4)

        if ip4:
            self._src_ip_times[dpid][ip4.src].append(now)

        is_miss = False

        if getattr(msg, "cookie", None) == self._TABLE_MISS_COOKIE:
            is_miss = True
        else:
            if eth and eth.ethertype != ether_types.ETH_TYPE_LLDP:
                dst = eth.dst
                mac_table = self.mac_to_port.get(dp.id, {})
                if dst not in mac_table:
                    is_miss = True

        if is_miss:
            self._miss_times[dpid].append(now)

        super(MitigationEngine, self)._packet_in_handler(ev)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        dpid = str(dp.id)
        now = time.time()

        flow_count = len(ev.msg.body)

        self.metrics.setdefault(dpid, {})
        self.metrics[dpid].update({
            "flow_count": flow_count,
            "flow_stats_last_updated": now,
        })

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        dpid = str(dp.id)
        now = time.time()

        per_port = {}
        prev_map = self._port_bytes_prev[dp.id]

        for stat in ev.msg.body:
            port_no = stat.port_no
            rx_bytes = stat.rx_bytes
            tx_bytes = stat.tx_bytes

            rx_rate_Bps = None
            tx_rate_Bps = None

            if port_no in prev_map:
                prev_rx, prev_tx, prev_ts = prev_map[port_no]
                dt = now - prev_ts
                if dt > 0:
                    rx_rate_Bps = (rx_bytes - prev_rx) / dt
                    tx_rate_Bps = (tx_bytes - prev_tx) / dt

            prev_map[port_no] = (rx_bytes, tx_bytes, now)

            per_port[str(port_no)] = {
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "rx_rate_Bps": round(rx_rate_Bps, 3) if rx_rate_Bps is not None else None,
                "tx_rate_Bps": round(tx_rate_Bps, 3) if tx_rate_Bps is not None else None,
            }

        self.metrics.setdefault(dpid, {})
        self.metrics[dpid].update({
            "port_stats_last_updated": now,
            "ports": per_port,
        })

    def get_switch_dpids(self):
        return sorted([str(dpid) for dpid in self.switches.keys()], key=lambda s: int(s))

    def _monitor_loop(self):
        last_stats_poll = 0.0

        while True:
            now = time.time()

            self._update_rate_metrics(now)

            for dpid_int in list(self.switches.keys()):
                self._run_detection(str(dpid_int), now)

            if now - last_stats_poll >= 2.0:
                for dp in list(self.switches.values()):
                    self._request_stats(dp)
                last_stats_poll = now

            hub.sleep(1)

    def _update_rate_metrics(self, now):
        window = float(self.config.get("window_seconds", 5))

        for dpid_int in list(self.switches.keys()):
            dpid = str(dpid_int)

            pq = self._pktin_times[dpid]
            while pq and (now - pq[0]) > window:
                pq.popleft()

            pktin_count = len(pq)
            pktin_rate = (pktin_count / window) if window > 0 else 0.0

            mq = self._miss_times[dpid]
            while mq and (now - mq[0]) > window:
                mq.popleft()

            miss_count = len(mq)
            miss_rate = (miss_count / window) if window > 0 else 0.0

            self.metrics.setdefault(dpid, {})
            self.metrics[dpid].update({
                "last_updated": now,
                "window_seconds": window,
                "packet_in_count_in_window": pktin_count,
                "packet_in_rate": round(pktin_rate, 3),
                "table_miss_count_in_window": miss_count,
                "table_miss_rate": round(miss_rate, 3),
                "top_sources": self._top_attack_sources(dpid, now),
            })

        self.metrics.setdefault("global", {})
        self.metrics["global"].update({
            "last_updated": now,
            "connected_switches": len(self.switches),
        })

    def _run_detection(self, dpid, now):
        if not self.detection_enabled:
            self._streak[dpid] = 0
            return

        window = float(self.config.get("window_seconds", 5))
        need = int(self.config.get("consecutive_windows", 2))
        cooldown = float(self.config.get("alert_cooldown_seconds", 5))

        pktin_thr = float(self.config.get("packet_in_rate_threshold", 200.0))
        miss_thr = float(self.config.get("table_miss_rate_threshold", 200.0))

        m = self.metrics.get(dpid, {})
        pktin_rate = float(m.get("packet_in_rate", 0.0))
        miss_rate = float(m.get("table_miss_rate", 0.0))

        trigger = (pktin_rate >= pktin_thr) or (miss_rate >= miss_thr)

        if trigger:
            self._streak[dpid] += 1
        else:
            self._streak[dpid] = 0

        if self._streak[dpid] == need:
            if (now - self._last_alert_ts[dpid]) < cooldown:
                return

            alert = {
                "ts": now,
                "dpid": dpid,
                "type": "CONTROL_PLANE_SATURATION_SUSPECT",
                "window_seconds": window,
                "packet_in_rate": pktin_rate,
                "packet_in_rate_threshold": pktin_thr,
                "table_miss_rate": miss_rate,
                "table_miss_rate_threshold": miss_thr,
                "consecutive_windows": need,
            }

            self.alerts.append(alert)
            self._last_alert_ts[dpid] = now

            if self.config.get("mitigation_mode", "auto") == "auto":
                top_sources = self._top_attack_sources(dpid, now)
                if top_sources:
                    self.mitigate(
                        dpid=dpid,
                        action="drop",
                        src_ip=top_sources[0]["src_ip"],
                        reason="auto_detection"
                    )

    def _request_stats(self, dp):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        dp.send_msg(parser.OFPFlowStatsRequest(dp))
        dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY))

    def _get_dp(self, dpid):
        try:
            return self.switches.get(int(dpid))
        except Exception:
            return None

    def _top_attack_sources(self, dpid, now=None):
        now = now or time.time()
        window = float(self.config.get("window_seconds", 5))
        results = []

        for src_ip, q in self._src_ip_times[str(dpid)].items():
            while q and (now - q[0]) > window:
                q.popleft()

            if q:
                results.append({
                    "src_ip": src_ip,
                    "packet_count": len(q),
                    "rate_pps": round(len(q) / window, 3) if window > 0 else 0.0,
                })

        return sorted(results, key=lambda x: x["packet_count"], reverse=True)[:10]

    def mitigate(self, dpid, action="drop", src_ip=None, rate_kbps=2000, reason="manual"):
        dp = self._get_dp(dpid)
        if dp is None:
            return {"ok": False, "error": "unknown dpid"}

        parser = dp.ofproto_parser
        ofp = dp.ofproto
        now = time.time()

        if action == "drop":
            if not src_ip:
                return {"ok": False, "error": "src_ip required for drop action"}

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            inst = []

            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=100,
                match=match,
                instructions=inst,
                idle_timeout=60,
                hard_timeout=120,
                cookie=self._mitigation_cookie
            )
            dp.send_msg(mod)

            record = {
                "ts": now,
                "dpid": str(dpid),
                "action": "drop",
                "src_ip": src_ip,
                "priority": 100,
                "idle_timeout": 60,
                "hard_timeout": 120,
                "reason": reason
            }

        elif action == "meter":
            bands = [
                parser.OFPMeterBandDrop(rate=int(rate_kbps), burst_size=100)
            ]

            meter_mod = parser.OFPMeterMod(
                datapath=dp,
                command=ofp.OFPMC_ADD,
                flags=ofp.OFPMF_KBPS,
                meter_id=self._meter_id,
                bands=bands
            )
            dp.send_msg(meter_mod)

            match = parser.OFPMatch(eth_type=0x0800)
            inst = [
                parser.OFPInstructionMeter(self._meter_id),
                parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
                )
            ]

            mod = parser.OFPFlowMod(
                datapath=dp,
                priority=90,
                match=match,
                instructions=inst,
                idle_timeout=60,
                hard_timeout=120,
                cookie=self._mitigation_cookie
            )
            dp.send_msg(mod)

            record = {
                "ts": now,
                "dpid": str(dpid),
                "action": "meter",
                "rate_kbps": int(rate_kbps),
                "meter_id": self._meter_id,
                "priority": 90,
                "idle_timeout": 60,
                "hard_timeout": 120,
                "reason": reason
            }

        else:
            return {"ok": False, "error": "action must be drop or meter"}

        self.mitigation_log.append(record)
        report_meta = self._generate_report(str(dpid), record)
        record["report_id"] = report_meta["report_id"]

        return {
            "ok": True,
            "mitigation": record,
            "report": report_meta
        }

    def unmitigate(self, dpid=None):
        targets = [self._get_dp(dpid)] if dpid else list(self.switches.values())
        removed = []

        for dp in targets:
            if dp is None:
                continue

            parser = dp.ofproto_parser
            ofp = dp.ofproto

            flow_delete = parser.OFPFlowMod(
                datapath=dp,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                cookie=self._mitigation_cookie,
                cookie_mask=0xffffffffffffffff,
                match=parser.OFPMatch()
            )
            dp.send_msg(flow_delete)

            try:
                meter_delete = parser.OFPMeterMod(
                    datapath=dp,
                    command=ofp.OFPMC_DELETE,
                    flags=ofp.OFPMF_KBPS,
                    meter_id=self._meter_id,
                    bands=[]
                )
                dp.send_msg(meter_delete)
            except Exception:
                pass

            removed.append(str(dp.id))

        record = {
            "ts": time.time(),
            "action": "unmitigate",
            "dpids": removed
        }
        self.mitigation_log.append(record)

        return {"ok": True, "removed_from": removed}

    def _generate_report(self, dpid, mitigation_record):
        now = time.time()
        report_id = str(int(now * 1000))

        report = {
            "report_id": report_id,
            "timestamp": now,
            "switch_id": str(dpid),
            "summary": {
                "event": "control-plane saturation mitigation",
                "reason": mitigation_record.get("reason"),
                "mitigation_action": mitigation_record.get("action"),
            },
            "metrics": self.metrics.get(str(dpid), {}),
            "attack_sources": self._top_attack_sources(str(dpid), now),
            "mitigation_action": mitigation_record,
            "recent_alerts": [
                a for a in list(self.alerts)
                if str(a.get("dpid")) == str(dpid)
            ][-5:],
        }

        path = os.path.join(self.report_dir, f"{report_id}.json")

        with open(path, "w") as f:
            json.dump(report, f, indent=2, sort_keys=True)

        self.reports[report_id] = {
            "report_id": report_id,
            "timestamp": now,
            "path": path,
            "dpid": str(dpid)
        }

        return self.reports[report_id]

    def list_reports(self):
        return sorted(
            list(self.reports.values()),
            key=lambda r: r["timestamp"],
            reverse=True
        )

    def get_report(self, report_id):
        meta = self.reports.get(report_id)

        if not meta:
            path = os.path.join(self.report_dir, f"{report_id}.json")
            if not os.path.exists(path):
                return None
        else:
            path = meta["path"]

        with open(path) as f:
            return json.load(f)

    def export_report(self, report_id, fmt="json"):
        report = self.get_report(report_id)
        if report is None:
            return {"ok": False, "error": "report not found"}

        fmt = fmt.lower()

        if fmt == "json":
            return {
                "ok": True,
                "content_type": "application/json",
                "body": json.dumps(report, indent=2, sort_keys=True)
            }

        if fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)

            writer.writerow(["field", "value"])
            writer.writerow(["report_id", report.get("report_id")])
            writer.writerow(["timestamp", report.get("timestamp")])
            writer.writerow(["switch_id", report.get("switch_id")])

            for key, value in report.get("summary", {}).items():
                writer.writerow([f"summary.{key}", value])

            for key, value in report.get("mitigation_action", {}).items():
                writer.writerow([f"mitigation.{key}", value])

            for key, value in report.get("metrics", {}).items():
                writer.writerow([
                    f"metrics.{key}",
                    json.dumps(value) if isinstance(value, (dict, list)) else value
                ])

            writer.writerow([])
            writer.writerow(["attack_source_ip", "packet_count", "rate_pps"])

            for src in report.get("attack_sources", []):
                writer.writerow([
                    src.get("src_ip"),
                    src.get("packet_count"),
                    src.get("rate_pps")
                ])

            return {
                "ok": True,
                "content_type": "text/csv",
                "body": output.getvalue()
            }

        if fmt == "xml":
            root = ET.Element("report")

            def add(parent, key, value):
                child = ET.SubElement(parent, str(key))
                child.text = "" if value is None else str(value)
                return child

            add(root, "report_id", report.get("report_id"))
            add(root, "timestamp", report.get("timestamp"))
            add(root, "switch_id", report.get("switch_id"))

            summary_el = ET.SubElement(root, "summary")
            for key, value in report.get("summary", {}).items():
                add(summary_el, key, value)

            metrics_el = ET.SubElement(root, "metrics")
            for key, value in report.get("metrics", {}).items():
                add(metrics_el, key, json.dumps(value) if isinstance(value, (dict, list)) else value)

            sources_el = ET.SubElement(root, "attack_sources")
            for src in report.get("attack_sources", []):
                src_el = ET.SubElement(sources_el, "source")
                for key, value in src.items():
                    add(src_el, key, value)

            mitigation_el = ET.SubElement(root, "mitigation_action")
            for key, value in report.get("mitigation_action", {}).items():
                add(mitigation_el, key, value)

            alerts_el = ET.SubElement(root, "recent_alerts")
            for alert in report.get("recent_alerts", []):
                alert_el = ET.SubElement(alerts_el, "alert")
                for key, value in alert.items():
                    add(alert_el, key, value)

            return {
                "ok": True,
                "content_type": "application/xml",
                "body": ET.tostring(root, encoding="unicode")
            }

        return {"ok": False, "error": "format must be json, csv, or xml"}