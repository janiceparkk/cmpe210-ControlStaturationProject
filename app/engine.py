#!/usr/bin/env python3
import time
from collections import defaultdict, deque

from ryu.app import simple_switch_13
from ryu.app.wsgi import WSGIApplication
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub

from app.api import RestApiController  # /api/v1 routes


class MitigationEngine(simple_switch_13.SimpleSwitch13):
	"""
	WSGI (Web Server Gateway Interface) is a standard 
	Python interface that defines how a 
	web server/server component hands an HTTP request 
    to a Python web application, and how the app 
    returns a response.
	"""
	_CONTEXTS = {'wsgi': WSGIApplication}

	def __init__(self, *args, **kwargs):
		super(MitigationEngine, self).__init__(*args, **kwargs)

		# Track datapaths: dpid(int) -> datapath
		self.switches = {}

		# REST will read/write these
		self.start_time = time.time()
		self.config = {
			"window_seconds": 5,
			"packet_in_rate_threshold": 200.0,
			"consecutive_windows": 2,
			"mitigation_mode": "auto",
		}
		self.metrics = {}
		self.alerts = deque(maxlen=200)
		self.mitigation_log = deque(maxlen=500)

		# PacketIn + Miss Tracking
		self._pktin_times = defaultdict(lambda: deque(maxlen=200000)) # dpid(str) -> [ts...]
		self._miss_times = defaultdict(lambda: deque(maxlen=200000)) # dpid(str) -> [ts...]
		self._streak = defaultdict(int) # dpid(str) -> consecutive windows
		self._last_alert_ts = defaultdict(lambda: 0.0)

		# Detection on/off
		self.detection_enabled = True

		# Cookie to identify PacketIns caused by our table-miss flow
		self._TABLE_MISS_COOKIE = 0xA11CE

		# Register the REST controller and pass THIS instance
		wsgi = kwargs['wsgi']
		wsgi.register(RestApiController, {"engine": self})

		# dpid -> {port_no: (rx_bytes, tx_bytes, ts)}
		# need to store: Port stats from OpenFlow are cumulative totals, not rates
		self._port_bytes_prev = defaultdict(dict)

		# prev flow table sizes: dpid -> (flow_count, ts)
		# allows to calculate: low table growth rate, spikes, flow churn
		self._flow_count_prev = defaultdict(lambda: (0, 0.0))

		# Start background monitoring loop - continuous
		# prunes timestamps, packet in rate, update self.metrics
		self._monitor_thread = hub.spawn(self._monitor_loop)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		# Call the base class handler (installs table-miss, etc.)
		super(MitigationEngine, self).switch_features_handler(ev)

		dp = ev.msg.datapath
		ofp = dp.ofproto
		parser = dp.ofproto_parser

		self.switches[dp.id] = dp
		self.mac_to_port.setdefault(dp.id, {})

		# Table-miss with cookie: send to controller
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
		# Track PacketIn timestamps for Monitoring
		msg = ev.msg
		dp = msg.datapath
		now = time.time()

		dpid = str(dp.id)
		self._pktin_times[dpid].append(now)

		# Count "miss PacketIns" when the cookie matches the table-miss flow
		if getattr(msg, "cookie", None) == self._TABLE_MISS_COOKIE:
			self._miss_times[dpid].append(now)

		# Preserve L2 learning switch behavior
		super(MitigationEngine, self)._packet_in_handler(ev)

	# -------- Monitoring Event Handlers -------------
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

		# Compute per-port rx/tx rates based on byte deltas
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
		# Helper for REST routes
		return sorted([str(dpid) for dpid in self.switches.keys()])
	
	def _monitor_loop(self):
		"""
		Every second:
		- compute packet_in_rate from timestamps
		- periodically request flow/port stats from switches
		"""
		last_stats_poll = 0.0

		while True:
			# Update Metrics
			now = time.time()
			self._update_packet_in_metrics(now)

			# Run Detection
			for dpid_int in list(self.switches.keys()):
				self._run_detection(str(dpid_int), now)

			# Poll OpenFlow stats every 2 seconds
			if now - last_stats_poll >= 2.0:
				for dp in list(self.switches.values()):
					self._request_stats(dp)
				last_stats_poll = now

			hub.sleep(1)

	def _update_packet_in_metrics(self, now: float):
		window = float(self.config.get("window_seconds", 5))

		for dpid_int in list(self.switches.keys()):
			dpid = str(dpid_int)

			# PacketIn rate
			pq = self._pktin_times[dpid]
			while pq and (now - pq[0]) > window:
				pq.popleft()
			pktin_count = len(pq)
			pktin_rate = (pktin_count / window) if window > 0 else 0.0

			# Table-miss rate
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
			})

		self.metrics.setdefault("global", {})
		self.metrics["global"].update({
			"last_updated": now,
			"connected_switches": len(self.switches),
		})
	
	# -------- Detection Event Handlers -------------
	def _run_detection(self, dpid: str, now: float):
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

	def _request_stats(self, dp):
		"""
		Send OpenFlow stats requests:
		- Flow stats for flow table occupancy
		- Port stats for tx/rx rates
		"""
		ofp = dp.ofproto
		parser = dp.ofproto_parser

		# Flow stats
		flow_req = parser.OFPFlowStatsRequest(dp)
		dp.send_msg(flow_req)

		# Port stats (ALL ports)
		port_req = parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY)
		dp.send_msg(port_req)