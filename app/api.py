#!/usr/bin/env python3
import json
import os
import time
from webob import Response

from ryu.app.wsgi import ControllerBase, route

APP_NAME = "sdn_mitigation_engine"
BASE = "/api/v1"


class RestApiController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.engine = data["engine"]

    def _json(self, obj, status=200):
        body = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8")
        return Response(content_type="application/json", body=body, status=status)

    # --------- Monitoring APIs ------------
    @route(APP_NAME, BASE + "/health", methods=["GET"])
    def health(self, req, **kwargs):
        dpids = self.engine.get_switch_dpids()
        ok = True
        problems = []

        if len(dpids) == 0:
            ok = False
            problems.append("no switches connected")

        return self._json({"ok": ok, "problems": problems})

    @route(APP_NAME, BASE + "/switches", methods=["GET"])
    def switches(self, req, **kwargs):
        return self._json({"switches": self.engine.get_switch_dpids()})

    @route(APP_NAME, BASE + "/status", methods=["GET"])
    def status(self, req, **kwargs):
        return self._json({
            "time": time.time(),
            "switches": self.engine.get_switch_dpids(),
            "detection_enabled": getattr(self.engine, "detection_enabled", True),
        })

    @route(APP_NAME, BASE + "/metrics", methods=["GET"])
    def metrics(self, req, **kwargs):
        dpid = req.params.get("dpid")
        if dpid:
            return self._json({dpid: self.engine.metrics.get(dpid, {})})
        return self._json(self.engine.metrics)

    # ---------- Detection APIs -----------
    @route(APP_NAME, BASE + "/alerts", methods=["GET"])
    def alerts(self, req, **kwargs):
        return self._json(list(getattr(self.engine, "alerts", [])))

    @route(APP_NAME, BASE + "/alerts", methods=["DELETE"])
    def clear_alerts(self, req, **kwargs):
        if hasattr(self.engine, "alerts"):
            self.engine.alerts.clear()
        return self._json({"ok": True})

    @route(APP_NAME, BASE + "/detection/status", methods=["GET"])
    def detection_status(self, req, **kwargs):
        return self._json({
            "detection_enabled": getattr(self.engine, "detection_enabled", True),
            "config": getattr(self.engine, "config", {}),
        })

    @route(APP_NAME, BASE + "/detection/mode", methods=["POST"])
    def detection_mode(self, req, **kwargs):
        body = req.json if req.body else {}
        if not isinstance(body, dict):
            return self._json({"ok": False, "error": "JSON body must be an object"}, status=400)

        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            return self._json({"ok": False, "error": "enabled must be true/false"}, status=400)

        self.engine.detection_enabled = enabled
        return self._json({"ok": True, "detection_enabled": self.engine.detection_enabled})

    @route(APP_NAME, BASE + "/config", methods=["GET"])
    def get_config(self, req, **kwargs):
        return self._json(getattr(self.engine, "config", {}))

    @route(APP_NAME, BASE + "/config", methods=["POST"])
    def set_config(self, req, **kwargs):
        body = req.json if req.body else {}
        if not isinstance(body, dict):
            return self._json({"ok": False, "error": "JSON body must be an object"}, status=400)

        if not hasattr(self.engine, "config") or not isinstance(self.engine.config, dict):
            return self._json({"ok": False, "error": "engine has no config dict"}, status=500)

        self.engine.config.update(body)
        return self._json({"ok": True, "config": self.engine.config})

    # ---------- Mitigation APIs -----------
    @route(APP_NAME, BASE + "/mitigate", methods=["POST"])
    def mitigate(self, req, **kwargs):
        body = req.json if req.body else {}
        if not isinstance(body, dict):
            return self._json({"ok": False, "error": "JSON body must be an object"}, status=400)

        dpid = body.get("dpid")
        action = body.get("action", "drop")
        src_ip = body.get("src_ip")
        rate_kbps = body.get("rate_kbps", 2000)

        if not dpid:
            return self._json({"ok": False, "error": "dpid is required"}, status=400)

        result = self.engine.mitigate(
            dpid=dpid,
            action=action,
            src_ip=src_ip,
            rate_kbps=rate_kbps,
            reason="manual_api"
        )

        return self._json(result, status=200 if result.get("ok") else 400)

    @route(APP_NAME, BASE + "/unmitigate", methods=["POST"])
    def unmitigate(self, req, **kwargs):
        body = req.json if req.body else {}
        if body and not isinstance(body, dict):
            return self._json({"ok": False, "error": "JSON body must be an object"}, status=400)

        dpid = body.get("dpid")
        result = self.engine.unmitigate(dpid=dpid)

        return self._json(result)

    @route(APP_NAME, BASE + "/mitigation/log", methods=["GET"])
    def mitigation_log(self, req, **kwargs):
        return self._json(list(getattr(self.engine, "mitigation_log", [])))

    # ---------- Report APIs -----------
    @route(APP_NAME, BASE + "/reports", methods=["GET"])
    def reports(self, req, **kwargs):
        return self._json(self.engine.list_reports())

    @route(APP_NAME, BASE + "/reports/{report_id}", methods=["GET"])
    def report_detail(self, req, report_id, **kwargs):
        report = self.engine.get_report(report_id)
        if report is None:
            return self._json({"ok": False, "error": "report not found"}, status=404)

        return self._json(report)

    @route(APP_NAME, BASE + "/reports/{report_id}/download", methods=["GET"])
    def report_download(self, req, report_id, **kwargs):
        fmt = req.params.get("format", "json").lower()

        result = self.engine.export_report(report_id, fmt)
        if not result.get("ok"):
            status = 404 if result.get("error") == "report not found" else 400
            return self._json(result, status=status)

        return Response(
            content_type=result["content_type"],
            body=result["body"].encode("utf-8"),
            headers={
                "Content-Disposition": f'attachment; filename="{report_id}.{fmt}"'
            }
        )