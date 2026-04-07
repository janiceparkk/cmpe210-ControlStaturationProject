#!/usr/bin/env python3
import json
import time
from webob import Response

from ryu.app.wsgi import ControllerBase, route

APP_NAME = "sdn_mitigation_engine"
BASE = "/api/v1"


class RestApiController(ControllerBase):
    def __init__(self, req, link, data, **config):
        """
        We are able to pull our engine instance from engine.py,
        thus accessing the defined functions within that
        instance. 
        
        This is possible via WSGI.
        """
        super().__init__(req, link, data, **config)
        self.engine = data["engine"]

    def _json(self, obj, status=200):
        body = json.dumps(obj, indent=2, sort_keys=True).encode("utf-8")
        return Response(content_type="application/json", body=body, status=status)
    
    def _get_datapath_dict(self):
        """
        Returns: dict[int, datapath]
        """
        if hasattr(self.engine, "switches") and isinstance(self.engine.switches, dict):
            return self.engine.switches
        return {}


    # Monitoring APIs
    @route(APP_NAME, BASE + "/health", methods=["GET"])
    def health(self, req, **kwargs):
        """
        Checks if the server is running and able to respond

        GET: sdn_mitigation_engine/api/v1/health
        """
        dpids = self.engine.get_switch_dpids()
        ok = True
        problems = []

        if len(dpids) == 0:
            ok = False
            problems.append("no switches connected")
        return self._json({"ok": ok, "problems": problems})

    @route(APP_NAME, BASE + "/switches", methods=["GET"])
    def switches(self, req, **kwargs):
        """
        List connected switches (dpids).
        """
        return self._json({"switches": self.engine.get_switch_dpids()})
	
    @route(APP_NAME, BASE + "/status", methods=["GET"])
    def status(self, req, **kwargs):
        """
        LATER: return detection and mitigation status/rates
        """
        return self._json({
            "time": time.time(),
            "switches": self.engine.get_switch_dpids(),
        })
    
    @route(APP_NAME, BASE + "/metrics", methods=["GET"])
    def metrics(self, req, **kwargs):
        """
        Default: Return all Metrics
        - packet_in_rate
        - table-miss rate
        - flow table occupancy
        - port stats

        dpid Specified: Return only the metrics for that dpid
        GET: sdn_mitigation_engine/api/v1/health?dpid={dpid}
        """
        dpid = req.params.get("dpid")
        if dpid:
            return self._json({dpid: self.engine.metrics.get(dpid, {})})
        return self._json(self.engine.metrics)
    

    # Detection APIs
    @route(APP_NAME, BASE + "/alerts", methods=["GET"])
    def alerts(self, req, **kwargs):
        alerts = getattr(self.engine, "alerts", [])
        return self._json(list(alerts))
    
    @route(APP_NAME, BASE + "/config", methods=["GET"])
    def get_config(self, req, **kwargs):
        return self._json(getattr(self.engine, "config", {}))

    @route(APP_NAME, BASE + "/config", methods=["POST"])
    def set_config(self, req, **kwargs):
        """
        Redefine or Update the following:
        - packet_in_rate_threshold
        - miss_rate_threshold
        - window_seconds
        - whitelist, blacklist

        - LATER: mitigation
        """
        body = req.json if req.body else {}
        if not isinstance(body, dict):
            return self._json({"ok": False, "error": "JSON body must be an object"}, status=400)

        if not hasattr(self.engine, "config") or not isinstance(self.engine.config, dict):
            return self._json({"ok": False, "error": "engine has no config dict"}, status=500)

        self.engine.config.update(body)
        return self._json({"ok": True, "config": self.engine.config})
    