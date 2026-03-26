#!/usr/bin/env python3
import time
from collections import defaultdict, deque

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.app.wsgi import WSGIApplication

from apps.api import RestApiController  # /api/v1 routes


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

		# PacketIn tracking
		self._pktin_times = defaultdict(lambda: deque(maxlen=200000))
		self._streak = defaultdict(int)

		# Register the REST controller and pass THIS instance
		wsgi = kwargs['wsgi']
		wsgi.register(RestApiController, {"engine": self})

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		# Call the base class handler (installs table-miss, etc.)
		super(MitigationEngine, self).switch_features_handler(ev)

		dp = ev.msg.datapath
		self.switches[dp.id] = dp
		self.mac_to_port.setdefault(dp.id, {})

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		# 1) Track PacketIn timestamps for your monitoring
		dp = ev.msg.datapath
		now = time.time()
		self._pktin_times[str(dp.id)].append(now)

		# 2) Overriding: Keep learning-switch behavior by delegating to base implementation
		super(MitigationEngine, self)._packet_in_handler(ev)

		# 3) (Later) update per-src attribution, detection, etc.

	def get_switch_dpids(self):
		# Helper for REST routes
		return sorted([str(dpid) for dpid in self.switches.keys()])