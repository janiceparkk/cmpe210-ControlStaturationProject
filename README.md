# An Adaptive Mitigation Engine against Control-Plane Saturation
This project runs an SDN controller (Ryu, OpenFlow 1.3) with REST APIs to monitor/control-plane load and detect saturation (PacketIn/table-miss storms). A separate attacker script generates miss-storm traffic from a Mininet host.

## Prerequisites
Before running Mininet make sure you install the following:
```
$ sudo apt-get update -y
$ sudo apt-get install -y python3 python3-pip mininet openvswitch-switch openvswitch-common curl
$ sudo apt install scapy
```

Enable or Restart the Open vSwitch as needed:
```
$ sudo systemctl enable --now openvswitch-switch || true
$ sudo systemctl restart openvswitch-switch || true
```

## Running the Ryu Controller & Mininet Set Up
The topology consists of 3 hosts (2 clients, 1 attacker) and 1 Open Flow 1.3 switch.
Run the following commands in your terminal (installs Ryu as a prerequisite)
```
$ chmod +x topo_setup.sh
$ ./topo_setup.sh
```

(RECOMMENDED) If you already installed everything and just want to run ryu and mininet, run:
```
$ RYU_APP=app/engine.py CTRL_PORT=6653 USE_APT_INSTALL=0 ./topo_setup.sh
```

## Testing Connectivity
To make sure your hosts are correctly set up on mininet, run:
```
mininet> pingall
```

## Running the Attack Script
To simulate a table miss attack storm, run:
```
$ chmod +x ./scripts/attack_miss_storm.py
mininet> h3 python3 scripts/attack_miss_storm.py --iface h3-eth0 --target 10.0.0.1 --seconds 8 --pps 2000 --burst 200 --random_src_mac
```

## How to Monitor the Traffic
```
$ curl -s http://127.0.0.1:8080/api/v1/health | python3 -m json.tool
$ curl -s http://127.0.0.1:8080/api/v1/switches | python3 -m json.tool
$ curl -s http://127.0.0.1:8080/api/v1/metrics | python3 -m json.tool
$ curl -s http://127.0.0.1:8080/api/v1/alerts | python3 -m json.tool
```

## How to Detect Supicious Activity
```
$ curl -s http://127.0.0.1:8080/api/v1/metrics | python3 -m json.tool
$ curl -s http://127.0.0.1:8080/api/v1/alerts | python3 -m json.tool

$ watch -n 1 'curl -s http://127.0.0.1:8080/api/v1/metrics | head -n 120'
```

If the commands above don't trigger/log the alerts, it may be because your VM may not achieve high pps with Scapy. Lower thresholds temporarily:
```
$ curl -s -X POST http://127.0.0.1:8080/api/v1/config \
  -H "Content-Type: application/json" \
  -d '{"window_seconds": 5, "packet_in_rate_threshold": 10, "table_miss_rate_threshold": 10, "consecutive_windows": 1, "alert_cooldown_seconds": 0}' \
  | python3 -m json.tool
```

Also make sure to clear alerts between runs: 
```
$ curl -s -X DELETE http://127.0.0.1:8080/api/v1/alerts | python3 -m json.tool
```

## Trouble Shooting
Check the Ports
```
ss -lntp | grep -E ':8080|:6653' || true
```

Check the Controller Log
```
tail -n 120 ryu.log
```

Verify Scapy is installed
```
mininet> h3 python3 -c "import scapy; print('scapy ok')"
```

## Clean Up
```
mininet> exit
$ sudo mn -c
$ pkill -f "ryu-manager" || true
$ pkill -f "ryu.cmd.manager" || true
```
