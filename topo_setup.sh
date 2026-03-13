#!/usr/bin/env bash
set -euo pipefail

# ---- Config (override via env vars) ----
CTRL_IP="${CTRL_IP:-127.0.0.1}"
CTRL_PORT="${CTRL_PORT:-6653}"          # OF1.3 commonly uses 6653; change if you want 6633
RYU_APP="${RYU_APP:-ryu.app.simple_switch_13}"
# ---------------------------------------

echo "[*] Installing prerequisites (Mininet, OVS, Ryu)..."
sudo apt-get update -y
sudo apt-get install -y \
  mininet openvswitch-switch openvswitch-common \
  python3 python3-pip

# Install Ryu via pip (system-wide).
sudo python3 -m pip install -U pip
sudo python3 -m pip install -U ryu

echo "[*] Restarting Open vSwitch..."
sudo systemctl enable --now openvswitch-switch || true
sudo systemctl restart openvswitch-switch || true

echo "[*] Cleaning any stale Mininet state..."
sudo mn -c >/dev/null || true

echo "[*] Starting Ryu controller: ${RYU_APP} on ${CTRL_IP}:${CTRL_PORT}"
# Run Ryu in background, log to file
ryu-manager "${RYU_APP}" --ofp-tcp-listen-port "${CTRL_PORT}" > ryu.log 2>&1 &
RYU_PID=$!
echo "[*] Ryu PID: ${RYU_PID} (logging to ./ryu.log)"

cleanup() {
  echo
  echo "[*] Cleaning up..."
  sudo mn -c >/dev/null || true
  if kill -0 "${RYU_PID}" >/dev/null 2>&1; then
    kill "${RYU_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "[*] Starting Mininet: 1 switch (OF1.3) + 3 hosts (2 clients + 1 attacker)"
echo "    Hostnames will be: h1, h2, h3 (treat h3 as the attacker)"
echo "    Auto IPs: h1=10.0.0.1/8, h2=10.0.0.2/8, h3=10.0.0.3/8"

sudo mn \
  --topo single,3 \
  --controller remote,ip="${CTRL_IP}",port="${CTRL_PORT}" \
  --switch ovs,protocols=OpenFlow13

echo "[*] Mininet exited."