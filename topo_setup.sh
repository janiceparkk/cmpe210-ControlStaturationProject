#!/usr/bin/env bash
set -euo pipefail

# ---- Config (override via env vars) ----
CTRL_IP="${CTRL_IP:-127.0.0.1}"
CTRL_PORT="${CTRL_PORT:-6653}"          # OF1.3 common default
RYU_APP="${RYU_APP:-ryu.app.simple_switch_13}"
USE_APT_INSTALL="${USE_APT_INSTALL:-1}" # set to 0 to skip apt installs
# ---------------------------------------

disable_broken_deadsnakes() {
	echo "[!] Checking for deadsnakes PPA entries..."
	local matches
	matches="$(grep -RIl "ppa\.launchpadcontent\.net/deadsnakes/ppa" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true)"

	if [ -z "${matches}" ]; then
		echo "[*] No deadsnakes entries found."
		return 0
	fi

	echo "[!] Found deadsnakes in:"
	echo "${matches}"

	# Disable by renaming source files (covers .list and .sources)
	while IFS= read -r f; do
		[ -z "$f" ] && continue
		if [ "$f" = "/etc/apt/sources.list" ]; then
			sudo sed -i.bak "/deadsnakes\/ppa/ s/^/# DISABLED: /" "$f"
		else
			sudo mv "$f" "$f.disabled" || true
		fi
	done <<< "${matches}"
}

apt_update_with_recovery() {
	set +e
	sudo apt-get update -y
	rc=$?
	set -e

	if [ $rc -ne 0 ]; then
		echo "[!] apt-get update failed. Attempting recovery..."
		disable_broken_deadsnakes
		sudo apt-get update -y
	fi
}

install_deps() {
	if [ "${USE_APT_INSTALL}" != "1" ]; then
		echo "[*] Skipping apt installs (USE_APT_INSTALL=0)."
		return
	fi

	echo "[*] Updating apt and installing prerequisites (Mininet, OVS, pip)..."
	apt_update_with_recovery

	sudo apt-get install -y \
		mininet openvswitch-switch openvswitch-common \
		python3 python3-pip

	echo "[*] Ensuring pip + ryu are installed..."
	sudo python3 -m pip install -U pip
	sudo python3 -m pip install -U ryu
}

start_ovs() {
	echo "[*] Restarting Open vSwitch..."
	sudo systemctl enable --now openvswitch-switch >/dev/null 2>&1 || true
	sudo systemctl restart openvswitch-switch >/dev/null 2>&1 || true
}

cleanup_mininet() {
	echo "[*] Cleaning Mininet state..."
	sudo mn -c >/dev/null 2>&1 || true
}

start_ryu() {
	echo "[*] Starting Ryu controller: ${RYU_APP} on ${CTRL_IP}:${CTRL_PORT}"
	ryu-manager "${RYU_APP}" --ofp-tcp-listen-port "${CTRL_PORT}" > ryu.log 2>&1 &
	RYU_PID=$!
	echo "[*] Ryu PID: ${RYU_PID} (logging to ./ryu.log)"
}

main() {
	install_deps
	start_ovs
	cleanup_mininet
	start_ryu

	cleanup() {
		echo
		echo "[*] Cleaning up..."
		cleanup_mininet
		if kill -0 "${RYU_PID}" >/dev/null 2>&1; then
			kill "${RYU_PID}" >/dev/null 2>&1 || true
		fi
	}
	trap cleanup EXIT

	echo "[*] Starting Mininet: 1 switch (OF1.3) + 3 hosts (2 clients + 1 attacker)"
	echo "    Hosts will be: h1, h2, h3 (treat h3 as attacker)"
	echo "    Auto IPs: h1=10.0.0.1/8, h2=10.0.0.2/8, h3=10.0.0.3/8"
	echo "    Controller: ${CTRL_IP}:${CTRL_PORT}"

	sudo mn \
		--topo single,3 \
		--controller remote,ip="${CTRL_IP}",port="${CTRL_PORT}" \
		--switch ovs,protocols=OpenFlow13
}

main "$@"