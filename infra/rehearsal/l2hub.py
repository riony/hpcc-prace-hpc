#!/usr/bin/env python3
"""Tiny L2 hub for QEMU dgram NICs on localhost: the rehearsal's private switch.
Each NIC is a pair (hub port it sends to, NIC port the hub sends back to); every frame
received on one hub port is flooded to all other NICs. Localhost only; unprivileged.
  l2hub.py --pair HUBPORT:NICPORT [--pair ...]
"""
import argparse
import select
import socket
import sys

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--pair", action="append", required=True)
args = ap.parse_args()
socks = {}
for pair in args.pair:
    hub, nic = (int(x) for x in pair.split(":"))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", hub))
    socks[s] = ("127.0.0.1", nic)
if len(socks) < 2:
    sys.exit("need at least two NICs")
while True:
    ready, _, _ = select.select(list(socks), [], [])
    for s in ready:
        frame, _ = s.recvfrom(65535)
        for other, dest in socks.items():
            if other is not s:
                other.sendto(frame, dest)
