#!/usr/bin/env python3
"""Fake login-node port for QEMU tests of prace-first-address.service (unprivileged).

Listens on a localhost UDP port used by a QEMU `-netdev dgram` NIC (one Ethernet frame per
datagram) and answers ARP requests for 10.90.10.1 as the login node's MAC, including the
duplicate-address probes (sender 0.0.0.0) that the helper uses. Nothing leaves localhost.
Counts are written to --log when it stops (SIGTERM) or after --seconds.
"""
import argparse
import signal
import socket
import struct
import sys
import time

PEER_IP = socket.inet_aton("10.90.10.1")
PEER_MAC = bytes.fromhex("02:00:00:00:00:01".replace(":", ""))   # login node private port


def reply(frame):
    """ARP reply for a request asking for PEER_IP, else None."""
    if len(frame) < 42 or frame[12:14] != b"\x08\x06":
        return None
    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", frame[14:22])
    sha, spa, tpa = frame[22:28], frame[28:32], frame[38:42]
    if (htype, ptype, hlen, plen, oper) != (1, 0x0800, 6, 4, 1) or tpa != PEER_IP:
        return None
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + PEER_MAC + PEER_IP + sha + spa
    return sha + PEER_MAC + b"\x08\x06" + arp


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--listen", required=True, help="127.0.0.1:PORT (the NIC's remote end)")
    ap.add_argument("--seconds", type=int, default=1800)
    ap.add_argument("--log", required=True)
    args = ap.parse_args()
    host, port = args.listen.rsplit(":", 1)
    if host != "127.0.0.1":
        sys.exit("refusing a non-localhost address")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, int(port)))
    s.settimeout(1.0)
    counts = {"frames": 0, "arp_requests_for_peer": 0, "replies": 0}
    stop = [False]
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__(0, True))
    end = time.time() + args.seconds
    while not stop[0] and time.time() < end:
        try:
            frame, source = s.recvfrom(65535)
        except socket.timeout:
            continue
        counts["frames"] += 1
        answer = reply(frame)
        if answer:
            counts["arp_requests_for_peer"] += 1
            s.sendto(answer, source)
            counts["replies"] += 1
    with open(args.log, "w") as f:
        f.write(" ".join(f"{k}={v}" for k, v in counts.items()) + "\n")


if __name__ == "__main__":
    main()
