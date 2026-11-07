#!/usr/bin/env python3
"""Traffic generator for the STM32 SmartNIC filter, run on the BeagleBone Black.

Each scenario sends a known set of frames. Compare the board's counters
(PuTTY stats line) with what the scenario says it expects.

Usage (on the BBB, needs root for raw sockets):
    sudo python3 nic_test.py normal --count 10
"""

import argparse
import time

from scapy.all import Ether, ICMP, IP, TCP, UDP, Raw, sendp

IFACE = "eth0"
BOARD_MAC = "00:80:e1:00:00:00"   # main.c MX_ETH_Init MACAddr
BOARD_IP = "192.168.10.1"         # filter_policy.h POLICY_BOARD_IP
BBB_IP = "192.168.10.2"
UDP_TEST_PORT = 5000              # filter_policy.h POLICY_UDP_TEST_PORT
TCP_PORT = 80                     # filter_policy.h POLICY_TCP_PORT


def scenario_normal(count):
    """Wanted traffic: UDP to the test port. Expect: passed += count, udp-test hits."""
    frame = (Ether(dst=BOARD_MAC)
             / IP(src=BBB_IP, dst=BOARD_IP)
             / UDP(sport=40000, dport=UDP_TEST_PORT)
             / Raw(b"smartnic"))
    sendp(frame, iface=IFACE, count=count, inter=0.1, verbose=False)
    print(f"normal: sent {count} UDP frames to port {UDP_TEST_PORT}")
    print(f"expect: passed +{count}, udp-test +{count}")


def udp_to_test_port(src_ip, dst_ip=BOARD_IP, src_mac=None):
    """UDP to the test port: would PASS if the source were honest."""
    eth = Ether(dst=BOARD_MAC) if src_mac is None else Ether(dst=BOARD_MAC, src=src_mac)
    return (eth
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=40000, dport=UDP_TEST_PORT)
            / Raw(b"spoof"))


def scenario_spoof(count):
    """Lying source addresses. Expect: spoofed += 6*count, default += count."""
    frames = [
        ("loopback 127.0.0.1",        udp_to_test_port("127.0.0.1")),
        ("multicast 224.0.0.5",       udp_to_test_port("224.0.0.5")),
        ("broadcast 255.255.255.255", udp_to_test_port("255.255.255.255")),
        ("0.0.0.0, not DHCP",         udp_to_test_port("0.0.0.0")),
        ("LAND: src == dst",          udp_to_test_port(BOARD_IP)),
        ("group source MAC",          udp_to_test_port(BBB_IP, src_mac="01:00:5e:00:00:01")),
        # Not a lie the board can see: a normal-looking address, but outside
        # the link subnet. The rules only allow 192.168.10.0/24 (ingress filtering).
        ("outside subnet 10.0.0.99",  udp_to_test_port("10.0.0.99")),
    ]
    for name, frame in frames:
        sendp(frame, iface=IFACE, count=count, inter=0.1, verbose=False)
        print(f"spoof: sent {count} x {name}")
    print(f"expect: spoofed +{6 * count}, default +{count}, passed +0")


def tcp_to_service(flags):
    """TCP from the BBB to the protected service port, with the given flags."""
    return (Ether(dst=BOARD_MAC)
            / IP(src=BBB_IP, dst=BOARD_IP)
            / TCP(sport=40001, dport=TCP_PORT, flags=flags))


def scenario_scan(count):
    """Port-scan flag combinations. Expect: tcp-scan += 5*count, tcp += count."""
    frames = [
        ("NULL scan (no flags)",       tcp_to_service("")),
        ("FIN scan (FIN alone)",       tcp_to_service("F")),
        ("XMAS scan (FIN+PSH+URG)",    tcp_to_service("FPU")),
        ("SYN+FIN",                    tcp_to_service("SF")),
        ("SYN+RST",                    tcp_to_service("SR")),
        # Control: same port, same sender, honest flags. Must PASS, so the
        # drops above are caused by the flags and nothing else.
        ("control: plain ACK",         tcp_to_service("A")),
    ]
    for name, frame in frames:
        sendp(frame, iface=IFACE, count=count, inter=0.1, verbose=False)
        print(f"scan: sent {count} x {name}")
    print(f"expect: tcp-scan +{5 * count}, passed +{count} (hits tcp +{count})")


def ip_to_board(**ip_fields):
    """Ethernet + IPv4 from the BBB to the board. ip_fields overwrite header
    fields Scapy would otherwise compute itself (len, ihl, version, frag...)."""
    return Ether(dst=BOARD_MAC) / IP(src=BBB_IP, dst=BOARD_IP, **ip_fields)


def scenario_malformed(count):
    """Headers that lie about themselves. Expect: malformed += 9*count, passed += count.

    Every frame comes from the honest BBB address to an open port, so the only
    reason to drop it is the broken header (stage 1, sanity). Note: the BBB pads
    short frames to 60 bytes, so "too long" lies must exceed 60 - 14 = 46 bytes.
    """
    udp = UDP(sport=40000, dport=UDP_TEST_PORT) / Raw(b"malformed")
    frames = [
        # IPv4 header
        ("IP version 6 inside an IPv4 frame",  ip_to_board(version=6) / udp),
        ("IHL 4 (header shorter than 20 B)",   ip_to_board(ihl=4) / udp),
        ("total length 10 (< header)",         ip_to_board(len=10) / udp),
        ("total length 1000 (> frame)",        ip_to_board(len=1000) / udp),
        # TCP/UDP header must fit inside the IP packet
        ("UDP header cut: total length 24",    ip_to_board(len=24) / udp),
        ("TCP data offset 4 (< 20 B)",
         ip_to_board() / TCP(sport=40001, dport=TCP_PORT, flags="A", dataofs=4)),
        ("TCP data offset 15 (past the end)",
         ip_to_board() / TCP(sport=40001, dport=TCP_PORT, flags="A", dataofs=15)),
        # RFC 1858 fragment attacks
        ("tiny fragment: 8 B of TCP header",
         ip_to_board(proto=6, flags="MF", frag=0) / Raw(bytes(TCP(dport=TCP_PORT))[:8])),
        ("overlapping fragment at offset 1",
         ip_to_board(proto=6, frag=1) / Raw(b"\x00" * 16)),
        # Control: the same sender and port, header honest. Must PASS.
        ("control: honest UDP",                ip_to_board() / udp),
    ]
    for name, frame in frames:
        sendp(frame, iface=IFACE, count=count, inter=0.1, verbose=False)
        print(f"malformed: sent {count} x {name}")
    print(f"expect: malformed +{9 * count}, passed +{count} (hits udp-test +{count})")


FLOOD_INTER = 0.02  # 50 frames/s: a flood for the 20/s and 10/s limits, but
                     # slow enough for the board's per-frame log line (~140/s).


def flood(name, frame, count, rate_pps, burst, counter):
    """Send count frames fast; print how many the token bucket should let pass."""
    start = time.monotonic()
    sendp(frame, iface=IFACE, count=count, inter=FLOOD_INTER, verbose=False)
    seconds = time.monotonic() - start

    allowed = min(count, burst + int(rate_pps * seconds))
    print(f"{name}: sent {count} frames in {seconds:.1f} s "
          f"({count / seconds:.0f} frames/s)")
    print(f"bucket: starts with {burst} tokens, refills {rate_pps}/s")
    print(f"expect: passed +{allowed} (about, +-2), rate-limit +{count - allowed}, "
          f"hits {counter} +{count}")


def scenario_syn_flood(count):
    """SYN flood on the service port. Rule tcp-new: 20/s, burst 5."""
    flood("syn-flood", tcp_to_service("S"), count, rate_pps=20, burst=5, counter="tcp-new")


def scenario_ping_flood(count):
    """Ping flood. Rule ping: 10/s, burst 5."""
    frame = Ether(dst=BOARD_MAC) / IP(src=BBB_IP, dst=BOARD_IP) / ICMP()
    flood("ping-flood", frame, count, rate_pps=10, burst=5, counter="ping")


SCENARIOS = {
    "normal": scenario_normal,
    "spoof": scenario_spoof,
    "scan": scenario_scan,
    "malformed": scenario_malformed,
    "syn-flood": scenario_syn_flood,
    "ping-flood": scenario_ping_flood,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("--count", type=int, default=10)
    args = parser.parse_args()
    SCENARIOS[args.scenario](args.count)


if __name__ == "__main__":
    main()
