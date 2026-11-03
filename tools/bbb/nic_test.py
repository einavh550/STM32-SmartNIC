#!/usr/bin/env python3
"""Traffic generator for the STM32 SmartNIC filter, run on the BeagleBone Black.

Each scenario sends a known set of frames. Compare the board's counters
(PuTTY stats line) with what the scenario says it expects.

Usage (on the BBB, needs root for raw sockets):
    sudo python3 nic_test.py normal --count 10
"""

import argparse

from scapy.all import Ether, IP, TCP, UDP, Raw, sendp

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


SCENARIOS = {
    "normal": scenario_normal,
    "spoof": scenario_spoof,
    "scan": scenario_scan,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("--count", type=int, default=10)
    args = parser.parse_args()
    SCENARIOS[args.scenario](args.count)


if __name__ == "__main__":
    main()
