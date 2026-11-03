#!/usr/bin/env python3
"""Traffic generator for the STM32 SmartNIC filter, run on the BeagleBone Black.

Each scenario sends a known set of frames. Compare the board's counters
(PuTTY stats line) with what the scenario says it expects.

Usage (on the BBB, needs root for raw sockets):
    sudo python3 nic_test.py normal --count 10
"""

import argparse

from scapy.all import Ether, IP, UDP, Raw, sendp

IFACE = "eth0"
BOARD_MAC = "00:80:e1:00:00:00"   # main.c MX_ETH_Init MACAddr
BOARD_IP = "192.168.10.1"         # filter_policy.h POLICY_BOARD_IP
BBB_IP = "192.168.10.2"
UDP_TEST_PORT = 5000              # filter_policy.h POLICY_UDP_TEST_PORT


def scenario_normal(count):
    """Wanted traffic: UDP to the test port. Expect: passed += count, udp-test hits."""
    frame = (Ether(dst=BOARD_MAC)
             / IP(src=BBB_IP, dst=BOARD_IP)
             / UDP(sport=40000, dport=UDP_TEST_PORT)
             / Raw(b"smartnic"))
    sendp(frame, iface=IFACE, count=count, inter=0.1, verbose=False)
    print(f"normal: sent {count} UDP frames to port {UDP_TEST_PORT}")
    print(f"expect: passed +{count}, udp-test +{count}")


SCENARIOS = {
    "normal": scenario_normal,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("--count", type=int, default=10)
    args = parser.parse_args()
    SCENARIOS[args.scenario](args.count)


if __name__ == "__main__":
    main()
