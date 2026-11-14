#!/usr/bin/env python3
"""
pulse_width.py - measure PERF_PIN pulse widths with a logic analyzer.

The firmware drives PERF_PIN (PA5, D13) HIGH while pkt_filter_process() runs.
This script captures that pin with a fx2lafw logic analyzer (sigrok-cli),
finds every HIGH pulse and prints min / avg / max width, in microseconds and
in CPU cycles at 550 MHz, to compare with the DWT number in the board's stats.

Run on the PC (WSL Ubuntu, analyzer attached with usbipd):
    python3 tools/la/pulse_width.py            # waits for the first pulse
then send traffic from the BBB, e.g.:
    sudo python3 nic_test.py normal --count 10

Wiring: analyzer GND -> board GND, analyzer CH1 (sigrok D0) -> D13.
"""
import argparse
import re
import statistics
import subprocess
import sys

CPU_HZ = 550_000_000


def parse_rate(text):
    """'12m' -> 12000000, '500k' -> 500000, '24000000' -> 24000000."""
    mult = {"k": 1_000, "m": 1_000_000}
    t = text.lower()
    if t[-1] in mult:
        return int(float(t[:-1]) * mult[t[-1]])
    return int(t)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rate", default="12m",
                    help="sample rate, e.g. 12m (default) or 24m")
    ap.add_argument("--seconds", type=float, default=2.0,
                    help="capture length after the first pulse (default 2)")
    ap.add_argument("--channel", default="D0", help="analyzer channel (default D0)")
    args = ap.parse_args()

    rate = parse_rate(args.rate)
    samples = int(rate * args.seconds)
    bit = int(args.channel.lstrip("Dd"))

    cmd = ["sigrok-cli", "-d", "fx2lafw",
           "-C", args.channel,
           "-c", f"samplerate={rate}",
           "--samples", str(samples),
           "--triggers", f"{args.channel}=r",   # start at the first rising edge
           "--wait-trigger",
           "-O", "binary"]
    print(f"Capturing {args.seconds} s at {rate / 1e6:g} MHz "
          f"(resolution {1e9 / rate:.0f} ns). Waiting for the first pulse...",
          file=sys.stderr)
    data = subprocess.run(cmd, stdout=subprocess.PIPE, check=True).stdout
    if len(data) < samples:
        print(f"warning: got {len(data)} of {samples} samples "
              f"(USB too slow? try a lower --rate)", file=sys.stderr)

    # One byte per sample, bit N = channel DN. Keep only our channel as 0/1.
    mask = 1 << bit
    table = bytes((1 if (b & mask) else 0) for b in range(256))
    levels = data.translate(table)

    widths = []
    for m in re.finditer(rb"\x01+", levels):
        if m.end() == len(levels):
            break                     # still HIGH when the capture ended: incomplete
        widths.append(m.end() - m.start())

    if not widths:
        print("No complete pulses captured.")
        return 1

    us = [w * 1e6 / rate for w in widths]
    avg = statistics.mean(us)
    print(f"pulses: {len(us)}")
    print(f"width  min {min(us):.3f} us  avg {avg:.3f} us  max {max(us):.3f} us")
    print(f"       = avg {avg * CPU_HZ / 1e6:.0f} CPU cycles at 550 MHz "
          f"(+/- {CPU_HZ / rate:.0f} cycles per sample)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
