#!/bin/sh
# stress.sh - send UDP frames to the board at rising rates with Linux pktgen.
#
# Scapy (nic_test.py) tops out at ~40 frames/s on the BBB, far too slow to
# load the filter (~290 000 frames/s). pktgen is a packet generator inside
# the kernel: it reuses one prepared frame and sends it in a tight loop.
#
# Every frame is the same 60-byte UDP frame to port 5000 (rule udp-test,
# PASS, no rate limit), so each one walks the full pipeline and is counted
# as passed. Compare per step: frames sent (pktgen "Result") with the board's
# "mac rx unicast" (reached the MAC) and "passed" (reached the filter).
#
# Usage (on the BBB):
#   sudo sh stress.sh                  # default ramp
#   sudo sh stress.sh 1000 5000 0      # custom rates, 0 = as fast as possible
#   sudo MAX_COUNT=4500000 sh stress.sh 0   # sustained: ~30 s at line rate
#
# Each step sends for ~3 s, then waits 12 s so the board's 5 s stats line
# shows each step on its own.

DEV=eth0
BOARD_IP=192.168.10.1
BBB_IP=192.168.10.2
BOARD_MAC=00:80:e1:00:00:00
STEP_SECONDS=3
GAP_SECONDS=12

RATES=${*:-"1000 2000 5000 10000 20000 50000 0"}

PG=/proc/net/pktgen
modprobe pktgen || exit 1

pgset() {   # pgset "command" file
    echo "$1" > "$2"
    if ! grep -q "Result: OK" "$2"; then
        echo "pktgen rejected '$1':"; grep "Result:" "$2"; exit 1
    fi
}

pgset "rem_device_all" $PG/kpktgend_0
pgset "add_device $DEV" $PG/kpktgend_0
D=$PG/$DEV

pgset "clone_skb 100000"      $D   # reuse the same frame: no per-frame allocation
pgset "pkt_size 60"           $D   # 60 B + 4 B FCS = minimum Ethernet frame
pgset "dst $BOARD_IP"         $D
pgset "src_min $BBB_IP"       $D
pgset "src_max $BBB_IP"       $D
pgset "dst_mac $BOARD_MAC"    $D
pgset "udp_src_min 40000"     $D
pgset "udp_src_max 40000"     $D
pgset "udp_dst_min 5000"      $D
pgset "udp_dst_max 5000"      $D

step=0
for rate in $RATES; do
    step=$((step + 1))
    if [ "$rate" -eq 0 ]; then
        delay=0
        count=${MAX_COUNT:-300000}   # max speed: a fixed number of frames (~2 s)
        label="max"
    else
        delay=$((1000000000 / rate)) # ns between frames
        count=$((rate * STEP_SECONDS))
        label="$rate/s"
    fi
    pgset "delay $delay" $D
    pgset "count $count" $D

    echo "step $step: rate $label, sending $count frames..."
    echo "start" > $PG/pgctrl        # blocks until all frames are sent
    # pktgen's own report: frames sent, time, achieved rate
    grep -E "Result:|pkts-sofar" $D | sed 's/^/    /'
    sleep $GAP_SECONDS
done
echo "done"
