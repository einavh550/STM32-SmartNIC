# STM32-SmartNIC

[![host-tests](https://github.com/einavh550/STM32-SmartNIC/actions/workflows/host-tests.yml/badge.svg)](https://github.com/einavh550/STM32-SmartNIC/actions/workflows/host-tests.yml)

Bare-metal firmware that turns an STM32H723 into a simple SmartNIC: it receives
Ethernet frames through the MAC's DMA, hands them from the interrupt to the main
loop without copying, parses the Ethernet / IPv4 / TCP / UDP headers and runs
them through a first-match rule filter.
A BeagleBone Black on the other end of the cable acts as the traffic generator.

## Hardware

| Part             | Role                                                      |
|------------------|-----------------------------------------------------------|
| NUCLEO-H723ZG    | Target. Cortex-M7 (up to 550 MHz), on-board LAN8742 PHY (RMII) |
| BeagleBone Black | Traffic generator (Linux, Python/Scapy), direct cable     |
| ST-LINK V3 (on-board) | Flashing, debugging, virtual COM port for logs (115200 8N1) |

## Status

| Phase | Description                                   | State       |
|-------|-----------------------------------------------|-------------|
| 1     | Lock-free SPSC ring buffer + on-target test   | Done        |
| 2     | Interrupt-driven, zero-copy Ethernet RX       | Done, verified on hardware |
| 3     | Header parsing and filter pipeline: sanity, anti-spoofing, TCP scan detection, rate limiting, rule policy | Done: verified on hardware, host unit tests in CI |
| 4     | Traffic generation and stress tests from the BBB | In progress: link up, Scapy generator, normal / spoof / scan / flood / malformed scenarios verified |
| 5     | Profiling, throughput limits, hardening       | Planned     |

## RX data path

```
            ETH DMA                    ETH IRQ                       main loop
  wire --> writes frame into  -->  HAL_ETH_RxLinkCallback  -->  eth_rx_pop()
           a buffer from the       pushes {ptr, len} into      process frame
           D2 SRAM pool            pkt_ring                    eth_rx_buf_free()
               ^                                                     |
               |            HAL_ETH_RxAllocateCallback               |
               +------------ pops an empty buffer <---- free_ring <--+
```

- 16 RX buffers of 1536 bytes live in a fixed pool. Frames are never copied;
  only an 8-byte descriptor (`pointer, length, flags`) moves between contexts.
- Two SPSC rings connect the contexts, each with exactly one writer:
  - `pkt_ring`: ISR -> main (buffers holding a received frame)
  - `free_ring`: main -> ISR (empty buffers ready for the DMA)
- Both rings are larger than the pool, so a push can never fail. If the main
  loop falls behind, the pool runs empty and the DMA simply has nowhere to write;
  the ISR never blocks.

## Design notes

**Ring buffer (`ring_buffer.c`)**
- Single producer / single consumer, synchronised with C11 acquire/release
  atomics. Interrupts are never disabled.
- Free-running 32-bit head/tail indices; the slot is `index & (N - 1)`, so the
  capacity must be a power of two (checked with `_Static_assert`).
- Drop counter for frames rejected when the ring is full.

**Memory and cache coherency (STM32H7 specific)**
- The ETH DMA cannot reach DTCM, so RX/TX descriptors and the RX buffer pool are
  placed in D2 SRAM (`0x30000000`) through dedicated `NOLOAD` sections in the
  linker script.
- I-Cache and D-Cache are enabled. An MPU region marks the 32 KB of D2 SRAM as
  non-cacheable, so the CPU always sees what the DMA wrote without manual cache
  maintenance.

**Header parser (`pkt_parse.c`)**
- Parses layer by layer, each step only if the previous one succeeded:
  Ethernet (MACs, EtherType) -> IPv4 (addresses, protocol, header length,
  fragment offset) -> TCP/UDP (ports).
- Fields are read byte by byte with explicit big-endian helpers instead of
  casting a struct over the buffer: no alignment or padding assumptions.
- Every read is bounds-checked against the frame length; a truncated or
  inconsistent header (wrong version, IHL < 5, options past the end) is rejected.
- IPv4 options are supported through the IHL field (`l4_offset = 14 + IHL * 4`).
- The IPv4 total length is checked against the frame: smaller than the header,
  or larger than what arrived, is malformed. A longer frame is accepted
  (Ethernet pads short frames to 60 bytes), and the TCP/UDP header must fit
  inside the IP packet, so padding bytes are never read as ports.
- RFC 1858 fragment attacks are dropped as malformed: a first TCP fragment too
  small to hold the full TCP header (tiny fragment), and a TCP fragment at
  offset 1 that would overwrite the TCP flags (overlapping fragment).
- Non-first IP fragments carry no L4 header, so no ports are read from them.
- TCP: the flags byte is read, and the header length field (data offset) must
  be at least 20 bytes and fit inside the IP packet.
- `pkt_hdr_t.valid` records which layers were parsed (`PKT_HAS_ETH/IPV4/L4`).
- Pure C, no HAL: the same file is compiled for the board and for host tests.

**Rule filter (`pkt_filter.c`)**
- `pkt_filter_process()` is the whole per-frame pipeline. Each stage either
  decides or hands the frame to the next one; the fixed checks run before the
  rule table, so no rule can let a bad frame through:
  1. **sanity**: malformed frames are dropped;
  2. **anti-spoofing**: source addresses no honest sender can have
     ("martians", RFC 1812 / RFC 5735) are dropped: a multicast/broadcast
     source MAC, a loopback (127/8), multicast, reserved or broadcast source
     IP, source 0.0.0.0 (allowed only for a DHCP request, UDP 68 -> 67), and
     source == destination (LAND attack). Which subnets may send on this link
     (ingress filtering, BCP 38) is policy and belongs in the rule table;
  3. **TCP scan detection**: the TCP flags must be a combination a real TCP
     stack sends. A 32-entry whitelist (the same idea as Linux
     `nf_conntrack`) drops NULL, FIN, XMAS, SYN+FIN, SYN+RST scans in one
     table lookup. Stateless, so ACK / FIN+ACK scans are not caught;
  4. **rule table**, with actions PASS, DROP and RATE_LIMIT.

  It returns a verdict (`action`, drop `reason`, matching `rule_idx`).
- A frame is malformed when a layer it claims to have is broken (EtherType
  says IPv4 but the header or its length is invalid, protocol says TCP/UDP but
  the header does not fit, RFC 1858 fragments). An absent layer is not an
  error (ARP, ICMP, later fragments).
- Ordered rule table, first match wins, default action if nothing matches
  (like a firewall rule list).
- A rule compares only the fields named in its `match` bits: EtherType,
  IP protocol, source/destination IP under a mask (subnets), ports, and TCP
  flags under a mask (e.g. mask `SYN|ACK`, value `SYN` = new connection).
- A rule that asks about a layer the frame does not have never matches, so a
  port rule cannot hit an ARP frame through stale fields.
- **Rate limiting (flood protection):** a `PKT_RATE_LIMIT` rule passes
  matching frames through a token bucket: `rate_pps` tokens per second, at
  most `burst` stored, one token per frame, the rest is dropped as
  `rate-limit`. Example: a rule on TCP flags `SYN` without `ACK` with
  10/s, burst 3 limits new connections (SYN flood) while data packets of open
  connections are not slowed down.
  - Tokens are kept in thousandths, so the refill `elapsed_ms * rate_pps` is
    exact integer math (no float, no rounding loss); 64-bit for the product,
    so even a gap of days cannot overflow.
  - Time comes from the caller (`HAL_GetTick()` on the board, a fake clock in
    the tests), which keeps the filter free of HAL. Tick wrap-around after
    49.7 days is handled by unsigned subtraction.
  - Each rule has its own bucket in `pkt_filter_t`; the rule table stays `const`.
  - The limit is per rule (aggregate): all senders matching a rule share one
    bucket. That protects the board from any number of senders, but a flood
    also uses up the share of honest senders (see limitations).
- The rule table is `const`. The filter instance (`pkt_filter_t`) keeps the
  statistics: per-rule hits, default hits, passed frames and drops per reason
  (`malformed`, `spoofed`, `tcp-scan`, `rate-limit`, `rule`, `default`). The
  main loop prints them every 5 s (example numbers):
  ```
  --- passed 7 | dropped: malformed 0 spoofed 0 tcp-scan 0 rate-limit 0 rule 0 default 14 | hits: arp:7 ping:0 tcp-new:0 tcp:0 udp-test:0 default:14 ---
  ```

**Filter policy (`filter_policy.c`)**

The rule table the board runs, for a direct cable to the BeagleBone Black on
`192.168.10.0/24` (board `.1`, BBB `.2`). It lives in its own file so the host
tests check exactly this table. Default deny: anything not listed is dropped.

| # | Name       | Matches                                         | Action                 | Protects against |
|---|------------|-------------------------------------------------|------------------------|------------------|
| 0 | `arp`      | ARP                                             | rate limit 20/s, burst 10 | ARP storm     |
| 1 | `ping`     | ICMP, link subnet -> board                      | rate limit 10/s, burst 5  | ping flood    |
| 2 | `tcp-new`  | TCP SYN without ACK, link subnet -> board:80    | rate limit 20/s, burst 5  | SYN flood     |
| 3 | `tcp`      | other TCP, link subnet -> board:80              | pass                   |                  |
| 4 | `udp-test` | UDP, link subnet -> board:5000                  | pass, no limit         | (throughput tests measure the board, not the limiter) |
| - | default    | everything else                                 | drop                   | unlisted services, other subnets, IPv6 |

- Every IP rule requires a source in the link subnet and the board as
  destination: ingress filtering (BCP 38) is part of the policy.
- `tcp` can pass every flag combination it sees, because scans were already
  dropped by the scan stage and new connections were already caught by `tcp-new`.
- Rate numbers are first guesses, to be tuned from measurements in Phase 4.

**HAL integration**
- Uses the HAL ETH driver's buffer callbacks (`RxAllocateCallback`,
  `RxLinkCallback`) so the driver works directly on the pool buffers.
- `HAL_ETH_RxCpltCallback` drains every completed descriptor with
  `HAL_ETH_ReadData()` in a loop, so a burst of frames is handled in one interrupt.

## Verification

- **Ring buffer:** on-target self-test (`ring_buffer_test.c`, enabled with
  `RB_SELF_TEST`) covering empty/full, drop on overflow, FIFO order and
  32-bit index wrap-around. Result is
  printed on the COM port and shown on the green LED.
- **Ethernet RX:** board connected to a live link; frames of 60, 110 and 342 bytes
  (ARP, discovery and DHCP traffic) were received continuously. More frames than
  pool buffers arrived, which confirms buffers are recycled correctly.

```
RB self-test: PASS (0 failures)
ETH RX started
RX frame: 342 bytes
RX frame: 60 bytes
RX frame: 110 bytes
```

- **Parser and filter on hardware:** live traffic from a PC was decoded as ARP
  (`0x0806`), DHCP Discover (`0.0.0.0 -> 255.255.255.255`, UDP 68 -> 67) and
  NetBIOS broadcasts (UDP 137). With a demo rule set (drop UDP:137, pass ARP,
  pass UDP:67, default drop) the per-rule counters matched the traffic seen.
- **BBB link (Phase 4):** `nic_test.py normal --count 10` sent 10 UDP frames
  to port 5000; the board logged 10 x `PASS (udp-test)` and the counters
  went to `passed 10 | udp-test:10`. The BBB's own DHCP Discover
  (`0.0.0.0 -> 255.255.255.255`, 68 -> 67) was dropped by the default rule.
- **Spoofed sources (BBB):** `nic_test.py spoof --count 3` sent UDP to the open
  test port from 127.0.0.1, 224.0.0.5, 255.255.255.255, 0.0.0.0 (not DHCP),
  the board's own IP (LAND) and a group source MAC, plus an honest-looking
  10.0.0.99 from outside the link subnet. Counters: `spoofed +18` (6 x 3),
  `default +3` (ingress filtering), `passed +0`, exactly as expected.
- **TCP scans (BBB):** `nic_test.py scan --count 3` sent NULL, FIN, XMAS
  (FIN+PSH+URG), SYN+FIN and SYN+RST to port 80, plus plain ACKs as a control.
  Two runs: `tcp-scan +30` (5 x 3 x 2), `passed +6` (`tcp:6`, the controls),
  nothing else changed. Flags logged as `0x01`, `0x29`, `0x03`, `0x06` -> DROP,
  `0x10` -> PASS.
- **SYN flood (BBB):** `nic_test.py syn-flood --count 200` sent 200 SYNs to
  port 80 in 5.4 s (37 frames/s) against the `tcp-new` bucket (20/s, burst 5).
  Predicted `5 + 20 x 5.4 = 112` passed; the board counted `passed +113`,
  `rate-limit +87`, `tcp-new +200` (off by one: the board's and the BBB's
  clocks do not start at the same instant).
- **Ping flood (BBB):** `nic_test.py ping-flood --count 200` sent 200 ICMP
  frames in 5.6 s (35 frames/s) against the `ping` bucket (10/s, burst 5).
  Predicted `5 + 10 x 5.6 = 61` passed / 139 rate-limited; the board counted
  about 63 / 137 and `ping +200`. In the log, roughly one ping in 3.5 passes
  (35 arriving per second, 10 tokens per second).
- **Malformed headers (BBB):** `nic_test.py malformed --count 3` sent 9 kinds
  of lying headers (IPv4 version 6, IHL 4, total length 10 and 1000, UDP
  header cut by the total length, TCP data offset 4 and 15, RFC 1858 tiny and
  overlapping fragments) plus an honest UDP control frame. With the HAL
  default MAC settings the board counted only `malformed +12` (the 4 TCP
  kinds) and `passed +3`: the 15 frames with a broken IPv4 header were never
  seen by the firmware and appeared in no counter. Cause: the MAC's checksum
  offload engine flags them and the MTL drops them in hardware, before the DMA
  (`DropTCPIPChecksumErrorPacket = ENABLE`). With that drop disabled, the same
  run gave `malformed +27`, `passed +3`, as predicted. The PC test harness
  checked beforehand that `pkt_parse.c` rejects all 9 frames, padded to 60 bytes.
- **Host unit tests:** 79 tests (380 checks) build `pkt_parse.c` and
  `pkt_filter.c` for the PC and feed them hand-built frames: valid ARP / UDP /
  TCP, byte order, truncated and malformed headers, lying IP total length,
  Ethernet padding, IPv4 and TCP options, fragments and RFC 1858 fragment
  attacks, real TCP flag combinations vs. NULL / FIN / XMAS scans, TCP flag rules,
  spoofed sources (loopback, multicast, broadcast, 0.0.0.0 outside DHCP, LAND,
  group source MAC), the token bucket (burst, refill, cap, tick wrap,
  overflow, SYN flood), the shipped policy (BBB traffic, SYN / ping / ARP
  floods, ingress filtering, unlisted services),
  first-match order, subnet masks, stale-field protection,
  and the pipeline verdicts and drop-reason counters. GitHub Actions runs them on every push with
  AddressSanitizer + UBSan, so any read past the end of a frame fails the build.

## BBB test link

The BBB is controlled over USB SSH (`ssh debian@192.168.7.2`) while its
Ethernet port is cabled directly to the board. Its
`/etc/systemd/network/eth0.network`:

```
[Match]
Name=eth0

[Network]
DHCP=ipv4
Address=192.168.10.2/24

[Neighbor]
Address=192.168.10.1
LinkLayerAddress=00:80:e1:00:00:00
```

- DHCP stays on so the same cable can go to a router for `apt install`;
  on the board link only the static address is used.
- The board has no TX path yet, so it never answers ARP. The static
  neighbor entry gives the BBB the board's MAC up front; Scapy scenarios
  send at layer 2 (`sendp`) and set the MAC themselves.

Scenarios live in `tools/bbb/nic_test.py` (Scapy 2.5, `apt install
python3-scapy`). Copy it over USB and run it on the BBB:

```
scp tools/bbb/nic_test.py debian@192.168.7.2:~     # on the PC
sudo python3 nic_test.py normal --count 10         # on the BBB
```

Each scenario prints the counter change it expects, to compare with the
board's stats line.

## Running the unit tests

Needs a host GCC (Linux/macOS: `gcc` + `make`; Windows: e.g. WinLibs GCC,
where make is called `mingw32-make`).

```
cd tests
make            # Windows: mingw32-make
make SAN=1      # with AddressSanitizer + UBSan (Linux/macOS)
```

Expected last line: `380 checks, 0 failed: PASS`.

## Build and flash

Toolchain: STM32CubeIDE 2.x (GCC arm-none-eabi). Peripheral setup is generated
from `STM32-SmartNIC.ioc`; MPU, cache and NVIC changes are made in CubeMX, and
hand-written code stays inside `USER CODE` blocks or in separate files.

1. Import the project into STM32CubeIDE and build the `Debug` configuration.
2. Flash from the IDE, or with STM32CubeProgrammer:
   ```
   STM32_Programmer_CLI -c port=SWD mode=UR -w Debug/STM32-SmartNIC.elf -v -hardRst
   ```
3. Open the ST-LINK virtual COM port at 115200 baud to see the log.

## Project layout

```
Core/Inc, Core/Src
  ring_buffer.[ch]       SPSC ring buffer
  ring_buffer_test.[ch]  on-target self-test
  eth_rx.[ch]            RX buffer pool, HAL ETH callbacks, rings glue
  pkt_parse.[ch]         Ethernet / IPv4 / TCP / UDP header parser
  pkt_filter.[ch]        filter pipeline, rules, token buckets, counters
  filter_policy.[ch]     the rule table the board runs (BBB link)
  main.c                 init sequence, main loop, rule table and counters
tools/bbb/nic_test.py    Scapy traffic generator, run on the BBB
tests/                   host unit tests (parser, filter) + Makefile
.github/workflows/       CI: runs the host tests on every push
STM32H723ZGTX_FLASH.ld   linker script with D2 SRAM sections for the ETH DMA
STM32-SmartNIC.ioc       CubeMX configuration (clocks, ETH, MPU, NVIC)
```

## Known limitations

- If all 16 buffers are in use, the DMA stops with "RX buffer unavailable" and is
  not yet restarted automatically when buffers are freed.
- The core runs directly from the 8 MHz HSE clock; PLL configuration to full
  speed is planned for the profiling phase.
- Only 4 RX DMA descriptors (CubeMX default); to be tuned during stress testing.
- The `flags` field of the packet descriptor is not filled yet (no per-frame
  error reporting).
- The parser handles untagged Ethernet + IPv4 only; VLAN-tagged frames and
  IPv6 are classified by EtherType but not parsed further.
- The filter is stateless (no connection tracking): ACK / FIN+ACK scans look
  like normal traffic, and a spoofed source that looks valid (inside the link
  subnet) cannot be told apart from a real one. ARP is not inspected (no
  ARP-spoofing detection).
- Rate limits are per rule, shared by all senders: a flood is capped, but it
  also takes the share of honest senders. Per-source buckets (a hash table
  keyed by source IP, plus the total cap) would make it fair.
- No device can stop a flood larger than its link: that has to be filtered
  upstream.
- Rules cannot say "not" (e.g. "source not in subnet"); ingress filtering is
  done by requiring the subnet in every allow rule.
- The COM log loses characters (e.g. `passd`, `drppe`) under steady
  traffic. Under investigation (per-frame printf load, 8 MHz clock).
