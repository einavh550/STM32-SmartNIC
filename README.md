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
| 4     | Traffic generation and stress tests from the BBB | In progress: link up, Scapy generator, normal / spoof / scan / flood / malformed / bad-checksum scenarios verified, core at 550 MHz (PLL), per-frame log switch (USER button), DWT cycles per frame and per path, cross-checked with a GPIO pulse + logic analyzer, stress tested at 100 Mbit/s line rate with zero loss (after two fixes) |
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
  1. **sanity**: malformed frames are dropped; then frames whose headers look
     valid but whose MAC checksum offload report says the bytes are corrupted
     (`bad-checksum`, see Checksum offload). A frame that is both broken and
     flagged counts as `malformed`: the parser's answer is more precise and
     does not depend on the hardware. Corrupted frames are dropped before
     anti-spoofing, because their addresses may be the corrupted part;
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
  (`malformed`, `bad-checksum`, `spoofed`, `tcp-scan`, `rate-limit`, `rule`, `default`). The
  main loop prints them every 5 s (example numbers):
  ```
  --- passed 7 | dropped: malformed 0 bad-checksum 0 spoofed 0 tcp-scan 0 rate-limit 0 rule 0 default 14 | hits: arp:7 ping:0 tcp-new:0 tcp:0 udp-test:0 default:14 ---
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

**Clock tree (CubeMX)**
- 8 MHz HSE → PLL1 (÷4 = 2 MHz input, ×275, ÷1) → **550 MHz** SYSCLK / CPU,
  the maximum for the STM32H723.
- AXI / AHB (ETH DMA, SRAM) 275 MHz, APB1-4 137.5 MHz: each at its limit.
- Needs core voltage scale 0 and 3 flash wait states (`FLASH_LATENCY_3`):
  flash cannot deliver an instruction every cycle at this speed.
- UART baud rate and the 1 ms SysTick are recomputed by the HAL from the new
  clocks. The boot log prints `CPU clock: 550 MHz`, read back from the RCC
  registers.

**Per-frame log switch (USER button)**
- One log line at 115200 baud takes ~7 ms, thousands of times longer than
  filtering the frame, so with the log on any timing would measure the UART,
  not the filter.
- The blue USER button toggles the per-frame log at runtime (no reflash).
  The yellow LED is on while the log is on; the board prints
  `Per-frame log ON` / `OFF`. It starts ON. The stats line every 5 s is always
  printed.
- The button interrupt (`BSP_PB_Callback`) only sets a flag; the main loop
  flips the switch and prints, so no `printf` runs inside an ISR. Presses
  closer than 200 ms are ignored (contact bounce).

**Cycle measurement (DWT)**
- The Cortex-M7 DWT unit has a 32-bit counter, `CYCCNT`, that counts CPU
  clock cycles (1 cycle = 1.82 ns at 550 MHz). `perf.[ch]` starts it at boot
  and reads it before and after `pkt_filter_process()` (parse + all filter
  stages) for every frame.
- The cost of the two reads themselves is measured at boot and subtracted.
- Every 5 s the stats show min / avg / max cycles per frame for that period
  (and avg in ns), then the numbers restart.
- `max` can include an Ethernet interrupt that arrived during the
  measurement; `min` and `avg` are the filter's own cost.
- Cross-check from outside: `PERF_PIN` (PA5, header pin D13, set up in
  CubeMX, very high speed) is HIGH while `pkt_filter_process()` runs. The pin
  is written through `BSRR` (one store) so the edges add almost nothing.
  `tools/la/pulse_width.py` captures it with a logic analyzer (sigrok-cli) and
  prints min / avg / max pulse width and a histogram of widths (frames that
  take different paths form separate groups). It reads the capture in 1 MB
  chunks, so long captures fit in memory. It matches the DWT number (see
  Performance).
- Per-path stats: each frame's cycles are also added to the stats of its
  path (drop stage, or matched rule + pass / rate-limit), kept since boot and
  printed as `--- cycles by path (since boot) ---` after every period that
  had frames.

**Checksum offload (MAC hardware)**
- The MAC checks every IPv4 header and TCP/UDP/ICMP checksum in hardware while
  the frame arrives, at no CPU cost, and writes the result into the RX
  descriptor (DESC1: `IPHE` IP header error, `IPCE` IP payload error).
- The HAL default (`DropTCPIPChecksumErrorPacket = ENABLE`) also drops the
  failing frames inside the MAC, before the DMA, with no counter: the firmware
  never learns they existed (found with the `malformed` scenario, see
  Verification). `main.c` disables that drop, so every frame reaches the
  firmware and every drop is counted.
- The HAL keeps only DESC3 of a finished descriptor and the link callback gets
  only the buffer address. `eth_rx.c` finds the descriptor that owns the buffer
  (`BackupAddr0`, 4 descriptors), checks `RS1V` (DESC1 valid) and translates
  `IPHE` / `IPCE` into `PKT_FLAG_IP_HDR_ERR` / `PKT_FLAG_IP_PAYLOAD_ERR` in
  `pkt_desc_t.flags` (`pkt_flags.h`), our own bits, so the code that reads them does not
  depend on the descriptor layout. This happens inside `HAL_ETH_ReadData()`,
  before the HAL rebuilds the descriptor; the descriptors are in non-cacheable
  D2 SRAM, so no cache maintenance is needed.
- The RX log shows the report as `[hw: ip-hdr]` / `[hw: payload]`, and the
  filter drops such frames as `bad-checksum` (see Rule filter).

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
  With the MAC's report shown in the log (`--count 1`, `malformed +9`,
  `passed +1`): version 6 and IHL 4 -> `[hw: ip-hdr]`; total length 10, 1000
  and the cut UDP header -> `[hw: payload]` (the hardware counts a total length
  that disagrees with the received bytes as a payload error, not a header
  error); TCP data offset 4 and 15 -> no report (the hardware checksums all the
  bytes and ignores the data offset; only the parser catches them); both
  fragments -> no report (the hardware does not checksum fragments; only the
  RFC 1858 checks catch them). Hardware and parser check different things.
- **Checksum errors (BBB):** the `malformed` scenario also sends two frames
  whose headers are correct but whose checksums are wrong: IP header checksum
  `0xDEAD` (correct value `0xE573`) and UDP checksum `0xBEEF` (correct value
  `0xA00F`). The parser accepts both, so only the MAC can catch them.
  `--count 1` gave `malformed +9`, `bad-checksum +2`, `passed +1`, as expected.
  Log: `p17 40000->5000 [hw: ip-hdr] => DROP (bad-checksum)` and
  `p17 40000->5000 [hw: payload] => DROP (bad-checksum)`. The bad-checksum
  path works end to end, from the RX descriptor's status bits through the ISR
  and the main loop to the filter.
- **Host unit tests:** 82 tests (401 checks) build `pkt_parse.c` and
  `pkt_filter.c` for the PC and feed them hand-built frames: valid ARP / UDP /
  TCP, byte order, truncated and malformed headers, lying IP total length,
  Ethernet padding, IPv4 and TCP options, fragments and RFC 1858 fragment
  attacks, real TCP flag combinations vs. NULL / FIN / XMAS scans, TCP flag rules,
  spoofed sources (loopback, multicast, broadcast, 0.0.0.0 outside DHCP, LAND,
  group source MAC), the token bucket (burst, refill, cap, tick wrap,
  overflow, SYN flood), the shipped policy (BBB traffic, SYN / ping / ARP
  floods, ingress filtering, unlisted services),
  first-match order, subnet masks, stale-field protection, the MAC's
  checksum report (drops a valid-looking frame, loses to `malformed`, runs
  before anti-spoofing and scan detection),
  and the pipeline verdicts and drop-reason counters. GitHub Actions runs them on every push with
  AddressSanitizer + UBSan, so any read past the end of a frame fails the build.
- **Per-frame log switch:** log ON, `normal --count 10` printed 10 `RX` lines
  and `passed 10`; after one USER button press (`Per-frame log OFF`, yellow LED
  off) the same command printed no `RX` lines and the stats went to
  `passed 20`. The filter keeps running and counting with the log off.

## Performance

### Filter cost per frame: two independent measurements

The time `pkt_filter_process()` takes for one frame (parse + every filter
stage + counter update) was measured two ways at once:

1. **DWT cycle counter (inside):** the CPU counts its own clock cycles around
   the call (`perf.[ch]`, overhead of 13 cycles measured at boot and
   subtracted). Printed every 5 s in the stats line.
2. **GPIO pulse + logic analyzer (outside):** `PERF_PIN` (PA5, D13) is HIGH
   during the same call. A logic analyzer with its own clock measures the
   pulse (`tools/la/pulse_width.py`). It does not rely on anything the chip
   reports, so it checks both the DWT code and that the CPU really runs at
   550 MHz (the DWT -> ns conversion assumes it).

**Setup:** Debug build (`-O0`), core at 550 MHz, I-Cache + D-Cache on,
per-frame log OFF. Traffic: `nic_test.py normal` from the BBB (60-byte UDP
frames to port 5000, 10 per second), so every frame walks the full pipeline
and passes on the `udp-test` rule. Each run used a different `--count`, so
the matching stats line (`(N frames)`, `passed` +N) proves which run it was.
Analyzer: fx2lafw (Saleae-compatible clone), sigrok-cli in WSL2, GND + CH1 on
D13.

| Run | Frames | DWT min / avg / max (cycles) | DWT avg | Analyzer rate | Pulses | Analyzer min / avg / max | Analyzer avg (cycles) | Difference |
|-----|--------|------------------------------|---------|---------------|--------|--------------------------|-----------------------|------------|
| A   | 7      | 1837 / 1865 / 1904           | 3.39 us | 12 MHz (83 ns)  | 7 | 3.250 / 3.333 / 3.417 us | 1833 (+/- 46) | 32 cycles |
| B   | 5      | 1837 / 1837 / 1838           | 3.34 us | 12 MHz (83 ns)  | 5 | 3.250 / 3.283 / 3.333 us | 1806 (+/- 46) | 31 cycles |
| C   | 9      | 1837 / 1873 / 1904           | 3.41 us | 24 MHz (42 ns)  | 9 | 3.250 / 3.338 / 3.417 us | 1836 (+/- 23) | 37 cycles |

**Result: the filter takes about 1840-1870 cycles = 3.3-3.4 us per frame**
(Debug build). Earlier runs gave the same: avg 1864 and 1872 cycles.

**Reading the numbers**
- Pulse count = frame count in every run: every frame was seen by both
  methods.
- The two methods agree within about 35 cycles (~60 ns). The pulse is always
  a little shorter, and by about the same amount, so it is a fixed offset,
  not noise: the two pin writes (and, at `-O0`, the instructions that load the
  port address) sit inside the DWT window but outside the pulse.
- `min` is 1837 cycles in every run: the same frame always costs the same
  code path. The slower frames (up to 1904, +67 cycles) are most likely cache
  misses or a SysTick interrupt landing inside the measurement.
- 3.4 us per frame means the filter alone could handle about 290 000 frames/s.
  A 100 Mbit/s link carries at most ~148 800 minimum-size frames/s, so the
  filter is not the bottleneck on paper. The stress test (next) checks the
  whole path (DMA, interrupt, ring buffers).

**Reproduce:** see `tools/la/pulse_width.py` (wiring and commands in the
header). Order per run: start the script (it waits for the first pulse), then
send from the BBB.

### Filter cost per path

Every frame's cost is also recorded by the path it took through the filter
(`--- cycles by path (since boot) ---` block under the stats): which stage
dropped it, or which rule it matched and whether it passed or hit the rate
limit. One run of every BBB scenario, same setup as above (Debug `-O0`,
550 MHz, caches on, log OFF), all on one boot:

| Path (where the verdict is made) | Frames | min / avg / max (cycles) | avg time |
|----------------------------------|--------|--------------------------|----------|
| `malformed` (stage 1, sanity)            | 54  |  571 /  852 / 1137 | 1.55 us |
| `bad-checksum` (stage 1, MAC report)     | 12  | 1166 / 1177 / 1233 | 2.14 us |
| `spoofed` (stage 2, anti-spoofing)       | 24  | 1225 / 1260 / 1360 | 2.29 us |
| `tcp-scan` (stage 3, scan detection)     | 30  | 1357 / 1388 / 1437 | 2.52 us |
| rule `ping` (#2) pass                    | 76  | 1471 / 1527 / 1569 | 2.78 us |
| rule `ping` (#2) rate-limit drop         | 164 | 1491 / 1519 / 1560 | 2.76 us |
| rule `udp-test` (#5) pass                | 27  | 1832 / 1859 / 1899 | 3.38 us |
| `default` drop (no rule matched)         | 36  | 1785 / 1860 / 2373 | 3.38 us |
| rule `tcp` (#4) pass                     | 6   | 1922 / 1942 / 2003 | 3.53 us |
| rule `tcp-new` (#3) rate-limit drop      | 42  | 1915 / 1946 / 1996 | 3.54 us |
| rule `tcp-new` (#3) pass                 | 58  | 1924 / 1958 / 2064 | 3.56 us |

Every counter moved by exactly what the scenario promises (e.g. `malformed
--count 2`: malformed +18, bad-checksum +4, passed +2; `spoof --count 2`:
spoofed +12, default +2). `default` also holds the BBB's own background
frames (DHCP), hence its wider max.

**Logic analyzer cross-check, per scenario** (pulse-width histogram, which
splits the paths from outside the chip):

| Scenario | Frames | Pulses | Groups seen by the analyzer | Analyzer avg vs. DWT avg |
|----------|--------|--------|-----------------------------|--------------------------|
| `normal --count 11`      | 11  | 11  | one group, 1788-1879 cycles | 1808 vs 1849 |
| `spoof --count 2`        | 14  | 14  | 12 spoofed at 1192-1329 + 2 default at 1742 | 1238 vs ~1270 (spoofed) |
| `scan --count 3`         | 18  | 18  | 15 scans at 1329-1421 + 3 tcp pass at 1879 | 1360 vs ~1390 (scans) |
| `malformed --count 2`    | 24  | 23  | 8 at 550-642 + 10 at 917-1100 (malformed), 4 at 1146 (bad-checksum), 1 pass | 838 vs ~854 (malformed) |
| `syn-flood --count 100`  | 100 | 100 | one group, 1879-2017 | 1914 vs ~1953 |
| `ping-flood --count 120` | 120 | 120 | one group, 1375-1558 (6 MHz, +/- 92 cycles) | 1493 vs 1523 |

The analyzer saw every frame except one control frame at the end of the
`malformed` run (the last frames sent; the capture window most likely
closed first). The same ~20-40 cycle offset as above appears in every run.

**What the numbers say**
- **The earlier a frame is decided, the cheaper it is.** The cost grows with
  the pipeline order: sanity (malformed, ~850) < MAC checksum report (~1180)
  < anti-spoofing (~1260) < scan detection (~1390) < rule table (1520-1960).
  Bad traffic that is caught early is cheap: a malformed frame costs less
  than half of a frame that passes.
- **The analyzer even sees the order inside one stage.** The malformed run
  splits into two groups: 8 frames at ~600 cycles (4 broken IPv4 header kinds
  x 2: version, IHL, total length) and 10 at ~1000 (5 broken TCP/UDP header
  or fragment kinds x 2), which are only checked after the IPv4 header has
  been parsed.
- **First match: rule position matters.** Among non-TCP frames, `ping`
  (matched by rule #2) costs ~1520 cycles and `udp-test` (rule #5) ~1860:
  about 110 cycles for every rule checked before the match (Debug build). A
  frame that matches nothing walks all 5 rules (`default`, ~1860). The most
  common traffic should sit at the top of the table.
- **TCP costs more than its rule position.** TCP frames (rules #3 and #4)
  cost ~1950, more than `udp-test` at #5: the TCP header is parsed further
  and goes through scan detection.
- **A rate-limited drop costs the same as a pass** (ping 1519 vs 1527,
  tcp-new 1946 vs 1958): the token bucket is checked only after the frame has
  walked the whole pipeline and matched its rule. During a flood the filter
  pays full price for every frame. Rate limiting protects what is behind the
  board, not the board's own CPU; an early per-source block (before the
  rules) would make flood frames cheap.
- **Token buckets behave as configured.** `ping-flood --count 120` gave
  38 passed / 82 rate-limited twice in a row (burst 5 + 10/s for ~3.3 s, the
  BBB sends ~36 frames/s); `syn-flood --count 100` gave 58 / 42 (burst 5 +
  20/s for ~2.6 s).

**How the data was collected** (and what went wrong)
- The board was flashed once and not reset, so the per-path numbers add up
  over all runs. Every run used its own `--count`, and the counters' change
  proved which run each stats line belongs to. The PuTTY session was logged
  to a file and the numbers were read from it.
- The analyzer script starts on the first rising edge. Three times it
  started on a background frame from the BBB (its DHCP client) and its window
  ended before the scenario was sent (1 pulse instead of 11, 24, 120). Those
  captures were thrown away and repeated with a longer window (`--seconds 10`
  or `--seconds 20 --rate 6m`).

### Stress test setup (in progress)

- Scapy sends only ~40 frames/s from the BBB, far below what the filter can
  take. `tools/bbb/stress.sh` uses Linux **pktgen** (a packet generator in the
  kernel) to send the same 60-byte UDP frame to port 5000 (rule `udp-test`)
  at rising rates: 1k, 2k, 5k, 10k, 20k, 50k frames/s, then as fast as
  possible.
- To see where frames are lost, the board now prints a hardware line every
  5 s: `--- hw: mac rx unicast N | filter saw M | fifo-overflow X dma-missed
  Y | rbu Z | free bufs F/16 ---`. `mac rx unicast` is the MAC's own counter
  (MMC `RX unicast good`), `fifo-overflow` / `dma-missed` are the MTL RX queue
  drop counters (clear-on-read, summed every main-loop pass), `rbu` counts
  DMA "receive buffer unavailable" interrupts (`HAL_ETH_ErrorCallback`), and
  `free bufs` is the pool's free ring. Frames sent by pktgen vs. `mac rx` vs.
  `passed` shows whether a frame was lost on the wire, in the MAC / DMA, or
  in software.

### Stress run 1: reception died for good at 1000 frames/s

| | Frames |
|---|---|
| Sent by pktgen (all 7 steps)       | 564 000 (max step: 300 000 in 2.02 s = 148 840 frames/s, the 100 Mbit/s line rate for 64-byte frames) |
| Received by the MAC (`mac rx unicast`) | 564 000: nothing lost on the wire |
| Seen by the filter                 | 892, then nothing until reset |
| Dropped in the MAC RX FIFO         | 554 949 |

The board died in the **first** step, 1000 frames/s, although the filter
alone could take ~290 000/s. The log shows the moment:
`mac rx unicast 892 | filter saw 884 | rbu 1 | free bufs 0/16`, and from then
on `free bufs 15/16` with nothing received. Two bugs together:

1. **The stats print blocks the main loop.** Every 5 s it prints ~600
   characters; at 115 200 baud that is ~50 ms in which no frame is processed.
   At 1000 frames/s ~50 frames arrive in that time, but there are only 16
   buffers: the pool runs empty and the DMA raises "receive buffer
   unavailable" (RBU) and suspends.
2. **Nothing ever woke the DMA up again (the serious one).** The main loop
   freed the buffers, but descriptors are only refilled inside
   `HAL_ETH_ReadData()`, which only the RX interrupt called, and a suspended
   DMA receives nothing, so there is no RX interrupt: a deadlock. One short
   overload killed reception until reset.

**Fix for bug 2:** `eth_rx_refill()`, called every main-loop pass. If the HAL
still has descriptors without a buffer (`RxDescList.RxBuildDescCnt != 0`),
it calls `HAL_ETH_ReadData()` with the ETH interrupt masked (the HAL's
descriptor bookkeeping is not reentrant). That gives the freed buffers to
the descriptors and writes the DMA tail pointer, which resumes a suspended
DMA. The hw line counts these as `refills`. Bug 1 (blocking UART output) is
next.

### Stress run 2: with the DMA recovery fix

Same ramp, same frames. Totals after each step (read from the stats lines):

| After step | Rate | Sent (total) | MAC got | Passed | Lost (total) | rbu / refills |
|---|---|---|---|---|---|---|
| 1 | 1 000/s | 3 000 | 3 000 | 2 993 | 7 | 3 / 3 |
| 2 | 2 000/s | 9 000 | 9 000 | 8 934 | 66 | 6 / 6 |
| 3 | 5 000/s | 24 000 | 24 000 | 23 720 | 280 | 9 / 9 |
| 6 | 50 000/s | 264 000 | 264 000 | 263 720 | 280 (+0 in steps 4-6) | 9 / 9 |
| 7 | max, 148 840/s | 564 000 | 564 000 | 563 720 | 280 (+0) | 9 / 9 |

- **The board survives overload.** The DMA ran out of buffers 9 times and
  was woken up 9 times (`rbu` = `refills`). Before the fix the first time
  was fatal.
- **The filter keeps up with the 100 Mbit/s line rate.** Step 7 delivered
  300 000 minimum-size frames at 148 840 frames/s, the most a 100 Mbit/s
  link can carry, and all 300 000 passed (one 5 s window: `300000 frames`,
  min 1821 / avg 1851 / max 1961 cycles, the same 3.37 us per frame as at
  low rate). At line rate the filter uses about half of the CPU
  (148 840 x 3.37 us = 0.50 s per second). On this link the bottleneck is
  the cable, not the filter.
- **Every lost frame was lost while the stats were printing.** The 280
  losses all happened in steps 1-3, where a stats print fell inside a step
  (snapshots during those steps show `free bufs 0/16`). In steps 4-7 the
  prints happened to fall in the 12 s pauses: luck, not a fix. Under
  constant traffic every print would lose frames (~50 ms x 148 840/s ≈ 7 400
  frames at line rate). That is bug 1.

**Fix for bug 1: non-blocking log output (`uart_log.[ch]`).** `printf` used
to end in `HAL_UART_Transmit()`, which waits ~87 us for every character. Now
`_write` (overriding the weak one in `syscalls.c`) only copies the text into
a 4 KB RAM ring and returns; the USART3 "transmit register empty" interrupt
sends one byte per interrupt in the background and switches itself off when
the ring is empty. Single producer (main loop) / single consumer (ISR), like
the frame rings. USART3 has priority 5, below ETH (0), so frames always come
first; enabling the TX interrupt masks only USART3, never ETH. If a write
does not fit, the whole write is dropped and counted (`log-drop` in the hw
line): losing log text is better than losing frames. USART3 belongs to the
Nucleo BSP (COM1), not to a CubeMX peripheral, so its NVIC setup is in
`uart_log_init()`.
- The run was not captured in the PuTTY log file (logging was off after
  the reflash); the numbers above are from the stats lines on screen.

### Stress run 3: both fixes, zero loss at line rate

Same frames, logged to a file (`putty_stress3.log`). Test A is the same
ramp; test B is sustained line rate (`sudo MAX_COUNT=4500000 sh stress.sh 0`,
4.5 million frames, ~31 s), so it must overlap ~6 stats prints.

| Test | Sent | MAC got | Passed | `fifo-overflow` | `dma-missed` | `rbu` / `refills` | `log-drop` |
|---|---|---|---|---|---|---|---|
| A: ramp 1k ... max | 564 000 | 564 000 | 564 000 | 0 | 0 | 19 / 4 | 0 |
| B: 31 s at max (totals A+B) | 5 064 000 | 5 064 000 | 5 064 000 | 0 | 0 | 66 / 28 | 0 |

- **No frame lost.** During test B every 5 s window held ~730 500 frames
  (~146 000 frames/s, the line rate) and every one passed, while the stats
  were printed every 5 s.
- **RBU is harmless now.** At line rate the DMA still runs out of
  descriptors for a moment (`rbu` 66), but the MAC's RX FIFO holds the next
  frames for those few microseconds and the main loop re-arms the DMA
  (`refills`), so nothing overflows. Before fix 1 the first RBU was fatal.
- **The filter's cost does not change under load:** min / avg 1819 / 1847
  cycles in every window, as at 10 frames/s. Only `max` grows, to
  3000-3600 cycles at line rate: frames whose measurement was interrupted by
  the next frame's ETH interrupt. That puts the RX interrupt itself at about
  1 500 cycles (~2.7 us, Debug build). Filter + interrupt ≈ 6 us per frame
  against 6.7 us between frames at line rate: the CPU is close to fully
  busy.
- **Margin:** at the moments the stats are printed during line-rate traffic
  only `free bufs 3/16` remain. Formatting the text (printf turning numbers
  into characters) still holds the main loop for roughly 60-90 us, and ~10
  frames queue up meanwhile. Safe, but 3 buffers from the edge.

**Summary of the stress tests**

| Run | Firmware | Result |
|---|---|---|
| 1 | before fixes | reception died for good after 892 frames at 1 000 frames/s |
| 2 | + DMA recovery (`eth_rx_refill`) | survives; 280 frames lost, all during blocking stats prints |
| 3 | + non-blocking log (`uart_log`) | 5 064 000 of 5 064 000 frames, 31 s at line rate, 0 lost |

**Still to measure:** an optimised (`-O2`) build, and heavier work per frame
(more rules) to find where the CPU, not the cable, becomes the limit.

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

Expected last line: `401 checks, 0 failed: PASS`.

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
   Press the blue USER button to turn the per-frame log off / on (yellow LED).

## Project layout

```
Core/Inc, Core/Src
  ring_buffer.[ch]       SPSC ring buffer
  ring_buffer_test.[ch]  on-target self-test
  eth_rx.[ch]            RX buffer pool, HAL ETH callbacks, rings glue, MAC checksum report
  pkt_flags.h            per-frame status bits from the MAC (PKT_FLAG_*)
  perf.[ch]              DWT cycle counter: cycles per frame, min / avg / max
  uart_log.[ch]          non-blocking printf: RAM ring + USART3 TX interrupt
  pkt_parse.[ch]         Ethernet / IPv4 / TCP / UDP header parser
  pkt_filter.[ch]        filter pipeline, rules, token buckets, counters
  filter_policy.[ch]     the rule table the board runs (BBB link)
  main.c                 init sequence, main loop, rule table and counters
tools/bbb/nic_test.py    Scapy traffic generator, run on the BBB
tools/bbb/stress.sh      pktgen rate ramp (stress test), run on the BBB
tools/la/pulse_width.py  logic analyzer capture of PERF_PIN, pulse widths
tests/                   host unit tests (parser, filter) + Makefile
.github/workflows/       CI: runs the host tests on every push
STM32H723ZGTX_FLASH.ld   linker script with D2 SRAM sections for the ETH DMA
STM32-SmartNIC.ioc       CubeMX configuration (clocks, ETH, MPU, NVIC)
```

## Known limitations

- Log output is limited to 115 200 baud (~11 500 characters/s). With the
  per-frame log ON at high rates the 4 KB log ring fills and whole log lines
  are dropped (counted as `log-drop`); frames are not affected.
- At line rate, formatting the stats (~60-90 us of printf) leaves only 3 of
  the 16 RX buffers free. More stats text, or more work per frame, would need
  a bigger pool or printing the stats in smaller pieces.
- Only 4 RX DMA descriptors (CubeMX default); to be tuned during stress testing.
- The parser handles untagged Ethernet + IPv4 only; VLAN-tagged frames and
  IPv6 are classified by EtherType but not parsed further.
- The filter is stateless (no connection tracking): ACK / FIN+ACK scans look
  like normal traffic, and a spoofed source that looks valid (inside the link
  subnet) cannot be told apart from a real one. ARP is not inspected (no
  ARP-spoofing detection).
- Rate limits are per rule, shared by all senders: a flood is capped, but it
  also takes the share of honest senders. Per-source buckets (a hash table
  keyed by source IP, plus the total cap) would make it fair.
- A rate-limited frame costs as much CPU as a passed one (measured, see
  Performance): the bucket is checked after the full pipeline, so a flood is
  capped but not cheap to filter.
- The BBB's `eth0` still runs a DHCP client (left from the Scapy install), so
  it sends a background frame now and then; it lands in `default` and can
  start an analyzer capture early.
- No device can stop a flood larger than its link: that has to be filtered
  upstream.
- Rules cannot say "not" (e.g. "source not in subnet"); ingress filtering is
  done by requiring the subnet in every allow rule.
- With the per-frame log on, `printf` at 115200 baud (~140 lines/s) limits how
  fast frames can be processed; turn it off with the USER button for
  throughput tests.
- Cycle numbers come from the Debug build (`-O0`, no optimisation); an
  optimised build will be faster.
