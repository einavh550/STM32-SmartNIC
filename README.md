# STM32-SmartNIC

[![ci](https://github.com/einavh550/STM32-SmartNIC/actions/workflows/ci.yml/badge.svg)](https://github.com/einavh550/STM32-SmartNIC/actions/workflows/ci.yml)

Bare-metal firmware that turns an STM32H723 into a simple SmartNIC: it receives
Ethernet frames through the MAC's DMA, hands them from the interrupt to the main
loop without copying, parses the Ethernet / IPv4 / TCP / UDP headers, runs
them through a first-match rule filter, and sends the UDP frames that passed
back to their sender from the same buffer (zero-copy RX → filter → TX).
A BeagleBone Black on the other end of the cable acts as the traffic generator.

## Results at a glance

Measured on the board at 550 MHz, 100 Mbit/s line rate with 60-byte frames
(~145 700 frames/s, one frame every ~3 775 CPU cycles), per-frame log off:

| Build / change | ISR + main = cycles per frame | CPU busy | Lost at line rate |
|---|---|---|---|
| `-O0`, ST HAL RX path | 3 656 | ~96 % | 0 |
| `-O2` | 1 660 | ~43 % | 0 |
| + lean RX descriptor driver (replaces `HAL_ETH_ReadData()`) | 429 + 901 = 1 330 | 35 % | 0 |
| + own ETH interrupt handler (one `DMACSR` read) | **357 + 902 = 1 259** | **33 %** | **0** |

With the TX path (Phase 6), every passed UDP frame is also sent back:

| Run, 1.5 M frames | ISR + main = cycles per frame | Reflected | Lost |
|---|---|---|---|
| RX only (reflect off), line rate | 357 + 930 = 1 287 | | 0 |
| RX + filter + zero-copy reflect, ~53 k frames/s (BBB limit) | 357 + 1 305 = **1 662** | **1 500 000**, counted on the BBB | **0** |

- **2.9x less CPU per frame** overall. The ISR went from 776 to 357 cycles
  at `-O2`. Filter cost per frame was cross-checked with a logic analyzer
  (GPIO pulse vs. DWT cycle counter).
- **~2 500 spare cycles per frame**: 1.5 M frames with +2 500 fake cycles
  per frame are still received with 0 loss. The HAL RX path lost 2.3 % there.
- **Tried and measured, not kept:** NAPI-style polling RX was 6 % slower at
  line rate and lost 6.8 % under overload on this MCU (a Cortex-M7 interrupt
  is cheap). Kept as a build option, with the numbers.
- **TX costs ~380 cycles per frame** (lean TX driver, main loop only, no TX
  interrupt). No checksum is recomputed: swapping source and destination
  does not change a one's-complement sum (proven in host tests). Reflect at
  full line rate would need ~44 % of the CPU; the BBB (one core, sending and
  receiving) could only drive ~53 k frames/s.
- **Bugs found and fixed:** an RX deadlock after buffer exhaustion
  ([docs/bug-rx-deadlock.md](docs/bug-rx-deadlock.md)), a main loop that
  never left its RX loop under overload (Phase 5, step 3c), RMII TX pins on
  the wrong GPIOs so nothing reached the cable although the DMA reported
  success ([docs/bug-tx-pins.md](docs/bug-tx-pins.md)), and a 4-descriptor
  TX ring that dropped bursts (Phase 6, step 3).
- Filter: malformed / spoofed / TCP-scan / bad-checksum frames dropped and
  counted, floods rate-limited. Host unit tests + firmware build in CI.

Details of every measurement are under [Performance](#performance) and
[Phase 6: TX path](#phase-6-tx-path).

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
| 4     | Traffic generation and stress tests from the BBB | Done: link up, Scapy generator, normal / spoof / scan / flood / malformed / bad-checksum scenarios verified, core at 550 MHz (PLL), per-frame log switch (USER button), DWT cycles per frame and per path, cross-checked with a GPIO pulse + logic analyzer, stress tested at 100 Mbit/s line rate with zero loss (after two fixes), whole cost per frame measured (ISR + main loop: ~3 650 of 3 700 cycles, ~250-500 cycles headroom), RX deadlock bug written up ([docs/bug-rx-deadlock.md](docs/bug-rx-deadlock.md)) |
| 5     | Profiling, throughput limits, hardening       | Done (summary in [Results at a glance](#results-at-a-glance)): `-O2` build done (whole cost 3 656 → 1 660 cycles per frame, CPU ~96 % → ~43 % busy at line rate, built in CI too); headroom at `-O2` ~2 000 spare cycles per frame (was ~250-500); NAPI-style polling RX measured and rejected (slower on this MCU, kept as a build option); lean RX driver instead of `HAL_ETH_ReadData()`: ISR 776 → 429 cycles, whole cost 1 683 → 1 330 cycles per frame (CPU 35 % busy at line rate), 0 loss at +2 500 extra cycles where the HAL lost 2.3 %; own ETH interrupt handler (reads `DMACSR` once): ISR 429 → 357, whole cost 1 259 cycles per frame (CPU 33 % busy); frame budget per main-loop pass (stats keep running under overload) |
| 6     | TX path: forward the frames that passed the filter | Done: lean TX driver (main loop only, no TX interrupt) sends a test frame every 5 s, received by the BBB; RMII TX pin bug found and fixed ([docs/bug-tx-pins.md](docs/bug-tx-pins.md)); zero-copy reflect: passed UDP frames go back to the sender from the same buffer, checksums not recomputed (host-tested), verified on the BBB; under load: 1.5 M frames reflected with 0 loss (counted on the BBB), TX ~380 cycles per frame, TX ring 4 → 16 descriptors fixed the burst drops |

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
- **Host unit tests:** 88 tests (432 checks) build `pkt_parse.c`, `pkt_reflect.c` and
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

### Stress test setup

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
- `free bufs` alone is a snapshot taken once per 5 s. The line also shows
  **low-water marks**: `low: period P, ever E, empty Z`, the fewest free
  buffers seen in this 5 s period and since boot, and how often the DMA asked
  for a buffer when none was left. They are updated in
  `HAL_ETH_RxAllocateCallback()`, the only place a buffer is taken. Note that
  an idle board shows `12/16`, not `16/16`: 4 buffers are always parked in
  the 4 RX DMA descriptors, waiting for the next frames. 12 is the real
  headroom for frames waiting on the main loop.

### Stress run 1: reception died for good at 1000 frames/s

Full bug write-up (symptom, root cause, fix, lessons):
[docs/bug-rx-deadlock.md](docs/bug-rx-deadlock.md).

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
  frames queue up meanwhile. This snapshot looked like a margin of 3
  buffers; edge test 1 below shows the real low point is 0.

### Edge test 1: how close does the pool get to empty?

`free bufs 3/16` above is a snapshot taken at print time. With the
low-water marks (`putty_edge.log`, `sudo MAX_COUNT=1500000 sh stress.sh 0`,
~10 s at line rate):

| 5 s window | Frames | Lost | Fewest free buffers in the window | Pool found empty (total) | `rbu` (total) |
|---|---|---|---|---|---|
| 1 | 639 581 | 0 | 3 | 0  | 0  |
| 2 | 730 368 | 0 | **0** | 32 | 9  |
| 3 (end) | 130 051 | 0 | **0** | 60 | 16 |

Total: 1 500 000 sent, 1 500 000 passed.

- **The pool does run empty at line rate:** 60 times in ~10 s the DMA asked
  for a buffer and none was left. The snapshot (`3/16`) hid this. The real
  margin of the 16-buffer pool at line rate is **zero**, not 3.
- **Still no frame was lost** because of a second, hardware buffer: the
  MAC's own RX FIFO (MTL queue) keeps receiving while the DMA waits, and
  `eth_rx_refill()` re-arms the DMA before that FIFO overflows
  (`fifo-overflow` stayed 0). So line rate works today on pool + FIFO
  together, with little to spare.
- **Growing the pool is limited by memory:** the pool must sit in D2 SRAM
  (the non-cacheable MPU region the ETH DMA uses), which is 32 KB; 16 x
  1536 B = 24.5 KB already, so ~20 buffers is the most that fits. More would
  need the pool in AXI SRAM (D1, 320 KB) with its own non-cacheable MPU
  region. The cheaper levers are shorter main-loop stalls (print the stats
  in pieces) and more RX descriptors.

**Summary of the stress tests**

| Run | Firmware | Result |
|---|---|---|
| 1 | before fixes | reception died for good after 892 frames at 1 000 frames/s |
| 2 | + DMA recovery (`eth_rx_refill`) | survives; 280 frames lost, all during blocking stats prints |
| 3 | + non-blocking log (`uart_log`) | 5 064 000 of 5 064 000 frames, 31 s at line rate, 0 lost |

### Edge test 2: CPU headroom, and the whole cost of one frame

At line rate (64 B frames, ~148 800 frames/s) a new frame arrives every
**~3 700 CPU cycles** (550 MHz / 148 800). The filter alone takes ~1 850, so
on paper half the CPU looks free. Two experiments check that
(`putty_headroom.log`, `sudo MAX_COUNT=1500000 sh stress.sh 0`, log OFF).

**1. Headroom: add fake work until frames are lost.** `EXTRA_CYCLES` in
`main.c` makes the main loop spin that many extra cycles per frame (on the
DWT counter, after the filter is measured, before the buffer is freed):

| `EXTRA_CYCLES` | Sent | Lost | Pool found empty |
|---|---|---|---|
| 0    | 1 500 000 | **0** | 60 |
| 250  | 1 500 000 | **0** | 152 909 |
| 500  | 1 500 000 | 7 873 (0.5 %) | 172 746 |
| 1000 | 1 500 000 | 31 949 (2.1 %) | 71 391 |

Only **~250-500 cycles per frame are free**, not ~1 850. With extra work the
first seconds are clean; the loss starts after a stats print stalls the main
loop: with no spare cycles the backlog from that pause is never cleared.

**2. Whole cost per frame.** Why so little room? The filter is only part of
the work for one frame. The firmware now also times the ETH interrupt
(`ETH_IRQHandler`, HAL driver + our callbacks) and the whole main-loop RX
work (pop, filter, free, refill), with the interrupt time that cut into the
main loop taken out, and prints every 5 s:

```
--- whole cost/frame (470548 frames): isr 1222 + main 2434 = 3656 cycles | cpu busy on rx 62% ---
```

| Part | Cycles per frame |
|---|---|
| ETH interrupt (HAL RX path, descriptor + checksum flags, ring push) | 1 222 |
| Filter (`pkt_filter_process`) | 1 858 |
| Rest of the main loop (pop, free, refill, measurement) | ~576 |
| **Total** | **3 656** of a ~3 700 budget |

- The cost per frame is the same at every rate; only the busy share changes:
  3 656 x 93 000 frames/s = 62 % (this run), 3 656 x 146 000 = ~97 % (an
  earlier run at full line rate printed 96 %).
- So at 100 Mbit/s line rate the CPU is **~96 % busy** at `-O0`: the driver
  around the filter costs about as much as the filter itself. That matches
  the headroom test.
- A lone frame after a quiet period costs much more (~14 000 cycles in the
  main loop): caches and branch predictors are cold.
- Two measurement pitfalls fixed on the way: the cycle counter and the ISR
  total are read as one consistent pair (`time_snapshot()` re-reads if the
  ISR fired in between; otherwise the difference could go negative and wrap
  to ~4 billion), and only loop passes that handled frames are counted (an
  empty pass is the CPU waiting, not frame work).

**What it means for a faster link:** 1 Gbit/s line rate is 1 488 000 frames/s
= **~370 cycles per frame** at 550 MHz, ten times less than this board needs
today. That is why real NICs do this work in hardware (or many cores) and
keep the per-packet software path to a few hundred cycles.

### Phase 5, step 1: optimised build (`-O2`)

Same firmware and same stress test (`sudo MAX_COUNT=1500000 sh stress.sh 0`,
60-byte UDP frames at ~145 000 frames/s), built with `-O2` instead of `-O0`
(`make -f firmware.mk OPT=-O2`). Log: `putty_o2.log`.

| | `-O0` (Debug) | `-O2` | Speed-up |
|---|---|---|---|
| Frames sent / seen by the MAC / seen by the filter | 1.5 M / 1.5 M / 1.5 M | 1.5 M / 1.5 M / 1.5 M | 0 lost in both |
| Filter, cycles per frame (avg) | 1 858 (3.37 µs) | **630 (1.15 µs)** | 2.9x |
| ETH ISR, cycles per frame | 1 222 | **769** | 1.6x |
| Main loop RX work, cycles per frame | 2 434 | **891** | 2.7x |
| **Whole cost per frame** | 3 656 | **1 660** | **2.2x** |
| CPU busy on RX at line rate | ~96 % | **~43 %** | more than half the CPU now free |

- The filter (our own code) gains the most: at `-O0` every variable lives
  in memory; at `-O2` it stays in registers and small functions are inlined.
- The ISR gains the least, so it is now the **largest single part** of the
  cost (769 of 1 660 cycles). Most of it is the ST HAL driver (descriptor
  walk, callbacks), so the next step is fewer interrupts per frame
  (NAPI-style polling: mask the RX interrupt while the main loop drains).
- The buffer pool still runs empty for moments (`rbu` +4, failed
  allocations +12 in 1.5 M frames) and no frame is lost. Even with half the
  CPU free the pool empties, so the stats print stall (not the per-frame
  cost) is what drains it.
- The first try of this run was invalid: the per-frame log was still on
  after flashing (it starts on). Every frame then tried to `printf`
  (41 M log writes dropped, ~10 000 cycles per frame in the main loop) and
  ~65 % of frames were lost in the MAC FIFO. Turn the log off with the USER
  button before any throughput test.

### Phase 5, step 1b: CPU headroom at `-O2`

Edge test 2 again, now on the `-O2` build: fake work per frame
(`EXTRA_CYCLES`) is raised until frames are lost. Each value is its own
build, set from the command line, so `main.c` is never edited for a test:

```
make -f firmware.mk OPT=-O2 EXTRA=2000   # -> build/fw-O2-x2000/STM32-SmartNIC.elf
```

Same stress (`sudo MAX_COUNT=1500000 sh stress.sh 0`, ~145 700 frames/s),
log OFF, one PuTTY log per value (`putty_headroom_o2_x<N>.log`). At line
rate a frame arrives every **~3 775 cycles** (550 MHz / 145 700).

| `EXTRA_CYCLES` | Whole cost per frame | CPU busy | Pool found empty | Lost |
|---|---|---|---|---|
| 0    | 1 660 | 43 % | 12 | **0** |
| 1000 | 2 676 | 70 % | 26 | **0** (2 runs, identical) |
| 1500 | 3 167 | 83 % | 33 | **0** |
| 2000 | 3 675 | 97 % | 16 576 | **0** |
| 2500 | 3 868 | 99 % | 413 641 | 33 879 (2.3 %) |

- **~2 000 cycles per frame are free at `-O2`**, against ~250-500 at `-O0`:
  4-8x more room for real per-packet work (more rules, a TX path).
- At +2000 the board survives on the edge: the pool is empty 16 576 times
  and the MAC RX FIFO holds frames until a buffer is freed.
- Over the limit it degrades gracefully, it does not die: ~142 000
  frames/s still pass at 99 % busy, the MAC FIFO drops only the rest, and
  every RX stall is recovered (`rbu` 82 728 = refills 82 728).
- **Under overload the ISR got cheaper: 771 → 548 cycles per frame.** The
  main loop is always behind, so each interrupt finds several frames and
  pays its entry/exit cost once for all of them. Polling RX (next step)
  does this batching on purpose, not only under overload.
- Pitfall: CubeIDE's Debug button rebuilds and flashes its own `-O0`
  `Debug/` build, not these files. Flash them with
  `STM32_Programmer_CLI ... -w build/fw-O2-x<N>/STM32-SmartNIC.elf`, and
  check the boot line `Headroom test: +N` before trusting a run.

### Phase 5, step 2: NAPI-style polling RX (measured, not kept)

**Idea (from Linux NAPI):** the first RX interrupt switches itself off (RIE
in the DMA interrupt-enable register) and only wakes the main loop. Main
reads the finished frames itself (`eth_rx_poll()`, up to 8 per pass) and
switches the interrupt back on only when the DMA has nothing left. Under
load, one interrupt should then pay for many frames. Re-enabling has a race
(a frame finishing just before RI is cleared would never be announced), so
`eth_rx_poll()` clears RI, looks once more, and only then enables RIE.

Build switch: `ETH_RX_NAPI` in `eth_rx.h` (default 0 = interrupt mode),
`make -f firmware.mk OPT=-O2 NAPI=1` → `build/fw-O2-napi/`. The stats show
`rx irqs N | frames per irq M` and the boot line says `RX mode: ...`.

All runs `-O2`, log OFF, ~145 700 frames/s (a frame every ~3 775 cycles):

| Run (log) | Mode | Frames per IRQ | ISR + main = cycles/frame | CPU busy | Lost |
|---|---|---|---|---|---|
| Line rate, 2 064 000 frames (`putty_napi_irq.log`) | interrupt | 1 | 776 + 907 = **1 683** | 44 % | 0 |
| Line rate, 2 064 000 frames (`putty_napi.log`) | NAPI | 1 | 142 + 1 641 = **1 783** | 47 % | 0 |
| Overload +2 500, 1.5 M frames (`putty_headroom_o2_x2500.log`) | interrupt | ~1 | 548 + 3 320 = **3 868** | 99 % | 33 879 (2.3 %) |
| Overload +2 500, 1.5 M frames (`putty_napi_x2500.log`) | NAPI | **16 831** | 130 + 3 910 = **4 040** | 99 % | 102 052 (**6.8 %**) |

- **At line rate NAPI cannot batch.** A frame costs ~1 700 cycles but
  arrives only every ~3 775, so main is always done before the next one:
  still one interrupt per frame, plus the cost of switching RIE off and on.
  Result: 6 % slower.
- **Under overload the batching works** (30 interrupts for 505 000 frames,
  ISR 548 → 130 cycles per frame), **but the total got worse.** The work of
  `HAL_ETH_ReadData()` did not disappear, it moved into the main loop.
- **Why worse: the DMA starves.** There are only 4 RX descriptors. In
  interrupt mode the ISR preempts main and re-arms a descriptor right away.
  With NAPI they are re-armed only when main polls, and 8 frames of work
  (~31 000 cycles here) use up 4 descriptors long before that:
  `rbu` 1 397 803, i.e. the DMA stopped for almost every frame and frames
  waited in the small MAC FIFO until it overflowed.
- **The loss is just arithmetic:** lost ≈ 1 − 3 775 / cost per frame.
  Interrupt mode: 1 − 3 775 / 3 868 = 2.4 % (measured 2.3 %). NAPI:
  1 − 3 775 / 4 040 = 6.6 % (measured 6.8 %). Every cycle per frame counts.
- **Lesson:** NAPI pays off in Linux, where an interrupt is expensive
  (context switch, cache damage). On a Cortex-M7 the interrupt entry is a
  few dozen cycles; the real cost is the HAL driver code, and NAPI only moves
  it. Measured before keeping it, so interrupt mode stays the default.
- **What would help instead:** a leaner RX path than the HAL's
  `HAL_ETH_ReadData()` (step 3). More RX descriptors were considered and
  dropped: in interrupt mode the ISR re-arms a descriptor at once, a
  descriptor only holds one of the same 16 pool buffers (no extra room for
  waiting frames), and sustained overload loss is set by the cost per frame,
  not by queue depth.

### Phase 5, step 3: lean RX driver

**Why:** at `-O2` the ETH ISR was the largest single cost (776 of 1 683
cycles per frame) and most of it was `HAL_ETH_ReadData()`. The HAL handles
every case (frames split over several descriptors, timestamps, polling
mode, a callback per step) and reads the same descriptor word ~6 times per
frame; our checksum code then searched the 4 descriptors for the buffer.
Every one of those reads goes to D2 SRAM, which is non-cacheable (MPU
region 1), so each is a slow bus access. Our case is simpler: one 1536-byte
buffer always holds a whole frame, and timestamps are off.

**What (`eth_rx.c`, `ETH_RX_LEAN`, default 1):**
- `rx_harvest()`: per frame read `DESC3` once (OWN, first + last, length)
  and `DESC1` once (the checksum report), push buffer + length + flags into
  `pkt_ring`, move to the next descriptor.
- `rx_arm()`: give each empty descriptor a pool buffer (`DESC0`), `__DMB()`,
  then `DESC3` = OWN | BUF1V | IOC (the DMA must see the address before the
  OWN bit), and move the tail pointer once, which also wakes a DMA stopped
  by RBU.
- `rx_desc_buf[]`: which buffer each descriptor holds, in normal cached RAM
  instead of `BackupAddr0` in D2.
- `eth_rx_start()`: the HAL still starts the MAC and DMA
  (`HAL_ETH_Start_IT()`, ETH IRQ masked meanwhile), then the driver copies
  the HAL's ring state and the HAL never touches RX again. The ISR, NAPI
  poll and the RBU refill all use `rx_harvest()`.
- `make -f firmware.mk OPT=-O2 LEAN=0` builds the HAL path
  (`build/fw-O2-hal/`) for comparison; the boot line says which driver runs.

**Correctness** (`putty_lean.log`, per-frame log on): `malformed --count 1`
gives malformed +9, bad-checksum +2, passed +1, the same as with the HAL, so
the checksum report is still read correctly.

**Speed**, `-O2`, log OFF, ~145 700 frames/s (a frame every ~3 775 cycles):

| Run (log) | Driver | ISR + main = cycles/frame | CPU busy | Lost |
|---|---|---|---|---|
| Line rate, 2 064 000 frames (`putty_napi_irq.log`) | HAL | 776 + 907 = **1 683** | 44 % | 0 |
| Line rate, 1 500 000 frames (`putty_lean_speed.log`) | lean | 429 + 901 = **1 330** | 35 % | 0 |
| +2 500 extra, 1.5 M frames (`putty_headroom_o2_x2500.log`) | HAL | 548 + 3 320 = 3 868 | 99 % | 33 879 (2.3 %) |
| +2 500 extra, 1.5 M frames (`putty_lean_x2500.log`) | lean | 425-520 + 3 251-3 346 = **3 771** | | **0** |

- **The ISR got 45 % cheaper (776 → 429 cycles), the whole frame 21 %.**
  The main loop (901 vs 907) and the filter (~634) did not change, so the
  saving is the driver alone.
- **Overload: from 2.3 % lost to 0.** The total cost at +2 500 (3 771)
  now sits just under the ~3 775-cycle gap between frames. It is right on
  the edge: the pool was found empty 570 313 times and the DMA stopped
  (`rbu` 570 310), but the ISR re-armed it at once each time (main-loop
  refills only 8) and the MAC RX FIFO held the waiting frames: no overflow.
- My prediction was ~1.4 % loss (1 330 + 2 500 = 3 830 cycles). It came out
  lower because `EXTRA_CYCLES` spins on the cycle counter (wall time):
  an ISR that interrupts the spin is hidden inside it instead of adding to
  it (main 3 346, not 901 + 2 500). The HAL run had the same effect, so the
  comparison stays fair.
- Total so far: whole cost per frame **3 656 (`-O0`, HAL) → 1 660 (`-O2`)
  → 1 330 (`-O2` + lean driver)**.
- What is left in the 429-cycle ISR: interrupt entry/exit, the timing
  around it, and the HAL's `HAL_ETH_IRQHandler()` dispatcher, which reads 4
  peripheral registers (MAC, DMA, EXTI) per interrupt before calling us.
  Next candidate: our own dispatch (read `DMACSR` once), step 3b.

### Phase 5, step 3b: own ETH interrupt handler

**Why:** `HAL_ETH_IRQHandler()` reads 4 peripheral registers (`MACISR`,
`DMACSR`, `DMACIER`, `EXTI PR3`) on every interrupt before it calls our RX
code, and each one is a slow bus read. In our setup only DMA events are
enabled and the enable mask never changes (interrupt mode), so the DMA
status register alone says what happened.

**What (`eth_rx_irq_handler()` in `eth_rx.c`, `ETH_RX_OWN_IRQ`, default 1
with the lean driver):**
- read `DMACSR` once, then write back exactly the bits that were set
  (write 1 to clear). A bit the DMA sets after the read stays set and
  raises a new interrupt, so nothing is lost. Clearing first also gives a
  frame that finishes during the harvest its own interrupt.
- `RI` (frame received): `rx_harvest()`. `RBU` (no buffer): counted, as
  before. `FBE` (fatal bus error): ETH interrupts off and driver state set
  to error, the same as the HAL does.
- Safety net: an interrupt with neither summary bit (`NIS` / `AIS`) set is
  not a DMA event (MAC, wake-up; none is enabled today), so it goes to
  `HAL_ETH_IRQHandler()`, which finds and clears its source.
- Called from the `USER CODE` block of `ETH_IRQHandler()`
  (`stm32h7xx_it.c`), so CubeMX regeneration keeps it.
- Interrupt mode only (`#error` with NAPI, which switches `RIE` on and off).
  `make -f firmware.mk OPT=-O2 OWNIRQ=0` builds the lean driver with the
  HAL handler (`build/fw-O2-halirq/`). The boot line says which one runs.

**Correctness** (`putty_irq3b.log`, per-frame log on): `malformed --count 1`
gives malformed +9, bad-checksum +2, passed +1, with the same `[hw: ...]`
tags as before.

**Speed**, `-O2`, log OFF, ~145 700 frames/s:

| Run (log) | IRQ handler | ISR + main = cycles/frame | CPU busy | Lost |
|---|---|---|---|---|
| Line rate, 1.5 M frames (`putty_lean_speed.log`) | HAL | 429 + 901 = 1 330 | 35 % | 0 |
| Line rate, 1.5 M frames (`putty_irq3b.log`) | own | **357** + 902 = **1 259** | 33 % | 0 |
| +2 500 extra, 1.5 M frames (`putty_lean_x2500.log`) | HAL | 425-520 + 3 251-3 346 = 3 771 | | 0 |
| +2 500 extra, 1.5 M frames (`putty_irq3b_x2500.log`) | own | 353-400 + 3 373-3 391 = 3 744-3 773 | | **0** |

- **The ISR got 72 cycles (17 %) cheaper (429 → 357)**: the 3 skipped
  register reads plus the HAL's call chain. The main loop did not change
  (902), so the saving is the handler alone.
- **Total so far: whole cost per frame 3 656 (`-O0`, HAL) → 1 660 (`-O2`)
  → 1 330 (lean driver) → 1 259 (own IRQ handler)**, i.e. ISR 776 → 357
  over steps 3 and 3b.
- Overload: still 0 lost, on the edge as before (pool empty 1 454 479 times,
  `rbu` 300 674, main-loop refills 12, no FIFO overflow). The ISR costs a
  bit more there (400) because of the extra RBU interrupts.
- **Measurement finding:** in the overload run the main loop never left its
  RX loop for the whole ~10 s burst, because a frame was always waiting. So
  (1) the 5 s stats print was skipped until the burst ended, and (2) the
  32-bit cycle delta of that one main-loop pass wrapped (2^32 cycles =
  7.8 s): the raw line said `main 420`. Corrected: 420 + 2^32 / 1 454 589
  frames = 3 373. Same root cause for both: the RX loop had no per-pass
  limit, fixed in step 3c.

### Phase 5, step 3c: frame budget per main-loop pass

**Fix (`main.c`, `MAIN_RX_BUDGET` = 16, the whole pool):** one main-loop
pass handles at most 16 frames, then does its other work (refill, button,
MAC drop counters, stats) and starts a new pass. The budget is checked
before `eth_rx_pop()`, so no frame is popped and then skipped. Frames left
over wait in `pkt_ring`. At line rate a pass sees ~1 frame, so only
overload is affected.

**Test:** same overload as step 3b (`putty_budget_x2500.log`, +2 500 extra
cycles, 1.5 M frames, log OFF):

| | Step 3b (no budget) | Step 3c (budget 16) |
|---|---|---|
| Stats lines during the ~10 s burst | 1, after the burst | 3, on time (609 k / 729 k / 162 k frames) |
| main cycles/frame (raw line) | 420 (wrapped) | 3 383-3 389 (real) |
| Whole cost/frame | 3 744-3 773 | 3 743-3 763 |
| Lost / FIFO overflow | 0 / 0 | 0 / 0 |
| Pool found empty / `rbu` / main-loop refills | 1 454 479 / 300 674 / 12 | 309 864 / 90 495 / 18 262 |

- The stats print and the button now run during overload, and the cost
  numbers are real (no wrap). The extra work every 16 frames costs nothing
  measurable (whole cost unchanged).
- Bonus: main now re-arms descriptors every 16 frames (refills 12 →
  18 262), so the DMA stopped for lack of a buffer 3x less often (`rbu`
  300 674 → 90 495).

## Phase 6: TX path

### Step 1: lean TX driver and a test frame

**Design (`eth_tx.[ch]`):**
- Main loop only: `eth_tx_send()` fills a TX descriptor (buffer address,
  length, `__DMB()`, then OWN | first | last | CRC + pad insertion) and moves
  the tail pointer `DMACTDTPR`, which also wakes a suspended TX DMA.
  `eth_tx_reclaim()` runs every main-loop pass, reads `DESC3` once per
  descriptor and collects the ones the DMA has finished (OWN cleared, `ES`
  = error). One context, so no locks and no TX interrupt (no IOC bit).
  Linux NIC drivers clean their TX ring the same way, from the poll loop.
- Zero-copy ready: a sent buffer that belongs to the RX pool goes back to
  the pool on reclaim (`eth_rx_buf_is_pool()`), for step 2.
- Ring full: `eth_tx_send()` returns false at once and counts `busy`. It
  never waits, so TX can never hold up RX.
- The HAL still initialises the TX ring and starts the TX DMA
  (`HAL_ETH_Start_IT()`); its TX functions are never called.
- Test frame every stats period (5 s): UDP broadcast 192.168.10.1:5000 →
  192.168.10.255:5001, payload `STM32-SmartNIC TX test #N`, IPv4 header
  checksum in software, UDP checksum 0. Its buffer sits in D2 SRAM next to
  the RX pool (DMA-reachable, non-cacheable), not in cached D1 SRAM.
- New stats line: `--- tx: sent N done N | busy 0 errors 0 | in flight 0 ---`.

**Test:** a UDP socket on the BBB (`tcpdump` is not installed there):

```
python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("", 5001))
while True: print(*s.recvfrom(2048))'
```

- First run (`putty_tx1.log`): board `sent 37 done 37 errors 0`, BBB
  nothing, and its `ip -s link` showed **RX packets 0** since boot. Cause:
  two RMII TX pins on the wrong GPIOs. Full story in
  [docs/bug-tx-pins.md](docs/bug-tx-pins.md).
- After the pin fix (`putty_tx1b.log`): the BBB printed
  `b'STM32-SmartNIC TX test #3' ('192.168.10.1', 5000)` through `#13`, one
  every 5 s, none missing; BBB `RX packets` 0 → 21; board `sent 19 done 19
  busy 0 errors 0`. Linux only hands a frame to the socket if the Ethernet,
  IPv4 and UDP headers are valid, so this also checks the frame format.

### Step 2: zero-copy reflect of passed frames

**What:** a UDP frame that passed the filter goes back to its sender. The
board answers like an end host ("reflector"), which is the natural
forwarding test with one Ethernet port.
- `pkt_reflect_udp()` (`pkt_reflect.[ch]`, pure C, host-tested): in place,
  destination MAC = old source, source MAC = board, swap the IPv4 source and
  destination, swap the UDP ports. **No checksum is recomputed:** the IPv4
  and UDP checksums are one's-complement sums of 16-bit words, and swapping
  two words (or two addresses in the pseudo-header) does not change a sum.
  The MAC adds the Ethernet CRC.
- Reflected: IPv4 UDP sent to the board's own IP, not a fragment. Not
  reflected: TCP and ICMP (the sender's stack would answer again: RST, echo
  reply), broadcast / multicast / other hosts, fragments. Those frames are
  consumed as before.
- **Zero-copy:** the main loop gives the same RX buffer to `eth_tx_send()`
  and does not free it. `eth_tx_reclaim()` (now inside the timed window,
  so TX work counts in the cost per frame) returns it to the pool once sent.
  TX ring full: the frame is dropped and freed (`busy`).
- `main.c TX_REFLECT` (default 1); `make ... REFLECT=0` builds the RX-only
  behaviour (`build/fw-O2-noreflect/`). Stats line: `--- tx: reflected N |
  sent N done N | busy 0 errors 0 | in flight 0 ---`.
- Host tests (`tests/test_pkt_reflect.c`, 6 tests): addresses and ports
  swapped, payload untouched, **both checksums still valid without being
  recomputed**, and TCP / broadcast / other host / fragment / unparsed
  frames left byte-for-byte untouched.

**Test** (`putty_tx2.log`, UDP listener on the BBB's port 40000, the source
port `nic_test.py` uses):

| Scenario | BBB got back | Board filter |
|---|---|---|
| `normal --count 5` | 5 x `b'smartnic' ('192.168.10.1', 5000)` | passed +5 |
| `malformed --count 1` (12 frames) | 1 x `b'malformed'`: only the honest control frame | malformed +9, bad-checksum +2, passed +1 |
| `spoof --count 1` (7 frames) | nothing | spoofed +6, default +1 |

- `reflected 6` = passed 6: every passed frame came back, no dropped one did.
- The BBB's IP stack accepted every reflected frame, so the swapped headers
  and the untouched checksums are valid on a real stack, not only in the
  host test.
- No buffer leak: `free bufs 12/16` after the test, as before it. TX `sent
  26 done 26` (6 reflected + 20 test frames), `busy 0 errors 0`.

### Step 3: reflect under load (1.5 M frames)

pktgen sends 1.5 M frames to port 5000 (`stress.sh 0`); every one passes
and is reflected to the BBB's port 40000. Counted on both ends: the board's
`reflected` / `busy`, and on the BBB `RX packets` (`ip -s link`) and `Udp
NoPorts` (reflected datagrams that reached the UDP layer and found no
socket on port 40000: each one is a complete, valid frame).

| Run (log) | TX descriptors | pktgen rate | Reflected | `busy` | BBB got back | Cost/frame (ISR + main) |
|---|---|---|---|---|---|---|
| A (`putty_tx3.log`) | 4 | ~33 k/s | 1 499 853 | 147 | `NoPorts` +1 499 853 | 355 + 1 309 = 1 664 |
| B (`putty_tx3_noreflect.log`), reflect OFF | 4 | ~146 k/s (line rate) | 0 | 0 | | 357 + 930 = **1 287** |
| C (`putty_tx4.log`) | **16** | ~33 k/s | **1 500 000** | **0** | `NoPorts` **+1 500 000** | 357 + 1 320 = 1 677 |
| D (`putty_tx5.log`), BBB drops early | 16 | ~53 k/s | **1 500 000** | **0** | `RX packets` +1 500 045 | 357 + 1 305 = 1 662 |

All runs: 0 FIFO overflow, 0 TX errors, pool back to `12/16` at the end.

- **Zero loss end to end:** 1.5 M in, 1.5 M reflected, 1.5 M counted by the
  BBB's UDP layer (run C). The BBB answered some datagrams with ICMP port
  unreachable (rate-limited, 51 in 45 s): they passed the `ping` rule and
  were not reflected (ICMP), as designed.
- **TX costs ~380 cycles per frame** (1 664 - 1 287, ~0.7 us): the reflect
  swaps, 4 descriptor words written to D2, two `__DMB()`, the tail-pointer
  register write, and the reclaim read. The ISR is unchanged (357), so it
  is all main-loop work. The cost does not depend on the rate (1 662-1 677
  at 33 k and 53 k frames/s).
- **Bug found: 4 TX descriptors were too few.** After each stats print the
  main loop finds a backlog (up to 12 frames, the pool minus the 4 buffers
  parked in RX descriptors) and sends it faster (~2.4 us per frame) than
  the wire carries it (6.7 us per 60-byte frame). A TX descriptor stays
  busy until the wire has sent its frame, so the TX ring IS the TX queue;
  RX descriptors are re-armed by the ISR at once, which is why 4 are enough
  there. Fix: `ETH_TX_DESC_CNT` 4 → 16 (`stm32h7xx_hal_conf.h`, 384 B of
  D2), with a `_Static_assert` in `eth_tx.c` so a CubeMX regeneration
  cannot silently restore 4. Result: `busy` 147 → 0, same cost.
- The backlog now waits in the TX ring instead of being dropped, so its
  buffers are out of the pool longer: pool found empty 26 → 256 times, RX
  DMA stopped (`rbu`) 25 → 34 times, all covered by the MAC RX FIFO (0
  overflow).
- **Not line rate, and the limit is the BBB:** its single CPU core sends
  with pktgen and receives every reflected frame. Dropping the reflected
  frames early (`iptables -t raw -A PREROUTING -p udp --dport 40000 -j
  DROP`) raised the rate from ~33 k to ~53 k frames/s; the board was 15 %
  busy. From the measured cost, reflect at full line rate (~145 700
  frames/s, a frame every ~3 775 cycles) would need ~44 % of the CPU.

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
- The board does not answer ARP (its TX path only reflects UDP, Phase 6).
  The static neighbor entry gives the BBB the board's MAC up front; Scapy
  scenarios send at layer 2 (`sendp`) and set the MAC themselves.

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
make tsan       # ring buffer, 2 threads, ThreadSanitizer (Linux/macOS)
```

Expected last line: `432 checks, 0 failed: PASS`.

`make tsan` runs the SPSC ring buffer with a real producer thread and a real
consumer thread (on the board: ETH ISR and main loop) for 2 000 000
descriptors and checks each one arrives once, in order, intact:
`ring buffer 2-thread test: 2000000 frames, ... 0 errors -> PASS`.
ThreadSanitizer also checks that every shared access is synchronised. To
show it is not a toothless test: with the `release`/`acquire` on `head`
changed to `relaxed`, it fails with `data race ... rb_push (ring_buffer.c:43)`
vs `rb_pop (ring_buffer.c:66)`, the slot write and the slot read that the
ordering protects. On a kernel with high address randomisation TSan stops
with `unexpected memory mapping`; run it as
`setarch $(uname -m) -R make tsan` (CI lowers `vm.mmap_rnd_bits` instead).

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

### Command-line build (used by CI)

`firmware.mk` builds the same `.elf` without the IDE, with the CubeIDE
`Debug` compiler flags plus `-Werror`. CubeIDE's own generated makefile lives
in `Debug/`, which is not in git, so CI uses this one. Both builds give
identical section sizes.

```
make -f firmware.mk            # -> build/fw/STM32-SmartNIC.elf (-O0; Windows: mingw32-make)
make -f firmware.mk OPT=-O2    # -> build/fw-O2/STM32-SmartNIC.elf (optimised)
make -f firmware.mk OPT=-O2 EXTRA=1000   # headroom test build -> build/fw-O2-x1000/
make -f firmware.mk OPT=-O2 NAPI=1       # NAPI-style polling RX -> build/fw-O2-napi/
make -f firmware.mk OPT=-O2 LEAN=0       # ST HAL RX path instead of the lean driver -> build/fw-O2-hal/
make -f firmware.mk OPT=-O2 OWNIRQ=0     # lean driver + HAL_ETH_IRQHandler -> build/fw-O2-halirq/
make -f firmware.mk OPT=-O2 REFLECT=0    # no TX reflect (RX only) -> build/fw-O2-noreflect/
```

Each optimisation level gets its own build folder, so object files from the
two builds never mix.

Needs `arm-none-eabi-gcc` in `PATH` (Ubuntu: `apt install gcc-arm-none-eabi
libnewlib-arm-none-eabi`; or the one inside STM32CubeIDE's
`plugins/*gnu-tools-for-stm32*/tools/bin`).

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request, one job per
check:

| Job | What it checks |
|---|---|
| Host unit tests | parser, filter and policy tests built with AddressSanitizer + UBSan |
| Ring buffer, 2 threads | producer and consumer threads push/pop 2 000 000 descriptors under ThreadSanitizer: no lost, duplicated or torn descriptor, no data race |
| Tools syntax | every Python script under `tools/` compiles (`py_compile`) and every shell script parses (`sh -n`), so a typo is caught before it reaches the BBB |
| Firmware build | the full firmware compiles for the Cortex-M7 with no warnings (`-Werror`), both at `-O0` and at `-O2` (`-O2` analyses more and can warn where `-O0` is silent); both `.elf` and `.map` files are kept as a download |

## Project layout

```
Core/Inc, Core/Src
  ring_buffer.[ch]       SPSC ring buffer
  ring_buffer_test.[ch]  on-target self-test
  eth_rx.[ch]            RX buffer pool, lean RX descriptor driver + own ETH IRQ handler (HAL paths kept), rings glue, MAC checksum report
  eth_tx.[ch]            lean TX descriptor driver (main loop only), test frame
  pkt_reflect.[ch]       in-place UDP reply (swap MAC / IP / ports), no checksum recompute
  pkt_flags.h            per-frame status bits from the MAC (PKT_FLAG_*)
  perf.[ch]              DWT cycle counter: cycles per frame, min / avg / max, ETH ISR total
  uart_log.[ch]          non-blocking printf: RAM ring + USART3 TX interrupt
  pkt_parse.[ch]         Ethernet / IPv4 / TCP / UDP header parser
  pkt_filter.[ch]        filter pipeline, rules, token buckets, counters
  filter_policy.[ch]     the rule table the board runs (BBB link)
  main.c                 init sequence, main loop, rule table and counters
tools/bbb/nic_test.py    Scapy traffic generator, run on the BBB
tools/bbb/stress.sh      pktgen rate ramp (stress test), run on the BBB
tools/la/pulse_width.py  logic analyzer capture of PERF_PIN, pulse widths
tests/                   host unit tests (parser, filter, reflect), 2-thread ring buffer test (TSan) + Makefile
docs/bug-rx-deadlock.md  bug write-up: RX deadlock after buffer exhaustion
docs/bug-tx-pins.md      bug write-up: TX "sent" but nothing on the wire (RMII pins)
.github/workflows/ci.yml CI: host tests + firmware build on every push
firmware.mk              command-line firmware build (same flags as CubeIDE)
STM32H723ZGTX_FLASH.ld   linker script with D2 SRAM sections for the ETH DMA
STM32-SmartNIC.ioc       CubeMX configuration (clocks, ETH, MPU, NVIC)
```

## Known limitations

- Log output is limited to 115 200 baud (~11 500 characters/s). With the
  per-frame log ON at high rates the 4 KB log ring fills and whole log lines
  are dropped (counted as `log-drop`); frames are not affected.
- At line rate the 16-buffer pool runs empty for moments (low-water mark 0,
  edge test 1); no frame is lost only because the MAC's RX FIFO covers the
  gap. More stats text, or more work per frame, would need a bigger pool
  (limited by the 32 KB D2 SRAM) or printing the stats in smaller pieces.
- At line rate the CPU is ~96 % busy in the `-O0` build (only ~250-500
  spare cycles per frame, edge test 2), ~43 % in the `-O2` build and ~33 %
  with the lean RX driver and our own ETH interrupt handler.
- Our ETH interrupt handler assumes only DMA interrupts are enabled; any
  other source is passed to `HAL_ETH_IRQHandler()`.
- Only 4 RX DMA descriptors (CubeMX default; `ETH_RX_DESC_CNT` sits in a
  CubeMX-generated part of `stm32h7xx_hal_conf.h`). Enough in interrupt
  mode, too few for NAPI-style polling (the DMA stops while main is busy).
  TX has 16 (one per pool buffer, Phase 6 step 3).
- Reflect was measured up to ~53 k frames/s only: the BBB (one CPU core)
  cannot send at line rate and receive the reflected frames at the same
  time. Line rate in both directions would need a second traffic source or
  a faster receiver.
- The lean RX driver assumes one buffer per frame (1536-byte buffers) and
  no timestamps. A descriptor that breaks this is passed on with length 0
  and counted as malformed instead of being reassembled.
- NAPI-style polling RX is in the code but off by default: it measured
  slower on this MCU (Phase 5, step 2).
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
- Most cycle numbers in Performance come from the Debug build (`-O0`, no
  optimisation); the `-O2` section shows the optimised numbers
  (about 2-3x faster).
