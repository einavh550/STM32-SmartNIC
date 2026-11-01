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
| 3     | Header parsing and rule filter (EtherType / IP / port) | In progress: verified on hardware, host unit tests in CI |
| 4     | Traffic generation and stress tests from the BBB | Planned  |
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
- `pkt_hdr_t.valid` records which layers were parsed (`PKT_HAS_ETH/IPV4/L4`).
- Pure C, no HAL: the same file is compiled for the board and for host tests.

**Rule filter (`pkt_filter.c`)**
- `pkt_filter_process()` is the whole per-frame pipeline: parse, drop
  malformed frames before any rule sees them, then run the rule table.
  It returns a verdict (`action`, drop `reason`, matching `rule_idx`).
- A frame is malformed when a layer it claims to have is broken (EtherType
  says IPv4 but the header or its length is invalid, protocol says TCP/UDP but
  the header does not fit, RFC 1858 fragments). An absent layer is not an
  error (ARP, ICMP, later fragments).
- Ordered rule table, first match wins, default action if nothing matches
  (like a firewall rule list).
- A rule compares only the fields named in its `match` bits: EtherType,
  IP protocol, source/destination IP under a mask (subnets), ports.
- A rule that asks about a layer the frame does not have never matches, so a
  port rule cannot hit an ARP frame through stale fields.
- The rule table is `const`. The filter instance (`pkt_filter_t`) keeps the
  statistics: per-rule hits, default hits, passed frames and drops per reason
  (`malformed`, `rule`, `default`). The main loop prints them every 5 s
  (example numbers):
  ```
  --- passed 7 | dropped: malformed 0 rule 12 default 3 | hits: r0:12 r1:5 r2:2 default:3 ---
  ```

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
- **Host unit tests:** 46 tests (186 checks) build `pkt_parse.c` and
  `pkt_filter.c` for the PC and feed them hand-built frames: valid ARP / UDP /
  TCP, byte order, truncated and malformed headers, lying IP total length,
  Ethernet padding, IPv4 options, fragments and RFC 1858 fragment attacks,
  first-match order, subnet masks, stale-field protection, the demo rule
  table end to end, and the pipeline verdicts and drop-reason counters. GitHub Actions runs them on every push with
  AddressSanitizer + UBSan, so any read past the end of a frame fails the build.

## Running the unit tests

Needs a host GCC (Linux/macOS: `gcc` + `make`; Windows: e.g. WinLibs GCC,
where make is called `mingw32-make`).

```
cd tests
make            # Windows: mingw32-make
make SAN=1      # with AddressSanitizer + UBSan (Linux/macOS)
```

Expected last line: `186 checks, 0 failed: PASS`.

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
  pkt_filter.[ch]        first-match rule filter
  main.c                 init sequence, main loop, rule table and counters
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
- The current rule table is a demo for a PC link; the real policy (anti-spoofing,
  scan and flood protection) is designed together with the BBB tests.
