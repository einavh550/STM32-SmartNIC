# STM32-SmartNIC

Bare-metal firmware that turns an STM32H723 into a simple SmartNIC: it receives
Ethernet frames through the MAC's DMA, hands them from the interrupt to the main
loop without copying, and (in later phases) filters them by header fields.
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
| 3     | Header filtering (MAC / IP / port)            | Next        |
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
  main.c                 init sequence and main loop
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
