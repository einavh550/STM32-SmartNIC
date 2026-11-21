# Bug write-up: the board "sent" frames that never reached the cable

**Short version:** the first TX test reported every frame as sent (`sent 37
done 37 errors 0`), but the BeagleBone on the other end of the cable had
received **0 frames since boot**. Two of the three RMII TX pins were
configured on the wrong GPIOs (the STM32's defaults instead of the
NUCLEO-H723ZG wiring), so the MAC drove pins that are not connected to the
PHY. RX had always worked because the RX pins were right, which is why the
bug stayed hidden through 5 phases of RX-only work.

| | |
|---|---|
| Board | STM32H723 (NUCLEO-H723ZG), ETH MAC + DMA, LAN8742 PHY over RMII |
| Found by | Phase 6 step 1: first frame the board ever transmitted |
| Severity | no TX at all, and no error reported anywhere on the board |
| Fix | `STM32-SmartNIC.ioc` + `Core/Src/stm32h7xx_hal_msp.c`: TX_EN PB11 → PG11, TXD0 PB12 → PG13 |

## 1. Symptom

- Board: the TX descriptors came back from the DMA with OWN cleared and no
  error bit (`ES`): `--- tx: sent 37 done 37 | busy 0 errors 0 ---`.
- BBB: a UDP listener on port 5001 printed nothing. A raw Scapy sniff saw
  nothing either.

## 2. Finding the layer

Each check rules out one layer:

| Check | Result | Rules out |
|---|---|---|
| Board TX stats | sent = done, errors 0 | the driver: the DMA took and finished every descriptor |
| BBB UDP listener | silent | (could be anything below the socket) |
| BBB `ip -s link show eth0` | **RX packets 0, errors 0**, TX 4.5 M | the BBB's IP stack, checksums, ports: not even a broken frame arrived |

`RX packets 0, errors 0` was the key line. A frame with a bad checksum or a
bad CRC would still show up as a packet or as an error. Nothing at all means
no electrical signal reached the BBB's PHY. So the fault was between the
STM32 MAC and its own PHY: the pins.

## 3. Root cause

| Signal | Config (CubeMX chip default) | NUCLEO-H723ZG board (UM2407) |
|---|---|---|
| TX_EN | PB11 | **PG11** |
| TXD0 | PB12 | **PG13** |
| TXD1 | PB13 | PB13 |
| RXD0, RXD1, CRS_DV, REF_CLK, MDC, MDIO | PC4, PC5, PA7, PA1, PC1, PA2 | same |

The MAC does not know where its pins go. It shifts the frame out on
whatever GPIOs are set to the ETH alternate function and reports success.
There is no feedback from the wire on TX, so "done, no error" only means
"the MAC finished", not "the frame left the board".

## 4. Fix and proof

Moved TX_EN and TXD0 to PG11 / PG13 in both the `.ioc` (so CubeMX
regeneration keeps it) and the generated `HAL_ETH_MspInit()` /
`HAL_ETH_MspDeInit()` (GPIOG clock, pins, alternate function 11).

After the fix (`putty_tx1b.log`): the BBB listener printed
`b'STM32-SmartNIC TX test #3' ('192.168.10.1', 5000)` ... `#13`, one every
5 s with none missing, and the BBB's `RX packets` went from 0 to 21.

## 5. Lessons

- **"Done" from a DMA is not delivery.** On TX only the far end can prove a
  frame arrived. Count on the receiver too (here: the BBB's interface
  counters).
- **Check the board's pinout, not just the chip's.** CubeMX's default pins
  are valid for the chip, but a board wires only one of the possible pins.
  Starting the CubeMX project from the board (NUCLEO-H723ZG preset) instead
  of the bare MCU picks the right pins.
- **A one-directional test hides half the hardware.** 5 phases of RX tests
  never exercised the TX pins. A loopback or echo test early on would have
  found it on day one.
