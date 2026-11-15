# Bug write-up: Ethernet reception died for good after a short overload

**Short version:** at only 1 000 frames/s (under 1 % of line rate) the board
stopped receiving after 892 frames and never recovered until reset. The
Ethernet DMA ran out of RX buffers for a moment, suspended itself, and the
firmware's only way of waking it up was an interrupt that a suspended DMA can
never raise. A deadlock. Fixed in `6c53c3a`; after the fix the board takes
5 064 000 frames at 100 Mbit/s line rate with zero loss.

| | |
|---|---|
| Board | STM32H723 (Nucleo-H723ZG), ETH MAC + DMA, LAN8742 PHY, 100 Mbit/s |
| Driver | ST HAL ETH, zero-copy RX: 4 DMA descriptors, pool of 16 x 1536 B buffers |
| Found by | first stress test (`tools/bbb/stress.sh`, Linux pktgen on a BeagleBone Black) |
| Severity | total loss of reception, no recovery without reset |
| Fix | `eth_rx_refill()` in `Core/Src/eth_rx.c` + non-blocking log (`uart_log.[ch]`) |

---

## 1. Symptom

The stress script sends 64-byte UDP frames in steps: 1 000, 2 000, 5 000,
10 000, 20 000, 50 000 frames/s, then as fast as possible. The board died in
the **first and slowest** step. The stats line printed every 5 s:

```
before:  mac rx unicast 892    | filter saw 884 | rbu 1 | free bufs 0/16
after:   mac rx unicast 564000 | filter saw 892 | fifo-overflow 554949 | free bufs 15/16
```

What the counters say:

- **The wire and the MAC were fine.** The MAC counted all 564 000 frames that
  pktgen sent.
- **The frames never reached memory.** 554 949 of them were dropped in the
  MAC's small RX FIFO (`fifo-overflow`): the DMA was no longer moving them
  out.
- **The buffers were back, but nobody used them.** After the stall
  `free bufs` returned to 15/16, yet reception stayed dead.

That last point is the clue: this is not "too slow". The resources were free
and the hardware was still stopped.

## 2. How the RX path works (just enough to follow the bug)

```
  wire -> MAC -> RX FIFO -> DMA ---writes into---> buffer (from the pool)
                             |
                             +--> "frame done" interrupt -> ISR -> HAL_ETH_ReadData()
                                                                   - hands the frame to main (pkt_ring)
                                                                   - gives each empty descriptor a new
                                                                     buffer and tells the DMA (tail pointer)
  main loop: pop frame -> filter -> eth_rx_buf_free() -> buffer goes back to the pool
```

- A **descriptor** is a small slot the DMA reads to learn "where do I write
  the next frame". Each one needs a buffer attached.
- Buffers go round in a circle: pool -> descriptor -> DMA fills it -> main
  filters it -> pool.
- **Important detail:** in the HAL, descriptors get new buffers only inside
  `HAL_ETH_ReadData()`, and before the fix only the RX interrupt called it.

## 3. Root cause: two bugs that only together kill the board

**Bug 1, the trigger: the stats print blocked the main loop.** Every 5 s the
main loop printed ~600 characters with a blocking `printf` (115 200 baud,
~87 us per character): **~50 ms** with no frame processed. At 1 000 frames/s
that is ~50 frames arriving, and there are only 16 buffers. The pool ran
empty, the DMA found a descriptor without a buffer, raised **RBU** ("receive
buffer unavailable") and **suspended itself**. That part is normal hardware
behaviour and on its own would cost a few frames.

**Bug 2, the deadlock: nothing could ever wake the DMA again.**

```
time ->
main:  [ printing stats ... 50 ms ............ ] free 15 buffers -> back to pool
DMA:        receiving ... pool empty -> RBU -> SUSPENDED (receives nothing)
ISR:        runs per frame ...........  (no frames) -> never runs again
HAL_ETH_ReadData(): only called by the ISR -> never called again
descriptors: never get the freed buffers -> DMA stays suspended -> forever
```

The wake-up path depended on the very thing that had stopped. Main freed the
buffers into the pool, but only the ISR could move them into descriptors, and
the ISR only runs when a frame is received, which a suspended DMA never does.
A short overload became a permanent outage.

## 4. Why earlier tests never showed it

All earlier tests were Scapy scenarios (a few hundred frames at a few dozen
frames/s). The pool never came close to empty, so the DMA never suspended
and the broken recovery path never ran. The bug was in the code from the first
RX commit; it needed **overload** to show up. "Works at normal load" says
nothing about what happens after an overload.

## 5. The fix

**Fix for bug 2 (the real one): `eth_rx_refill()`, called on every main-loop pass.**

```c
void eth_rx_refill(void)
{
    if (heth.RxDescList.RxBuildDescCnt == 0u)   /* every descriptor has a buffer */
    {
        return;                                  /* normal case: costs one read */
    }
    HAL_NVIC_DisableIRQ(ETH_IRQn);               /* HAL RX bookkeeping is not reentrant */
    void *frame;
    while (HAL_ETH_ReadData(&heth, &frame) == HAL_OK)
    {
    }                                            /* refills descriptors + writes the
                                                    DMA tail pointer -> DMA resumes */
    HAL_NVIC_EnableIRQ(ETH_IRQn);
    refill_total++;
}
```

- The main loop is the code that frees buffers, so the main loop now also
  checks "is a descriptor waiting for a buffer?" The wake-up no longer depends
  on an interrupt that cannot come.
- `RxBuildDescCnt` (descriptors still to be given a buffer) is the HAL's own
  counter: 0 in normal operation, so the check is almost free.
- The ETH interrupt is masked while main calls `HAL_ETH_ReadData()`, because
  the ISR calls it too and the HAL's descriptor indexes are not safe against
  being changed from two places at once. Masking only `ETH_IRQn` (not all
  interrupts) keeps the window to a few microseconds.
- Writing the DMA **tail pointer** register (done inside the HAL refill) is
  what tells a suspended DMA "new descriptors are ready" and makes it resume.

**Fix for bug 1 (the trigger): non-blocking log.** `printf` now copies text into
a 4 KB RAM ring and returns at once; the USART3 TX interrupt sends it in the
background at a lower priority than Ethernet. If the ring is full, the log
line is dropped and counted (`log-drop`): losing log text is better than
losing frames.

**Instrumentation added to see all this** (printed every 5 s): MAC received
count, MTL FIFO overflow and DMA missed counters (clear-on-read registers,
summed), `rbu` events (from `HAL_ETH_ErrorCallback`), `refills`, free buffers
now, and later the pool low-water mark.

## 6. Verification

Same stress script, same frames, before and after:

| Run | Firmware | Result |
|---|---|---|
| 1 | before the fixes | died after 892 frames at 1 000 frames/s; 554 949 dropped in the FIFO |
| 2 | + `eth_rx_refill()` | survives: `rbu 9 / refills 9`, every stall recovered; 280 frames lost, all during blocking prints |
| 3 | + non-blocking log | 5 064 000 of 5 064 000 frames, 31 s at line rate (~146 000 frames/s), **0 lost** |

In run 3 the DMA still ran out of buffers now and then (`rbu 66`), and every
time it recovered within a main-loop pass while the MAC FIFO held the
incoming frames. Running out of buffers is now a short, harmless event
instead of a fatal one.

## 7. Lessons

1. **A recovery path must not depend on the thing that failed.** "Refill
   only in the RX interrupt" is fine until RX stops; then nothing refills.
   Whoever frees a resource should also be able to re-arm the hardware.
2. **Test overload, not only normal load.** The bug lived through every
   functional test and appeared in the first second of the first stress test.
3. **Hardware counters find bugs fast.** "MAC got 564 000, filter saw 892,
   free buffers 15/16" pointed straight at the DMA without a debugger.
4. **Blocking I/O in a packet loop is a latent bug.** A 50 ms `printf` is
   invisible at 10 frames/s and fatal at 1 000.
5. **Separate the trigger from the root cause.** Fixing only the print
   would have hidden the deadlock until some other stall (a burst, a slow
   flash write) set it off in the field.

## 8. The 60-second version (for interviews)

> "On my STM32 NIC project, the first stress test killed Ethernet reception at
> only 1 000 frames per second, and it never came back until reset. The
> counters showed the MAC got every frame, but they all died in its FIFO, and
> the buffer pool was full again. So the hardware was stuck, not slow.
> The cause was two bugs. A blocking 50 ms debug print let the 16-buffer pool
> run dry, so the DMA raised 'buffer unavailable' and suspended. That is
> normal. But in the ST HAL, descriptors are refilled only from the RX
> interrupt, and a suspended DMA never raises one. A deadlock. I fixed it by
> having the main loop, which frees the buffers, re-arm the descriptors and
> the DMA tail pointer itself, with only the ETH interrupt masked. Then I made
> logging non-blocking. After that the board took five million frames at
> 100 Mbit line rate with zero loss. The lesson: a recovery path must never
> depend on the event that failure stops."
