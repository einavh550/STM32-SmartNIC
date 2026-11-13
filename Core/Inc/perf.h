/**
 * perf.h - CPU cycle measurement with the Cortex-M7 DWT cycle counter.
 *
 * DWT->CYCCNT is a 32-bit hardware counter that adds 1 on every CPU clock
 * (550 MHz -> 1 cycle = 1.82 ns). Reading it before and after a piece of code
 * gives the exact number of cycles that code took, with no timer setup and
 * almost no overhead (one register read each side).
 *
 * Usage:
 *   perf_init();                         once at boot
 *   uint32_t t0 = perf_now();
 *   ...code to measure...
 *   perf_record(&stats, perf_now() - t0);
 *   ...every few seconds: print stats, then perf_reset(&stats).
 */
#ifndef PERF_H
#define PERF_H

#include <stdint.h>
#include "stm32h7xx.h"

/** min / max / sum of the samples recorded since the last perf_reset(). */
typedef struct
{
  uint32_t min;
  uint32_t max;
  uint64_t sum;    /* 64-bit: 5 s of samples can exceed 2^32 cycles */
  uint32_t count;
} perf_stats_t;

/** Start the cycle counter and measure the cost of measuring itself. */
void perf_init(void);

/** Current cycle count. The subtraction (now - t0) stays correct when the
 *  counter wraps at 2^32 (every ~7.8 s at 550 MHz), like HAL_GetTick(). */
static inline uint32_t perf_now(void)
{
  return DWT->CYCCNT;
}

/** Add one sample (raw cycles); the measurement overhead is subtracted. */
void perf_record(perf_stats_t *s, uint32_t cycles);

void perf_reset(perf_stats_t *s);

/** Cycles of an empty measurement (two back-to-back perf_now() reads). */
uint32_t perf_overhead(void);

/** Convert cycles to nanoseconds at the current CPU clock. */
uint32_t perf_cycles_to_ns(uint32_t cycles);

#endif /* PERF_H */
