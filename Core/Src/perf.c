/**
 * perf.c - CPU cycle measurement with the Cortex-M7 DWT cycle counter.
 * See perf.h.
 */
#include "perf.h"

static uint32_t overhead_cycles;

void perf_init(void)
{
  /* DWT belongs to the debug block: switch the trace/debug unit on first. */
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;

  /* The Cortex-M7 locks the DWT registers after reset; this key unlocks them. */
  DWT->LAR = 0xC5ACCE55u;

  DWT->CYCCNT = 0u;
  DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;

  /* Calibrate: time "nothing". Take the smallest of a few tries, so a stray
   * interrupt in the middle cannot inflate it. */
  uint32_t best = UINT32_MAX;
  for (int i = 0; i < 8; i++)
  {
    uint32_t t0 = perf_now();
    uint32_t t1 = perf_now();
    if ((t1 - t0) < best)
    {
      best = t1 - t0;
    }
  }
  overhead_cycles = best;
}

void perf_reset(perf_stats_t *s)
{
  s->min   = UINT32_MAX;
  s->max   = 0u;
  s->sum   = 0u;
  s->count = 0u;
}

void perf_record(perf_stats_t *s, uint32_t cycles)
{
  cycles = (cycles > overhead_cycles) ? (cycles - overhead_cycles) : 0u;

  if (cycles < s->min)
  {
    s->min = cycles;
  }
  if (cycles > s->max)
  {
    s->max = cycles;
  }
  s->sum += cycles;
  s->count++;
}

uint32_t perf_overhead(void)
{
  return overhead_cycles;
}

uint32_t perf_cycles_to_ns(uint32_t cycles)
{
  /* 64-bit so cycles * 1e9 cannot overflow. SystemCoreClock = 550000000. */
  return (uint32_t)(((uint64_t)cycles * 1000000000u) / SystemCoreClock);
}
