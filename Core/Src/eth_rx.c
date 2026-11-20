/**
 * @file    eth_rx.c
 * @brief   Ethernet RX path: buffer pool for the ETH DMA and the glue to the ring buffer.
 */

#include "eth_rx.h"
#include "ring_buffer.h"
#include "stm32h7xx_hal.h"

/* ------------------------------------------------------------------------- */
/* RX buffer pool                                                            */
/* ------------------------------------------------------------------------- */

/* The ETH DMA writes received frames directly into these buffers.
 * - section: the linker script places .RxBuffSection in D2 SRAM (0x3000xxxx),
 *   which the ETH DMA can reach and MPU region 1 makes non-cacheable.
 * - aligned(32): each buffer starts on a cache-line boundary (1536 is a
 *   multiple of 32, so every buffer in the array stays aligned). */
static uint8_t rx_pool[ETH_RX_BUF_COUNT][ETH_RX_BUF_SIZE]
    __attribute__((section(".RxBuffSection"), aligned(32)));

/* Free list: addresses of buffers that nobody is using right now.
 * It is a second SPSC ring, used in the OPPOSITE direction of the packet ring:
 * - producer = main loop (eth_rx_buf_free() gives a buffer back),
 * - consumer = ETH ISR   (HAL_ETH_RxAllocateCallback() takes one for the DMA).
 * Only the .data field of pkt_desc_t is used here. */
static ring_buffer_t free_ring;

/* Packet ring: one descriptor per received frame.
 * - producer = ETH ISR   (HAL_ETH_RxLinkCallback() pushes a full buffer),
 * - consumer = main loop (eth_rx_pop() takes it out). */
static ring_buffer_t pkt_ring;

/* A buffer is either in free_ring, held by the DMA, in pkt_ring, or being
 * processed by main. So pkt_ring can never hold more than ETH_RX_BUF_COUNT
 * entries, and rb_push() on it can never fail. */
_Static_assert(ETH_RX_BUF_COUNT <= RB_CAPACITY,
               "pkt_ring must be able to hold every RX buffer at once");

/* One buffer must hold a whole frame (1518 bytes, 1522 with a VLAN tag),
 * so the HAL never splits a frame over two buffers. */
_Static_assert(ETH_RX_BUF_SIZE >= 1522u,
               "RX buffer too small for a full Ethernet frame");

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

void eth_rx_init(void)
{
    rb_init(&free_ring);
    rb_init(&pkt_ring);

    /* At start every buffer is free. */
    for (uint32_t i = 0u; i < ETH_RX_BUF_COUNT; i++)
    {
        pkt_desc_t d = { .data = rx_pool[i], .len = 0u, .flags = 0u };
        (void)rb_push(&free_ring, &d);   /* cannot fail: 16 < RB_CAPACITY */
    }
}

void eth_rx_buf_free(uint8_t *buf)
{
    pkt_desc_t d = { .data = buf, .len = 0u, .flags = 0u };
    (void)rb_push(&free_ring, &d);       /* cannot fail: at most 16 buffers exist */
}

bool eth_rx_pop(pkt_desc_t *out)
{
    return rb_pop(&pkt_ring, out);
}

/* ------------------------------------------------------------------------- */
/* Checksum offload report                                                   */
/* ------------------------------------------------------------------------- */

extern ETH_HandleTypeDef heth;           /* main.c (CubeMX) */

/* When the DMA finishes a frame it writes a status report back into the RX
 * descriptor. The checksum offload result is in DESC1 (IPHE, IPCE), but the
 * HAL only keeps DESC3 and our link callback gets just the buffer address.
 * Each descriptor remembers its buffer in BackupAddr0, so find the one that
 * owns buff. Called from HAL_ETH_RxLinkCallback(), i.e. inside
 * HAL_ETH_ReadData() BEFORE the HAL rebuilds the descriptor, so the report
 * is still there. Descriptors live in non-cacheable D2 SRAM (MPU region 1):
 * the CPU reads exactly what the DMA wrote, no cache maintenance needed. */
static uint16_t rx_csum_flags(const uint8_t *buff)
{
    for (uint32_t i = 0u; i < ETH_RX_DESC_CNT; i++)
    {
        const ETH_DMADescTypeDef *desc = &heth.Init.RxDesc[i];

        if (desc->BackupAddr0 != (uint32_t)buff)
        {
            continue;
        }

        /* RS1V: the DMA says DESC1 holds a valid status for this frame. */
        if ((desc->DESC3 & ETH_DMARXNDESCWBF_RS1V) == 0u)
        {
            return 0u;
        }

        uint16_t flags = 0u;
        if ((desc->DESC1 & ETH_DMARXNDESCWBF_IPHE) != 0u)
        {
            flags |= PKT_FLAG_IP_HDR_ERR;
        }
        if ((desc->DESC1 & ETH_DMARXNDESCWBF_IPCE) != 0u)
        {
            flags |= PKT_FLAG_IP_PAYLOAD_ERR;
        }
        return flags;
    }

    return 0u;                           /* not found: cannot happen, report nothing */
}

/* ------------------------------------------------------------------------- */
/* HAL callbacks (override the __weak versions in stm32h7xx_hal_eth.c)       */
/* ------------------------------------------------------------------------- */

static void note_free_count(uint32_t n);   /* low-water marks, see below */
static volatile uint32_t pool_empty_total; /* allocations that found the pool empty */
static uint32_t rx_harvest(uint32_t budget); /* read finished frames, see below */

/* The HAL calls this when an RX descriptor needs an empty buffer.
 * Returning NULL is allowed: the HAL leaves that descriptor empty and
 * asks again on the next HAL_ETH_ReadData(). */
void HAL_ETH_RxAllocateCallback(uint8_t **buff)
{
    pkt_desc_t d;

    if (rb_pop(&free_ring, &d))
    {
        *buff = d.data;
        note_free_count(rb_count(&free_ring));   /* low-water mark */
    }
    else
    {
        *buff = NULL;                    /* pool empty: all buffers are busy */
        pool_empty_total++;
        note_free_count(0u);
    }
}

/* Called by HAL_ETH_ReadData() once the DMA has finished writing a frame.
 * buff   = the buffer the DMA filled (one we gave in RxAllocateCallback),
 * Length = number of bytes the DMA wrote.
 * Zero-copy: we only push the buffer's ADDRESS, length and the MAC's
 * checksum report, never the bytes. */
/* ------------------------------------------------------------------------- */
/* Hardware drop counters (stress tests)                                     */
/* ------------------------------------------------------------------------- */

static uint32_t fifo_overflow_total;     /* main loop only */
static uint32_t dma_missed_total;        /* main loop only */
static volatile uint32_t rbu_total;      /* written by the ETH ISR */
static uint32_t refill_total;            /* main loop only */

/* Low-water marks of the free ring. Written where buffers are TAKEN
 * (HAL_ETH_RxAllocateCallback: ETH ISR, or main with the ETH IRQ masked),
 * because that is the only place the count goes down. */
static volatile uint32_t free_low_ever   = ETH_RX_BUF_COUNT;
static volatile uint32_t free_low_period = ETH_RX_BUF_COUNT;

static void note_free_count(uint32_t n)
{
    if (n < free_low_ever)
    {
        free_low_ever = n;
    }
    if (n < free_low_period)
    {
        free_low_period = n;
    }
}

uint32_t eth_rx_take_period_low(void)
{
    /* Read and restart together, so a buffer taken by the ISR in between is
     * not lost: mask the ETH IRQ for these few instructions. */
    HAL_NVIC_DisableIRQ(ETH_IRQn);
    uint32_t low    = free_low_period;
    free_low_period = rb_count(&free_ring);
    HAL_NVIC_EnableIRQ(ETH_IRQn);
    return low;
}

static bool rx_ring_full(void);           /* every descriptor has a buffer? */

void eth_rx_refill(void)
{
    /* 0 descriptors waiting for a buffer is normal operation (the ISR
     * refills at once). One aligned 32-bit read is atomic; if the ISR
     * changes it right after, we just act one loop pass later. */
    if (rx_ring_full())
    {
        return;
    }

    /* rx_harvest() re-arms the empty descriptors from free_ring and writes
     * the DMA tail pointer, which resumes a suspended DMA. It also reads any
     * frame already finished (-> pkt_ring). The ISR calls it too, and the
     * descriptor bookkeeping is not reentrant, so keep the ETH interrupt off
     * meanwhile (at most 4 descriptors: a few microseconds). With the
     * interrupt off, main is the only producer of pkt_ring for that moment,
     * so the ring stays single-producer. */
    HAL_NVIC_DisableIRQ(ETH_IRQn);
    (void)rx_harvest(UINT32_MAX);
    HAL_NVIC_EnableIRQ(ETH_IRQn);

    refill_total++;
}

/* The HAL calls this from the ETH ISR on an "abnormal" DMA interrupt. With
 * enough traffic the only one we expect is RBU: the DMA wanted a descriptor
 * to write the next frame into, and none had a buffer (pool empty). */
void HAL_ETH_ErrorCallback(ETH_HandleTypeDef *h)
{
    if ((h->DMAErrorCode & ETH_DMACSR_RBU) != 0u)
    {
        rbu_total++;
    }
}

void eth_rx_poll_hw(void)
{
    /* Both 11-bit fields are cleared by this read, so add them up here. */
    uint32_t r = heth.Instance->MTLRQMPOCR;
    fifo_overflow_total += (r & ETH_MTLRQMPOCR_OVFPKTCNT_Msk) >> ETH_MTLRQMPOCR_OVFPKTCNT_Pos;
    dma_missed_total    += (r & ETH_MTLRQMPOCR_MISPKTCNT_Msk) >> ETH_MTLRQMPOCR_MISPKTCNT_Pos;
}

void eth_rx_get_stats(eth_rx_stats_t *out)
{
    out->mac_rx_good   = heth.Instance->MMCRUPGR;   /* 32-bit, not cleared on read */
    out->fifo_overflow = fifo_overflow_total;
    out->dma_missed    = dma_missed_total;
    out->rbu_events    = rbu_total;
    out->refills       = refill_total;
    out->free_bufs     = rb_count(&free_ring);
    out->free_low      = free_low_ever;
    out->pool_empty    = pool_empty_total;
}

void HAL_ETH_RxLinkCallback(void **pStart, void **pEnd, uint8_t *buff, uint16_t Length)
{
    pkt_desc_t d = { .data = buff, .len = Length, .flags = rx_csum_flags(buff) };
    (void)rb_push(&pkt_ring, &d);        /* cannot fail: see _Static_assert above */

    /* The HAL needs a non-NULL start pointer to know a frame was linked;
     * HAL_ETH_ReadData() returns it to the caller and then resets it. */
    *pStart = buff;
    *pEnd   = buff;
}

/* Called from ETH_IRQHandler -> HAL_ETH_IRQHandler() when the DMA has
 * received at least one frame. Runs in INTERRUPT context: keep it short.
 * One interrupt can stand for several frames (they may arrive faster than
 * the CPU reacts), so drain them all with rx_harvest() (bottom of file):
 * every finished frame goes into pkt_ring and its descriptor is re-armed. */
static volatile uint32_t rx_irq_total;      /* written by the ETH ISR */

#if ETH_RX_NAPI
/* 1 = the ISR said "frames are waiting" and switched the RX interrupt off;
 * main keeps polling until the DMA has nothing more. */
static volatile uint32_t rx_poll_pending;
#endif

void HAL_ETH_RxCpltCallback(ETH_HandleTypeDef *heth)
{
    rx_irq_total++;

#if ETH_RX_NAPI
    /* NAPI-style: do NOT read here. Turn the RX interrupt off (RIE in the DMA
     * channel's interrupt-enable register) and leave a note for main. More
     * frames can arrive now without costing more interrupts: main reads them
     * all in eth_rx_poll(). (The HAL already cleared RI before calling us.) */
    __HAL_ETH_DMA_DISABLE_IT(heth, ETH_DMACIER_RIE);
    rx_poll_pending = 1u;
#else
    (void)heth;
    (void)rx_harvest(UINT32_MAX);        /* every finished frame -> pkt_ring */
#endif
}

uint32_t eth_rx_irq_count(void)
{
    return rx_irq_total;
}

uint32_t eth_rx_poll(uint32_t budget)
{
#if ETH_RX_NAPI
    if (rx_poll_pending == 0u)
    {
        return 0u;                       /* interrupt mode: nothing announced */
    }

    /* Only main reads frames now (the ISR does not), so no need to mask the
     * ETH IRQ around it. Each frame goes into pkt_ring and its descriptor
     * gets a fresh buffer. */
    uint32_t n = rx_harvest(budget);

    if (n == budget)
    {
        return n;                        /* maybe more waiting: stay in polling */
    }

    /* The DMA has nothing more: go back to interrupt mode. Order matters:
     * 1. clear RI: forget the "frame done" flag of frames we already read,
     * 2. look ONE more time: a frame may have finished just before step 1,
     *    and its flag was just erased -> nobody would ever announce it,
     * 3. only if still nothing: clear the note, THEN switch RIE back on.
     *    A frame finishing after step 1 has set RI again, so the interrupt
     *    fires as soon as RIE is on: nothing is missed. */
    __HAL_ETH_DMA_CLEAR_IT(&heth, ETH_DMACSR_RI | ETH_DMACSR_NIS);
    if (rx_harvest(1u) != 0u)
    {
        return n + 1u;                   /* caught one: poll again next pass */
    }
    rx_poll_pending = 0u;
    __HAL_ETH_DMA_ENABLE_IT(&heth, ETH_DMACIER_RIE);
    return n;
#else
    (void)budget;
    return 0u;                           /* old mode: the ISR reads the frames */
#endif
}

/* ------------------------------------------------------------------------- */
/* Reading finished frames: lean driver or HAL                               */
/* ------------------------------------------------------------------------- */

#if ETH_RX_LEAN

/* Why our own loop: HAL_ETH_ReadData() is general (frames split over several
 * descriptors, timestamps, polling mode, a callback per step) and reads the
 * same descriptor word many times. Every descriptor read goes to D2 SRAM,
 * which is non-cacheable (MPU region 1), so each one is a slow bus access.
 * Our case is simpler: one 1536-byte buffer always holds a whole frame and
 * timestamps are off. So per frame: read DESC3 once, read DESC1 once, write
 * the descriptor back with a new buffer, and move the tail pointer.
 *
 * Ring state. The HAL builds the ring in HAL_ETH_Start_IT(); eth_rx_start()
 * then copies its state here and the HAL never touches the ring again.
 *   rx_next  = next descriptor the DMA will finish (we read from here),
 *   rx_build = next descriptor that needs a buffer (we arm from here),
 *   rx_armed = descriptors holding a buffer, owned by the DMA.
 * rx_desc_buf[] remembers which buffer each descriptor holds. It lives in
 * normal (cached) RAM, so looking it up is fast, unlike BackupAddr0 in D2.
 * Only the ETH ISR, or main with the ETH IRQ masked, runs this code. */
static uint8_t *rx_desc_buf[ETH_RX_DESC_CNT];
static uint32_t rx_next;
static uint32_t rx_build;
static volatile uint32_t rx_armed;       /* main reads it in eth_rx_refill() */

static inline uint32_t rx_idx_next(uint32_t i)
{
    return (i + 1u == ETH_RX_DESC_CNT) ? 0u : (i + 1u);
}

/* Give a free buffer to every descriptor that has none, then tell the DMA. */
static void rx_arm(void)
{
    uint32_t armed = rx_armed;
    const uint32_t before = armed;
    uint32_t last = rx_build;

    while (armed < ETH_RX_DESC_CNT)
    {
        pkt_desc_t d;
        if (!rb_pop(&free_ring, &d))
        {
            pool_empty_total++;          /* pool empty: try again later */
            note_free_count(0u);
            break;
        }
        note_free_count(rb_count(&free_ring));

        ETH_DMADescTypeDef *desc = &heth.Init.RxDesc[rx_build];
        rx_desc_buf[rx_build] = d.data;
        desc->DESC0 = (uint32_t)d.data;  /* buffer 1 address */
        /* The DMA must see the address BEFORE it sees OWN. D2 SRAM is
         * "normal" memory, where the CPU may reorder stores: force order. */
        __DMB();
        desc->DESC3 = ETH_DMARXNDESCRF_OWN | ETH_DMARXNDESCRF_BUF1V | ETH_DMARXNDESCRF_IOC;

        last     = rx_build;
        rx_build = rx_idx_next(rx_build);
        armed++;
    }

    if (armed != before)
    {
        rx_armed = armed;
        /* Tail pointer = last descriptor the DMA may use. Writing it also
         * wakes a DMA that stopped for lack of buffers (RBU). */
        __DMB();
        heth.Instance->DMACRDTPR = (uint32_t)&heth.Init.RxDesc[last];
    }
}

/* Read up to `budget` finished frames into pkt_ring, then re-arm the ring.
 * Returns the number of frames read. */
static uint32_t rx_harvest(uint32_t budget)
{
    uint32_t n = 0u;
    uint32_t armed = rx_armed;

    while ((n < budget) && (armed > 0u))
    {
        const ETH_DMADescTypeDef *desc = &heth.Init.RxDesc[rx_next];
        const uint32_t d3 = desc->DESC3; /* ONE read of the write-back word */

        if ((d3 & ETH_DMARXNDESCWBF_OWN) != 0u)
        {
            break;                       /* the DMA still owns it: no more frames */
        }

        pkt_desc_t d = { .data = rx_desc_buf[rx_next], .len = 0u, .flags = 0u };

        /* Normal case: the whole frame in this one descriptor (first and
         * last), not a context (timestamp) descriptor. */
        if ((d3 & (ETH_DMARXNDESCWBF_FD | ETH_DMARXNDESCWBF_LD | ETH_DMARXNDESCWBF_CTXT))
            == (ETH_DMARXNDESCWBF_FD | ETH_DMARXNDESCWBF_LD))
        {
            d.len = (uint16_t)(d3 & ETH_DMARXNDESCWBF_PL);
            if ((d3 & ETH_DMARXNDESCWBF_RS1V) != 0u)  /* DESC1 holds a valid report */
            {
                const uint32_t d1 = desc->DESC1;
                if ((d1 & ETH_DMARXNDESCWBF_IPHE) != 0u)
                {
                    d.flags |= PKT_FLAG_IP_HDR_ERR;
                }
                if ((d1 & ETH_DMARXNDESCWBF_IPCE) != 0u)
                {
                    d.flags |= PKT_FLAG_IP_PAYLOAD_ERR;
                }
            }
        }
        /* else: cannot happen with whole-frame buffers and timestamps off.
         * If it ever does, the buffer still goes to main with len 0: the
         * parser counts it as malformed and main frees it as usual. */

        (void)rb_push(&pkt_ring, &d);    /* cannot fail: see _Static_assert above */
        rx_desc_buf[rx_next] = NULL;
        rx_next = rx_idx_next(rx_next);
        armed--;
        n++;
    }

    rx_armed = armed;
    rx_arm();
    return n;
}

static bool rx_ring_full(void)
{
    return rx_armed == ETH_RX_DESC_CNT;
}

bool eth_rx_start(void)
{
    /* Keep the ETH interrupt off until the takeover below is done, so the
     * first RX interrupt already finds our state. A frame that arrives in
     * between just stays pending and is handled right after. */
    HAL_NVIC_DisableIRQ(ETH_IRQn);
    const bool ok = (HAL_ETH_Start_IT(&heth) == HAL_OK);

    /* HAL_ETH_Start_IT() armed the descriptors with our buffers (through
     * HAL_ETH_RxAllocateCallback); each one remembers its buffer in
     * BackupAddr0. Copy that state, then the HAL never touches RX again. */
    for (uint32_t i = 0u; i < ETH_RX_DESC_CNT; i++)
    {
        rx_desc_buf[i] = (uint8_t *)heth.Init.RxDesc[i].BackupAddr0;
    }
    rx_next  = heth.RxDescList.RxDescIdx;
    rx_build = heth.RxDescList.RxBuildDescIdx;
    rx_armed = ETH_RX_DESC_CNT - heth.RxDescList.RxBuildDescCnt;

    HAL_NVIC_EnableIRQ(ETH_IRQn);
    return ok;
}

#else /* !ETH_RX_LEAN: the ST HAL path */

/* Each successful HAL_ETH_ReadData() calls HAL_ETH_RxLinkCallback() (frame ->
 * pkt_ring) and refills the descriptor via HAL_ETH_RxAllocateCallback(). It
 * also re-arms starved descriptors even when no frame is waiting. */
static uint32_t rx_harvest(uint32_t budget)
{
    uint32_t n = 0u;
    void *frame;
    while ((n < budget) && (HAL_ETH_ReadData(&heth, &frame) == HAL_OK))
    {
        n++;
    }
    return n;
}

static bool rx_ring_full(void)
{
    /* RxBuildDescCnt = descriptors the HAL still has to give a buffer to. */
    return heth.RxDescList.RxBuildDescCnt == 0u;
}

bool eth_rx_start(void)
{
    return HAL_ETH_Start_IT(&heth) == HAL_OK;
}

#endif /* ETH_RX_LEAN */
