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
/* HAL callbacks (override the __weak versions in stm32h7xx_hal_eth.c)       */
/* ------------------------------------------------------------------------- */

/* The HAL calls this when an RX descriptor needs an empty buffer.
 * Returning NULL is allowed: the HAL leaves that descriptor empty and
 * asks again on the next HAL_ETH_ReadData(). */
void HAL_ETH_RxAllocateCallback(uint8_t **buff)
{
    pkt_desc_t d;

    if (rb_pop(&free_ring, &d))
    {
        *buff = d.data;
    }
    else
    {
        *buff = NULL;                    /* pool empty: all buffers are busy */
    }
}

/* Called by HAL_ETH_ReadData() once the DMA has finished writing a frame.
 * buff   = the buffer the DMA filled (one we gave in RxAllocateCallback),
 * Length = number of bytes the DMA wrote.
 * Zero-copy: we only push the buffer's ADDRESS and length, never the bytes. */
void HAL_ETH_RxLinkCallback(void **pStart, void **pEnd, uint8_t *buff, uint16_t Length)
{
    pkt_desc_t d = { .data = buff, .len = Length, .flags = 0u };
    (void)rb_push(&pkt_ring, &d);        /* cannot fail: see _Static_assert above */

    /* The HAL needs a non-NULL start pointer to know a frame was linked;
     * HAL_ETH_ReadData() returns it to the caller and then resets it. */
    *pStart = buff;
    *pEnd   = buff;
}
