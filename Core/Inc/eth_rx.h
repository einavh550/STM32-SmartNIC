/**
 * @file    eth_rx.h
 * @brief   Ethernet RX path: buffer pool for the ETH DMA and the glue to the ring buffer.
 */

#ifndef INC_ETH_RX_H_
#define INC_ETH_RX_H_

#include <stdint.h>
#include <stdbool.h>
#include "ring_buffer.h"

/* ------------------------------------------------------------------------- */
/* Configuration                                                             */
/* ------------------------------------------------------------------------- */

/** Size of one RX buffer in bytes. MUST match heth.Init.RxBuffLen (1536 in CubeMX).
 *  1536 >= 1518 (max Ethernet frame) and is a multiple of 32 (one cache line). */
#define ETH_RX_BUF_SIZE     (1536u)

/** Number of RX buffers in the pool. More than ETH_RX_DESC_CNT (4) so the DMA
 *  still has free buffers while the main loop is busy with older frames.
 *  16 x 1536 = 24 KB, which fits in the 32 KB of D2 SRAM next to the descriptors. */
#define ETH_RX_BUF_COUNT    (16u)

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

/**
 * @brief  Put all RX buffers in the free list.
 * @note   Call once from main AFTER MX_ETH_Init() and BEFORE HAL_ETH_Start_IT().
 */
void eth_rx_init(void);

/**
 * @brief  Give a buffer back to the pool after the frame in it was processed.
 * @note   MAIN LOOP ONLY (it is the single producer of the free list).
 */
void eth_rx_buf_free(uint8_t *buf);

/**
 * @brief  Take the oldest received frame out of the packet ring.
 * @note   MAIN LOOP ONLY. When done with out->data, call eth_rx_buf_free().
 * @return true if *out was filled, false if no frame is waiting.
 */
bool eth_rx_pop(pkt_desc_t *out);

/**
 * Give free pool buffers to RX descriptors that are waiting for one, and wake
 * the DMA. Call from the main loop after freeing buffers.
 *
 * Normally the RX interrupt refills each descriptor right after reading it.
 * But if the pool was empty at that moment the descriptor stays without a
 * buffer; once all are empty the DMA stops ("receive buffer unavailable")
 * and, since it receives nothing, no RX interrupt ever comes to refill them:
 * reception would be dead until reset. This breaks that deadlock.
 */
void eth_rx_refill(void);

/**
 * Where frames go before the filter sees them, for stress tests.
 * A frame on the wire is counted by the MAC (mac_rx_good). It then waits in
 * the MAC's RX FIFO until the DMA copies it into a pool buffer; if no buffer
 * (descriptor) is ready for too long the FIFO fills and the MAC drops frames
 * (fifo_overflow, dma_missed). Everything that makes it through is counted
 * by the filter. So: mac_rx_good - frames the filter saw = frames lost in
 * hardware.
 */
typedef struct
{
    uint32_t mac_rx_good;    /**< MMC: good unicast frames the MAC received.        */
    uint32_t fifo_overflow;  /**< MTL: frames dropped because the RX FIFO was full. */
    uint32_t dma_missed;     /**< MTL: frames the DMA could not take (no buffer).   */
    uint32_t rbu_events;     /**< DMA "receive buffer unavailable" interrupts.      */
    uint32_t refills;        /**< Times the main loop re-armed starved descriptors. */
    uint32_t free_bufs;      /**< Pool buffers free right now (of ETH_RX_BUF_COUNT). */
    uint32_t free_low;       /**< Fewest free buffers ever seen, since boot.       */
    uint32_t pool_empty;     /**< Times the DMA asked for a buffer and none was left. */
} eth_rx_stats_t;

/** Read the MAC's clear-on-read drop counters into the totals. Call often
 *  (every main-loop pass): the hardware counters are only 11 bits wide. */
void eth_rx_poll_hw(void);

/** Copy of the totals since boot. */
void eth_rx_get_stats(eth_rx_stats_t *out);

/** Fewest free buffers seen since the previous call (one stats period),
 *  then start a new period. The "free bufs" number above is only a snapshot
 *  at print time; this is the real low point in between. */
uint32_t eth_rx_take_period_low(void);

#endif /* INC_ETH_RX_H_ */
