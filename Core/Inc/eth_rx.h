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

#endif /* INC_ETH_RX_H_ */
