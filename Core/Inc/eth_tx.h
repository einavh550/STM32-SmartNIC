/**
 * @file    eth_tx.h
 * @brief   Ethernet TX path (Phase 6): a lean TX descriptor driver.
 *
 * Design:
 * - Only the main loop uses it: eth_tx_send() fills TX descriptors and
 *   eth_tx_reclaim() collects the ones the DMA has finished. One context,
 *   so no locks and no TX interrupt (descriptors are sent without IOC).
 *   Linux NIC drivers clean their TX ring the same way, from the poll loop.
 * - Zero-copy: the DMA reads the frame straight from the caller's buffer,
 *   which must be in D2 SRAM (DMA-reachable, non-cacheable: no cache clean
 *   needed). A buffer from the RX pool goes back to the pool once its frame
 *   is sent (in eth_tx_reclaim()).
 * - Ring full: eth_tx_send() returns false at once (counted as "busy");
 *   it never waits, so RX is never held up by TX.
 */

#ifndef INC_ETH_TX_H_
#define INC_ETH_TX_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct
{
    uint32_t sent;       /* frames handed to the DMA */
    uint32_t done;       /* frames the DMA finished (reclaimed) */
    uint32_t busy;       /* eth_tx_send() refused: all TX descriptors in use */
    uint32_t errors;     /* finished with the error summary bit (ES) set */
    uint32_t in_flight;  /* descriptors owned by the DMA right now */
} eth_tx_stats_t;

/** Take the TX ring over from the HAL. Call once, after eth_rx_start()
 *  (HAL_ETH_Start_IT() has started the TX DMA with an empty ring). */
void eth_tx_init(void);

/** Queue one whole frame (no FCS; the MAC adds the CRC and pads short
 *  frames to 60 bytes). buf must stay untouched until reclaimed.
 *  Returns false if no TX descriptor is free. Main loop only. */
bool eth_tx_send(uint8_t *buf, uint16_t len);

/** Collect finished descriptors; pool buffers go back to the RX pool.
 *  Returns how many were collected. Main loop only, call every pass. */
uint32_t eth_tx_reclaim(void);

/** Send the test frame: UDP broadcast 192.168.10.1:5000 ->
 *  192.168.10.255:5001, payload "STM32-SmartNIC TX test #<seq>".
 *  Returns false if the previous test frame is still being sent. */
bool eth_tx_send_test(uint32_t seq);

void eth_tx_get_stats(eth_tx_stats_t *out);

#endif /* INC_ETH_TX_H_ */
