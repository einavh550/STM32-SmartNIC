/**
 * @file    pkt_flags.h
 * @brief   Per-frame status bits reported by the ETH MAC (pkt_desc_t.flags).
 *
 * @note    Our own bit values, not the hardware's: the code that reads them
 *          (main loop, filter, host tests) does not depend on the STM32
 *          descriptor layout. eth_rx.c translates the descriptor bits.
 */

#ifndef INC_PKT_FLAGS_H_
#define INC_PKT_FLAGS_H_

/* The MAC's checksum offload report for one frame. */
#define PKT_FLAG_IP_HDR_ERR     (1u << 0)  /**< IPv4 header checksum/version/length wrong. */
#define PKT_FLAG_IP_PAYLOAD_ERR (1u << 1)  /**< TCP/UDP/ICMP checksum wrong, or the IP total
                                               length disagrees with the bytes received. */

/** Any checksum offload error: the frame's bytes are not what the sender wrote. */
#define PKT_FLAG_CSUM_ERRORS    (PKT_FLAG_IP_HDR_ERR | PKT_FLAG_IP_PAYLOAD_ERR)

#endif /* INC_PKT_FLAGS_H_ */
