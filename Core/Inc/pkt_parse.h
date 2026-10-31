/**
 * @file    pkt_parse.h
 * @brief   Header parser for received Ethernet frames.
 *
 * @note    Pure C, no HAL or hardware access, so it can also be built and
 *          unit-tested on a PC.
 */

#ifndef INC_PKT_PARSE_H_
#define INC_PKT_PARSE_H_

#include <stdint.h>
#include <stdbool.h>

/* ------------------------------------------------------------------------- */
/* Configuration                                                             */
/* ------------------------------------------------------------------------- */

#define ETH_MAC_LEN         (6u)    /**< Bytes in a MAC address.                 */
#define ETH_HDR_LEN         (14u)   /**< dst MAC (6) + src MAC (6) + EtherType (2). */

#define ETHERTYPE_IPV4      (0x0800u)
#define ETHERTYPE_ARP       (0x0806u)
#define ETHERTYPE_IPV6      (0x86DDu)

/* ------------------------------------------------------------------------- */
/* Types                                                                     */
/* ------------------------------------------------------------------------- */

/**
 * @brief Header fields extracted from one frame, in host byte order.
 *
 * Filled by the parser, read by the filter. Holds copies of a few fields,
 * not the frame itself.
 */
typedef struct
{
    uint8_t  dst_mac[ETH_MAC_LEN];
    uint8_t  src_mac[ETH_MAC_LEN];
    uint16_t ethertype;
} pkt_hdr_t;

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

/**
 * @brief  Parse the Ethernet header at the start of a frame.
 * @param  frame  First byte of the frame (destination MAC).
 * @param  len    Frame length in bytes.
 * @param  out    Filled with the parsed fields on success.
 * @return true on success, false if the frame is too short (*out untouched).
 */
bool pkt_parse_eth(const uint8_t *frame, uint16_t len, pkt_hdr_t *out);

#endif /* INC_PKT_PARSE_H_ */
