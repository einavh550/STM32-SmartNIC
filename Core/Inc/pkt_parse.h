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

#define IPV4_MIN_HDR_LEN    (20u)   /**< IPv4 header without options.            */

#define IP_PROTO_ICMP       (1u)
#define IP_PROTO_TCP        (6u)
#define IP_PROTO_UDP        (17u)

#define UDP_HDR_LEN         (8u)
#define TCP_MIN_HDR_LEN     (20u)   /**< TCP header without options.             */

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

    /* IPv4, valid only after pkt_parse_ipv4() returned true. */
    uint32_t src_ip;       /**< e.g. 192.168.1.5 is 0xC0A80105.                 */
    uint32_t dst_ip;
    uint8_t  ip_proto;     /**< What follows the IP header: TCP, UDP, ICMP...   */
    uint16_t l4_offset;    /**< Offset of the TCP/UDP header from frame start.  */
    uint16_t ip_frag_off;  /**< Fragment offset in 8-byte units, 0 = first piece. */

    /* TCP/UDP, valid only after pkt_parse_l4() returned true. */
    uint16_t src_port;
    uint16_t dst_port;
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

/**
 * @brief  Parse the IPv4 header that follows the Ethernet header.
 * @note   Call only after pkt_parse_eth() succeeded and out->ethertype is IPv4.
 *         VLAN-tagged frames are not supported yet.
 * @return true on success, false if the header is truncated or invalid.
 */
bool pkt_parse_ipv4(const uint8_t *frame, uint16_t len, pkt_hdr_t *out);

/**
 * @brief  Read the source and destination ports of a TCP or UDP header.
 * @note   Call only after pkt_parse_ipv4() succeeded.
 * @return true on success, false if the protocol is not TCP/UDP, the packet is
 *         a non-first fragment (no L4 header in it), or the header is truncated.
 */
bool pkt_parse_l4(const uint8_t *frame, uint16_t len, pkt_hdr_t *out);

#endif /* INC_PKT_PARSE_H_ */
