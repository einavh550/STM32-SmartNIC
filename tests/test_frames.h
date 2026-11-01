/**
 * @file    test_frames.h
 * @brief   Build fake Ethernet frames byte by byte for the tests.
 *
 * Values are written big-endian (network order), exactly as they arrive on
 * the wire, so the parser sees the same bytes as on the board.
 */

#ifndef TESTS_TEST_FRAMES_H_
#define TESTS_TEST_FRAMES_H_

#include <stdint.h>
#include <string.h>
#include "pkt_parse.h"
#include "pkt_filter.h"

/** Make an IPv4 address: IP4(192,168,7,1) = 0xC0A80701. */
#define IP4(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

static inline void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void wr_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/** Ethernet header: dst = broadcast, src = 02:00:00:00:00:01. Returns 14. */
static inline uint16_t build_eth(uint8_t *f, uint16_t ethertype)
{
    static const uint8_t src[ETH_MAC_LEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

    memset(&f[0], 0xFF, ETH_MAC_LEN);
    memcpy(&f[6], src, ETH_MAC_LEN);
    wr_be16(&f[12], ethertype);
    return ETH_HDR_LEN;
}

/** Ethernet + 20-byte IPv4 header (no options). Returns 34 = start of L4. */
static inline uint16_t build_ipv4(uint8_t *f, uint8_t proto, uint32_t src, uint32_t dst)
{
    uint8_t *ip = &f[build_eth(f, ETHERTYPE_IPV4)];

    memset(ip, 0, IPV4_MIN_HDR_LEN);
    ip[0] = 0x45;               /* version 4, IHL 5 (= 20 bytes)   */
    ip[8] = 64;                 /* TTL                             */
    ip[9] = proto;
    wr_be32(&ip[12], src);
    wr_be32(&ip[16], dst);
    return ETH_HDR_LEN + IPV4_MIN_HDR_LEN;
}

/** Ethernet + IPv4 + 8-byte UDP header. Returns the frame length (42). */
static inline uint16_t build_udp(uint8_t *f, uint32_t src, uint32_t dst,
                                 uint16_t sport, uint16_t dport)
{
    uint8_t *l4 = &f[build_ipv4(f, IP_PROTO_UDP, src, dst)];

    memset(l4, 0, UDP_HDR_LEN);
    wr_be16(&l4[0], sport);
    wr_be16(&l4[2], dport);
    wr_be16(&l4[4], UDP_HDR_LEN);
    return ETH_HDR_LEN + IPV4_MIN_HDR_LEN + UDP_HDR_LEN;
}

/** Ethernet + IPv4 + 20-byte TCP header. Returns the frame length (54). */
static inline uint16_t build_tcp(uint8_t *f, uint32_t src, uint32_t dst,
                                 uint16_t sport, uint16_t dport)
{
    uint8_t *l4 = &f[build_ipv4(f, IP_PROTO_TCP, src, dst)];

    memset(l4, 0, TCP_MIN_HDR_LEN);
    wr_be16(&l4[0], sport);
    wr_be16(&l4[2], dport);
    l4[12] = 0x50;              /* data offset 5 (= 20 bytes)      */
    l4[13] = 0x02;              /* SYN                             */
    return ETH_HDR_LEN + IPV4_MIN_HDR_LEN + TCP_MIN_HDR_LEN;
}

/** Same parse chain as the main loop in main.c. */
static inline bool parse_all(const uint8_t *f, uint16_t len, pkt_hdr_t *hdr)
{
    if (!pkt_parse_eth(f, len, hdr))
    {
        return false;
    }
    if ((hdr->ethertype == ETHERTYPE_IPV4) && pkt_parse_ipv4(f, len, hdr))
    {
        (void)pkt_parse_l4(f, len, hdr);
    }
    return true;
}

#endif /* TESTS_TEST_FRAMES_H_ */
