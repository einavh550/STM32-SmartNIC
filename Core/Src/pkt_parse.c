/**
 * @file    pkt_parse.c
 * @brief   Header parser implementation.
 *
 * @note    Fields are read byte by byte instead of casting a struct over the
 *          buffer: no packing or alignment assumptions, and the network
 *          (big-endian) to host (little-endian) conversion is explicit.
 */

#include <string.h>
#include "pkt_parse.h"

/** Read a 16-bit big-endian (network order) value. */
static uint16_t rd_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/** Read a 32-bit big-endian (network order) value. */
static uint32_t rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

bool pkt_parse_eth(const uint8_t *frame, uint16_t len, pkt_hdr_t *out)
{
    /* Never read past the end of the frame. */
    if (len < ETH_HDR_LEN)
    {
        return false;
    }

    memcpy(out->dst_mac, &frame[0], ETH_MAC_LEN);
    memcpy(out->src_mac, &frame[6], ETH_MAC_LEN);
    out->ethertype = rd_be16(&frame[12]);
    out->valid     = PKT_HAS_ETH;   /* new frame: forget the upper layers of the last one */

    return true;
}

bool pkt_parse_ipv4(const uint8_t *frame, uint16_t len, pkt_hdr_t *out)
{
    /* Room for at least the fixed 20-byte part of the header. */
    if (len < ETH_HDR_LEN + IPV4_MIN_HDR_LEN)
    {
        return false;
    }

    const uint8_t *ip = &frame[ETH_HDR_LEN];

    /* Byte 0 holds two 4-bit fields: version (high) and header length (low),
     * where the length is counted in 32-bit words. */
    const uint8_t  version = ip[0] >> 4;
    const uint16_t hdr_len = (uint16_t)((ip[0] & 0x0Fu) * 4u);

    if ((version != 4u) || (hdr_len < IPV4_MIN_HDR_LEN))
    {
        return false;
    }

    /* Options can make the header longer than 20 bytes: check it all fits. */
    if (len < ETH_HDR_LEN + hdr_len)
    {
        return false;
    }

    out->ip_proto  = ip[9];
    out->src_ip    = rd_be32(&ip[12]);
    out->dst_ip    = rd_be32(&ip[16]);
    out->l4_offset = (uint16_t)(ETH_HDR_LEN + hdr_len);

    /* Bytes 6-7: 3 flag bits, then a 13-bit fragment offset. */
    out->ip_frag_off = rd_be16(&ip[6]) & 0x1FFFu;
    out->valid      |= PKT_HAS_IPV4;

    return true;
}

bool pkt_parse_l4(const uint8_t *frame, uint16_t len, pkt_hdr_t *out)
{
    uint16_t min_hdr_len;

    if (out->ip_proto == IP_PROTO_UDP)
    {
        min_hdr_len = UDP_HDR_LEN;
    }
    else if (out->ip_proto == IP_PROTO_TCP)
    {
        min_hdr_len = TCP_MIN_HDR_LEN;
    }
    else
    {
        return false;
    }

    /* Only the first fragment of a split IP packet carries the TCP/UDP header.
     * In the others, the bytes at l4_offset are payload, not ports. */
    if (out->ip_frag_off != 0u)
    {
        return false;
    }

    if (len < out->l4_offset + min_hdr_len)
    {
        return false;
    }

    /* TCP and UDP both start with: source port (2 bytes), destination port (2 bytes). */
    const uint8_t *l4 = &frame[out->l4_offset];

    out->src_port = rd_be16(&l4[0]);
    out->dst_port = rd_be16(&l4[2]);
    out->valid   |= PKT_HAS_L4;

    return true;
}
