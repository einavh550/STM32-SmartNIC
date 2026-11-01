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

    /* Bytes 2-3: total length = IP header + everything after it. It comes from
     * the sender, so it can lie:
     * - smaller than the header itself: impossible, the packet is broken;
     * - larger than what arrived: the packet was cut, or someone wants us to
     *   read past the end of the buffer.
     * The frame MAY be longer than 14 + total_len: Ethernet pads short frames
     * up to 60 bytes, and those padding bytes are not part of the packet.
     * Since total_len >= hdr_len, this also checks that the options fit. */
    const uint16_t total_len = rd_be16(&ip[2]);

    if ((total_len < hdr_len) || (len < ETH_HDR_LEN + total_len))
    {
        return false;
    }

    out->ip_total_len = total_len;
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

    /* The TCP/UDP header must fit inside the IP packet, not only inside the
     * frame: otherwise we would read Ethernet padding bytes as ports.
     * pkt_parse_ipv4() already checked ip_end <= len; checking again is cheap
     * and keeps this function safe on its own. */
    const uint16_t ip_end = (uint16_t)(ETH_HDR_LEN + out->ip_total_len);

    if ((ip_end > len) || (ip_end < out->l4_offset + min_hdr_len))
    {
        return false;
    }

    const uint8_t *l4 = &frame[out->l4_offset];

    if (out->ip_proto == IP_PROTO_TCP)
    {
        /* Byte 12, high 4 bits: TCP header length in 32-bit words (like IHL).
         * Below 5 is impossible; it must also fit inside the IP packet. */
        const uint16_t tcp_hdr_len = (uint16_t)((l4[12] >> 4) * 4u);

        if ((tcp_hdr_len < TCP_MIN_HDR_LEN) || (ip_end < out->l4_offset + tcp_hdr_len))
        {
            return false;
        }

        out->tcp_flags = l4[13];       /* byte 13: CWR ECE URG ACK PSH RST SYN FIN */
    }
    else
    {
        out->tcp_flags = 0u;
    }

    /* TCP and UDP both start with: source port (2 bytes), destination port (2 bytes). */
    out->src_port = rd_be16(&l4[0]);
    out->dst_port = rd_be16(&l4[2]);
    out->valid   |= PKT_HAS_L4;

    return true;
}

bool pkt_parse_frame(const uint8_t *frame, uint16_t len, pkt_hdr_t *out)
{
    /* pkt_parse_eth() leaves *out untouched on failure: clear the layer bits
     * here so nothing from the previous frame survives. */
    out->valid = 0u;

    if (!pkt_parse_eth(frame, len, out))
    {
        return false;                 /* not even an Ethernet header */
    }

    if (out->ethertype != ETHERTYPE_IPV4)
    {
        return true;                  /* ARP, IPv6...: nothing more we parse */
    }

    if (!pkt_parse_ipv4(frame, len, out))
    {
        return false;                 /* says IPv4, but the header is broken */
    }

    /* Overlapping-fragment attack (RFC 1858): a TCP fragment at offset 1
     * (= byte 8) rewrites the TCP flags of the first fragment after a
     * firewall already checked them. No real sender does this. */
    if ((out->ip_proto == IP_PROTO_TCP) && (out->ip_frag_off == 1u))
    {
        return false;
    }

    const bool has_ports = ((out->ip_proto == IP_PROTO_TCP) || (out->ip_proto == IP_PROTO_UDP)) &&
                           (out->ip_frag_off == 0u);

    if (has_ports)
    {
        /* false = the TCP/UDP header does not fit in the packet. For a first
         * fragment this also blocks the "tiny fragment" attack (RFC 1858):
         * a TCP header split so its flags land in the second fragment. */
        return pkt_parse_l4(frame, len, out);
    }

    return true;                      /* ICMP, or a later fragment: no ports */
}
