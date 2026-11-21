/**
 * @file    pkt_reflect.c
 * @brief   Turn a received UDP frame into its reply, in place (Phase 6).
 */

#include "pkt_reflect.h"
#include <string.h>

/* Swap n bytes between a and b (non-overlapping). */
static void swap_bytes(uint8_t *a, uint8_t *b, uint32_t n)
{
    for (uint32_t i = 0u; i < n; i++)
    {
        uint8_t t = a[i];
        a[i] = b[i];
        b[i] = t;
    }
}

bool pkt_reflect_udp(uint8_t *frame, uint16_t len, const pkt_hdr_t *hdr,
                     const uint8_t my_mac[ETH_MAC_LEN], uint32_t my_ip)
{
    /* Only a fully parsed IPv4 UDP frame, sent to us (unicast). */
    if (((hdr->valid & PKT_HAS_L4) == 0u) || (hdr->ip_proto != IP_PROTO_UDP) ||
        (hdr->dst_ip != my_ip))
    {
        return false;
    }

    uint8_t *ip = &frame[ETH_HDR_LEN];

    /* Not a fragment: no offset, and no "more fragments" bit (flags byte,
     * bit 0x20). Reflecting one piece of a datagram makes no sense. */
    if ((hdr->ip_frag_off != 0u) || ((ip[6] & 0x20u) != 0u))
    {
        return false;
    }

    /* The parser guarantees the UDP header fits inside the frame; check the
     * last byte we touch anyway, so this function is safe on its own. */
    if ((uint32_t)hdr->l4_offset + 4u > len)
    {
        return false;
    }

    /* Ethernet: back to the sender, from us. */
    memcpy(&frame[0], &frame[6], ETH_MAC_LEN);  /* dst = old src */
    memcpy(&frame[6], my_mac, ETH_MAC_LEN);     /* src = us      */

    /* IPv4 source <-> destination (bytes 12..15 and 16..19 of the header).
     * Header checksum unchanged (see pkt_reflect.h). TTL kept: the board
     * answers like an end host, it does not route. */
    swap_bytes(&ip[12], &ip[16], 4u);

    /* UDP source port <-> destination port. UDP checksum unchanged. */
    uint8_t *udp = &frame[hdr->l4_offset];
    swap_bytes(&udp[0], &udp[2], 2u);

    return true;
}
