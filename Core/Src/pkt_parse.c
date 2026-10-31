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

    return true;
}
