/**
 * @file    pkt_reflect.h
 * @brief   Turn a received UDP frame into its reply, in place (Phase 6).
 *
 * Pure C, no HAL: the same file is compiled for the board and for the host
 * tests.
 *
 * The board is a "reflector": a UDP frame that passed the filter goes back
 * to its sender with source and destination swapped (MAC, IPv4, port). The
 * buffer is rewritten in place and sent as it is: zero-copy.
 *
 * No checksum is recomputed. The IPv4 header checksum and the UDP checksum
 * are one's-complement SUMS of 16-bit words, and a sum does not depend on
 * the order of its terms: swapping src and dst IP (both in the IPv4 header
 * and in the UDP pseudo-header) and swapping the two ports leaves both sums,
 * and so both checksums, unchanged. The Ethernet CRC is added by the MAC.
 */

#ifndef INC_PKT_REFLECT_H_
#define INC_PKT_REFLECT_H_

#include <stdbool.h>
#include <stdint.h>
#include "pkt_parse.h"

/**
 * @brief  Rewrite frame into the reply to its sender.
 * @param  frame   the received frame (modified in place on success)
 * @param  len     its length
 * @param  hdr     what pkt_parse_frame() / the filter found in it
 * @param  my_mac  the board's MAC: becomes the source MAC
 * @param  my_ip   the board's IPv4 address
 * @return true if rewritten. false (frame untouched) if the frame is not
 *         reflected: not IPv4 + UDP, not sent to my_ip (broadcast,
 *         multicast, someone else), or an IP fragment.
 *
 * Only UDP is reflected: a reflected TCP segment or ICMP echo would make the
 * sender's stack answer again (RST, echo reply), traffic nobody asked for.
 */
bool pkt_reflect_udp(uint8_t *frame, uint16_t len, const pkt_hdr_t *hdr,
                     const uint8_t my_mac[ETH_MAC_LEN], uint32_t my_ip);

#endif /* INC_PKT_REFLECT_H_ */
