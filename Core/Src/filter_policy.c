/**
 * @file    filter_policy.c
 * @brief   The filter policy for the BeagleBone Black test link.
 *
 * Default deny: only what is listed here may reach the board. Before this
 * table runs, the fixed stages already dropped malformed frames, spoofed
 * sources and TCP scans.
 *
 * Ingress filtering (BCP 38): every IP rule requires a source inside the link
 * subnet, so a packet from any other address falls through to the default
 * DROP. Rate numbers are first guesses, to be tuned with measurements on the
 * BBB (Phase 4).
 */

#include "filter_policy.h"

/* Every IP rule: from the link subnet, to the board. */
#define FROM_LINK_TO_BOARD                                              \
    .src_ip = POLICY_NET,       .src_mask = POLICY_NET_MASK,            \
    .dst_ip = POLICY_BOARD_IP,  .dst_mask = 0xFFFFFFFFu

#define MATCH_LINK_TO_BOARD     (RULE_SRC_IP | RULE_DST_IP)

const pkt_rule_t filter_policy[POLICY_RULE_COUNT] =
{
    /* ARP is needed to find each other's MAC. It has no IP header to check,
     * so it is only rate-limited: protects against ARP storms. */
    [POLICY_ARP] =
    {
        .match = RULE_ETHERTYPE, .ethertype = ETHERTYPE_ARP,
        .action = PKT_RATE_LIMIT, .rate_pps = 20u, .burst = 10u,
    },

    /* ping: allowed, but a ping flood is cut to 10/s. */
    [POLICY_PING] =
    {
        .match = MATCH_LINK_TO_BOARD | RULE_IP_PROTO, FROM_LINK_TO_BOARD,
        .ip_proto = IP_PROTO_ICMP,
        .action = PKT_RATE_LIMIT, .rate_pps = 10u, .burst = 5u,
    },

    /* New connection to the service (SYN without ACK): SYN flood limit. */
    [POLICY_TCP_NEW] =
    {
        .match = MATCH_LINK_TO_BOARD | RULE_IP_PROTO | RULE_DST_PORT | RULE_TCP_FLAGS,
        FROM_LINK_TO_BOARD,
        .ip_proto = IP_PROTO_TCP, .dst_port = POLICY_TCP_PORT,
        .tcp_flags = TCP_FLAG_SYN, .tcp_flags_mask = TCP_FLAG_SYN | TCP_FLAG_ACK,
        .action = PKT_RATE_LIMIT, .rate_pps = 20u, .burst = 5u,
    },

    /* Everything else of that service (ACK, data, FIN, RST): pass. Scans
     * never get here, the TCP scan stage already dropped them. */
    [POLICY_TCP] =
    {
        .match = MATCH_LINK_TO_BOARD | RULE_IP_PROTO | RULE_DST_PORT, FROM_LINK_TO_BOARD,
        .ip_proto = IP_PROTO_TCP, .dst_port = POLICY_TCP_PORT,
        .action = PKT_PASS,
    },

    /* UDP test stream for throughput measurements: no limit, so the
     * measurement shows the board's real speed, not the limiter's. */
    [POLICY_UDP_TEST] =
    {
        .match = MATCH_LINK_TO_BOARD | RULE_IP_PROTO | RULE_DST_PORT, FROM_LINK_TO_BOARD,
        .ip_proto = IP_PROTO_UDP, .dst_port = POLICY_UDP_TEST_PORT,
        .action = PKT_PASS,
    },
};

_Static_assert(POLICY_RULE_COUNT <= PKT_FILTER_MAX_RULES, "policy has too many rules");

const char *filter_policy_rule_name(int32_t rule_idx)
{
    switch (rule_idx)
    {
        case POLICY_ARP:      return "arp";
        case POLICY_PING:     return "ping";
        case POLICY_TCP_NEW:  return "tcp-new";
        case POLICY_TCP:      return "tcp";
        case POLICY_UDP_TEST: return "udp-test";
        default:              return "default";
    }
}
