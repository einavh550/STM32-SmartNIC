/**
 * @file    pkt_filter.c
 * @brief   Rule-based packet filter implementation.
 *
 * @note    A rule that asks about a layer the frame does not have never
 *          matches: a "UDP port 5000" rule must not match an ARP frame just
 *          because the port field holds an old or zero value.
 */

#include <stdbool.h>
#include <string.h>
#include "pkt_filter.h"

static bool rule_matches(const pkt_rule_t *r, const pkt_hdr_t *hdr)
{
    const uint32_t ip_fields = RULE_IP_PROTO | RULE_SRC_IP | RULE_DST_IP;
    const uint32_t l4_fields = RULE_SRC_PORT | RULE_DST_PORT | RULE_TCP_FLAGS;

    /* First: does the frame have every layer this rule looks at? */
    if (((r->match & RULE_ETHERTYPE) != 0u) && ((hdr->valid & PKT_HAS_ETH) == 0u))
    {
        return false;
    }
    if (((r->match & ip_fields) != 0u) && ((hdr->valid & PKT_HAS_IPV4) == 0u))
    {
        return false;
    }
    if (((r->match & l4_fields) != 0u) && ((hdr->valid & PKT_HAS_L4) == 0u))
    {
        return false;
    }

    /* Then: compare each field the rule asks about. */
    if (((r->match & RULE_ETHERTYPE) != 0u) && (hdr->ethertype != r->ethertype))
    {
        return false;
    }
    if (((r->match & RULE_IP_PROTO) != 0u) && (hdr->ip_proto != r->ip_proto))
    {
        return false;
    }
    if (((r->match & RULE_SRC_IP) != 0u) && ((hdr->src_ip & r->src_mask) != (r->src_ip & r->src_mask)))
    {
        return false;
    }
    if (((r->match & RULE_DST_IP) != 0u) && ((hdr->dst_ip & r->dst_mask) != (r->dst_ip & r->dst_mask)))
    {
        return false;
    }
    if (((r->match & RULE_SRC_PORT) != 0u) && (hdr->src_port != r->src_port))
    {
        return false;
    }
    if (((r->match & RULE_DST_PORT) != 0u) && (hdr->dst_port != r->dst_port))
    {
        return false;
    }
    if ((r->match & RULE_TCP_FLAGS) != 0u)
    {
        /* UDP has no flags: a flags rule only ever matches TCP. */
        if ((hdr->ip_proto != IP_PROTO_TCP) ||
            ((hdr->tcp_flags & r->tcp_flags_mask) != (r->tcp_flags & r->tcp_flags_mask)))
        {
            return false;
        }
    }

    return true;
}

/* Valid TCP flag combinations, indexed by FIN|SYN|RST|ACK|URG (5 bits = 32
 * entries). Same whitelist idea as the Linux connection tracker
 * (nf_conntrack_proto_tcp.c): anything not listed is never sent by a real
 * TCP stack, only by scanners. One table lookup per TCP frame. */
#define TCP_FLAGS_CHECKED  (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK | TCP_FLAG_URG)

static const bool tcp_valid_flags[TCP_FLAGS_CHECKED + 1u] =
{
    [TCP_FLAG_SYN]                               = true,  /* connect          */
    [TCP_FLAG_SYN | TCP_FLAG_URG]                = true,
    [TCP_FLAG_SYN | TCP_FLAG_ACK]                = true,  /* accept           */
    [TCP_FLAG_RST]                               = true,  /* refuse / abort   */
    [TCP_FLAG_RST | TCP_FLAG_ACK]                = true,
    [TCP_FLAG_FIN | TCP_FLAG_ACK]                = true,  /* close            */
    [TCP_FLAG_FIN | TCP_FLAG_ACK | TCP_FLAG_URG] = true,
    [TCP_FLAG_ACK]                               = true,  /* data / ack       */
    [TCP_FLAG_ACK | TCP_FLAG_URG]                = true,
};

bool pkt_tcp_flags_valid(uint8_t flags)
{
    /* PSH, ECE and CWR may appear with any valid combination: ignore them. */
    return tcp_valid_flags[flags & TCP_FLAGS_CHECKED];
}

#define IPV4_ANY            (0x00000000u)   /* 0.0.0.0                     */
#define IPV4_LOOPBACK_NET   (0x7F000000u)   /* 127.0.0.0/8                 */
#define IPV4_LOOPBACK_MASK  (0xFF000000u)
#define IPV4_MULTICAST_MIN  (0xE0000000u)   /* 224.0.0.0: multicast, then
                                               reserved, then broadcast    */
#define MAC_GROUP_BIT       (0x01u)         /* I/G bit of the first byte   */
#define DHCP_CLIENT_PORT    (68u)
#define DHCP_SERVER_PORT    (67u)

static bool is_dhcp_request(const pkt_hdr_t *hdr)
{
    return ((hdr->valid & PKT_HAS_L4) != 0u) && (hdr->ip_proto == IP_PROTO_UDP) &&
           (hdr->src_port == DHCP_CLIENT_PORT) && (hdr->dst_port == DHCP_SERVER_PORT);
}

bool pkt_src_is_spoofed(const pkt_hdr_t *hdr)
{
    /* Ethernet: the first bit sent says "group address". A source is always
     * one network card, never a group. Checked for every frame, ARP too. */
    if ((hdr->src_mac[0] & MAC_GROUP_BIT) != 0u)
    {
        return true;
    }

    if ((hdr->valid & PKT_HAS_IPV4) == 0u)
    {
        return false;
    }

    if ((hdr->src_ip & IPV4_LOOPBACK_MASK) == IPV4_LOOPBACK_NET)
    {
        return true;
    }
    if (hdr->src_ip >= IPV4_MULTICAST_MIN)
    {
        return true;
    }
    if (hdr->src_ip == IPV4_ANY)
    {
        return !is_dhcp_request(hdr);
    }

    return hdr->src_ip == hdr->dst_ip;            /* LAND attack */
}

#define MILLI_PER_TOKEN     (1000u)

bool pkt_bucket_take(pkt_bucket_t *b, uint16_t rate_pps, uint16_t burst, uint32_t now_ms)
{
    const uint32_t full = (uint32_t)burst * MILLI_PER_TOKEN;

    if (!b->started)
    {
        b->started      = true;
        b->tokens_milli = full;                   /* a new bucket starts full */
    }
    else
    {
        /* ms * (frames / s) = thousandths of a frame: exact, no division.
         * Unsigned subtraction stays correct when now_ms wraps at 2^32, and
         * 64-bit math cannot overflow even after days of silence. */
        const uint32_t elapsed = now_ms - b->last_ms;
        const uint64_t tokens  = (uint64_t)b->tokens_milli + ((uint64_t)elapsed * rate_pps);

        b->tokens_milli = (tokens > full) ? full : (uint32_t)tokens;
    }
    b->last_ms = now_ms;

    if (b->tokens_milli < MILLI_PER_TOKEN)
    {
        return false;                             /* empty: over the rate     */
    }
    b->tokens_milli -= MILLI_PER_TOKEN;
    return true;
}

pkt_action_t pkt_filter_eval(const pkt_rule_t *rules, uint32_t count,
                             pkt_action_t default_action, const pkt_hdr_t *hdr,
                             int32_t *rule_idx)
{
    for (uint32_t i = 0u; i < count; i++)
    {
        if (rule_matches(&rules[i], hdr))
        {
            *rule_idx = (int32_t)i;
            return rules[i].action;
        }
    }

    *rule_idx = -1;
    return default_action;
}

bool pkt_filter_init(pkt_filter_t *f, const pkt_rule_t *rules, uint32_t count,
                     pkt_action_t default_action)
{
    if (count > PKT_FILTER_MAX_RULES)
    {
        return false;
    }
    for (uint32_t i = 0u; i < count; i++)
    {
        if ((rules[i].action == PKT_RATE_LIMIT) && ((rules[i].rate_pps == 0u) || (rules[i].burst == 0u)))
        {
            return false;             /* a bucket that never holds a token */
        }
    }

    memset(f, 0, sizeof(*f));         /* counters 0, buckets not started */
    f->rules          = rules;
    f->rule_count     = count;
    f->default_action = default_action;

    return true;
}

/* The pipeline: each stage either decides (return) or hands over to the next.
 * Cheap, always-on checks come first, so no rule can let a bad frame through. */
static pkt_verdict_t decide(pkt_filter_t *f, const uint8_t *frame, uint16_t len,
                            uint32_t now_ms, pkt_hdr_t *hdr)
{
    pkt_verdict_t v = { .action = PKT_DROP, .reason = DROP_REASON_MALFORMED, .rule_idx = -1 };

    /* Stage 1: sanity. */
    if (!pkt_parse_frame(frame, len, hdr))
    {
        return v;                                 /* DROP, malformed */
    }

    /* Stage 2: anti-spoofing. */
    if (pkt_src_is_spoofed(hdr))
    {
        v.reason = DROP_REASON_SPOOFED;
        return v;                                 /* DROP, spoofed */
    }

    /* Stage 3: TCP scan detection. */
    if (((hdr->valid & PKT_HAS_L4) != 0u) && (hdr->ip_proto == IP_PROTO_TCP) &&
        !pkt_tcp_flags_valid(hdr->tcp_flags))
    {
        v.reason = DROP_REASON_TCP_SCAN;
        return v;                                 /* DROP, tcp-scan */
    }

    /* Stage 4: the rule table. */
    v.action = pkt_filter_eval(f->rules, f->rule_count, f->default_action, hdr, &v.rule_idx);

    if (v.action == PKT_RATE_LIMIT)               /* only a rule can say this */
    {
        const pkt_rule_t *r = &f->rules[v.rule_idx];

        if (!pkt_bucket_take(&f->buckets[v.rule_idx], r->rate_pps, r->burst, now_ms))
        {
            v.action = PKT_DROP;
            v.reason = DROP_REASON_RATE_LIMIT;
            return v;                             /* DROP, rate-limit */
        }
        v.action = PKT_PASS;
    }

    if (v.action == PKT_PASS)
    {
        v.reason = DROP_REASON_NONE;
    }
    else
    {
        v.reason = (v.rule_idx >= 0) ? DROP_REASON_RULE : DROP_REASON_DEFAULT;
    }

    return v;
}

pkt_verdict_t pkt_filter_process(pkt_filter_t *f, const uint8_t *frame, uint16_t len,
                                 uint32_t now_ms, pkt_hdr_t *hdr)
{
    const pkt_verdict_t v = decide(f, frame, len, now_ms, hdr);

    /* Rule statistics: only frames that reached the rule table. */
    if (v.rule_idx >= 0)
    {
        f->rule_hits[v.rule_idx]++;
    }
    else if ((v.action == PKT_PASS) || (v.reason == DROP_REASON_DEFAULT))
    {
        f->default_hits++;
    }

    /* Totals. */
    if (v.action == PKT_PASS)
    {
        f->passed++;
    }
    else
    {
        f->dropped[v.reason]++;
    }

    return v;
}

const char *pkt_drop_reason_name(pkt_drop_reason_t reason)
{
    switch (reason)
    {
        case DROP_REASON_NONE:      return "none";
        case DROP_REASON_MALFORMED: return "malformed";
        case DROP_REASON_SPOOFED:   return "spoofed";
        case DROP_REASON_TCP_SCAN:  return "tcp-scan";
        case DROP_REASON_RATE_LIMIT: return "rate-limit";
        case DROP_REASON_RULE:      return "rule";
        case DROP_REASON_DEFAULT:   return "default";
        default:                    return "?";
    }
}
