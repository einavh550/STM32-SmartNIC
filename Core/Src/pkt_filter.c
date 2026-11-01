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

    memset(f, 0, sizeof(*f));         /* all counters start at 0 */
    f->rules          = rules;
    f->rule_count     = count;
    f->default_action = default_action;

    return true;
}

/* The pipeline: each stage either decides (return) or hands over to the next.
 * Cheap, always-on checks come first, so no rule can let a bad frame through. */
static pkt_verdict_t decide(const pkt_filter_t *f, const uint8_t *frame, uint16_t len,
                            pkt_hdr_t *hdr)
{
    pkt_verdict_t v = { .action = PKT_DROP, .reason = DROP_REASON_MALFORMED, .rule_idx = -1 };

    /* Stage 1: sanity. */
    if (!pkt_parse_frame(frame, len, hdr))
    {
        return v;                                 /* DROP, malformed */
    }

    /* Stage 2: TCP scan detection. */
    if (((hdr->valid & PKT_HAS_L4) != 0u) && (hdr->ip_proto == IP_PROTO_TCP) &&
        !pkt_tcp_flags_valid(hdr->tcp_flags))
    {
        v.reason = DROP_REASON_TCP_SCAN;
        return v;                                 /* DROP, tcp-scan */
    }

    /* Stage 3: the rule table. */
    v.action = pkt_filter_eval(f->rules, f->rule_count, f->default_action, hdr, &v.rule_idx);

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
                                 pkt_hdr_t *hdr)
{
    const pkt_verdict_t v = decide(f, frame, len, hdr);

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
        case DROP_REASON_TCP_SCAN:  return "tcp-scan";
        case DROP_REASON_RULE:      return "rule";
        case DROP_REASON_DEFAULT:   return "default";
        default:                    return "?";
    }
}
