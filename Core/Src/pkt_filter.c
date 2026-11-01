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
    const uint32_t l4_fields = RULE_SRC_PORT | RULE_DST_PORT;

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

    memset(f, 0, sizeof(*f));         /* all counters start at 0 */
    f->rules          = rules;
    f->rule_count     = count;
    f->default_action = default_action;

    return true;
}

pkt_verdict_t pkt_filter_process(pkt_filter_t *f, const uint8_t *frame, uint16_t len,
                                 pkt_hdr_t *hdr)
{
    /* Start from "malformed": that is the answer if parsing fails. */
    pkt_verdict_t v = { .action = PKT_DROP, .reason = DROP_REASON_MALFORMED, .rule_idx = -1 };

    /* Stage 1: sanity. A broken frame never reaches the rules. */
    if (pkt_parse_frame(frame, len, hdr))
    {
        /* Stage 2: the rule table. */
        v.action = pkt_filter_eval(f->rules, f->rule_count, f->default_action, hdr, &v.rule_idx);

        if (v.rule_idx >= 0)
        {
            f->rule_hits[v.rule_idx]++;
            v.reason = DROP_REASON_RULE;
        }
        else
        {
            f->default_hits++;
            v.reason = DROP_REASON_DEFAULT;
        }

        if (v.action == PKT_PASS)
        {
            v.reason = DROP_REASON_NONE;
        }
    }

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
        case DROP_REASON_RULE:      return "rule";
        case DROP_REASON_DEFAULT:   return "default";
        default:                    return "?";
    }
}
