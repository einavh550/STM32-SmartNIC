/**
 * @file    pkt_filter.h
 * @brief   Rule-based packet filter on parsed header fields.
 *
 * @note    Rules are checked in order and the first match decides the action,
 *          like a firewall rule list. If no rule matches, the default action
 *          is used. Pure C, no HAL, so it can be unit-tested on a PC.
 */

#ifndef INC_PKT_FILTER_H_
#define INC_PKT_FILTER_H_

#include <stdint.h>
#include "pkt_parse.h"

/* ------------------------------------------------------------------------- */
/* Configuration                                                             */
/* ------------------------------------------------------------------------- */

/* Bits of pkt_rule_t.match: which fields the rule compares. Fields whose bit
 * is not set are ignored ("any"). match = 0 matches every frame. */
#define RULE_ETHERTYPE      (1u << 0)
#define RULE_IP_PROTO       (1u << 1)
#define RULE_SRC_IP         (1u << 2)
#define RULE_DST_IP         (1u << 3)
#define RULE_SRC_PORT       (1u << 4)
#define RULE_DST_PORT       (1u << 5)

/* ------------------------------------------------------------------------- */
/* Types                                                                     */
/* ------------------------------------------------------------------------- */

typedef enum
{
    PKT_PASS = 0,
    PKT_DROP
} pkt_action_t;

/**
 * @brief One filter rule.
 *
 * IP addresses are compared under a mask, so one rule can cover a subnet:
 * src_ip = 192.168.7.0 with src_mask = 255.255.255.0 matches 192.168.7.x.
 * Use mask 0xFFFFFFFF for a single address.
 */
typedef struct
{
    uint32_t     match;      /**< RULE_* bits.                         */
    pkt_action_t action;     /**< What to do with a matching frame.    */
    uint32_t     src_ip;
    uint32_t     src_mask;
    uint32_t     dst_ip;
    uint32_t     dst_mask;
    uint16_t     ethertype;
    uint16_t     src_port;
    uint16_t     dst_port;
    uint8_t      ip_proto;
} pkt_rule_t;

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

/**
 * @brief  Decide what to do with one parsed frame.
 * @param  rules           Rule list, checked from index 0.
 * @param  count           Number of rules.
 * @param  default_action  Used when no rule matches.
 * @param  hdr             Parsed headers (pkt_parse_* must have run first).
 * @param  rule_idx        Set to the index of the matching rule, or -1 if the
 *                         default action was used. Lets the caller keep
 *                         per-rule hit counters while the rule table stays const.
 * @return Action of the first matching rule, or default_action.
 */
pkt_action_t pkt_filter_eval(const pkt_rule_t *rules, uint32_t count,
                             pkt_action_t default_action, const pkt_hdr_t *hdr,
                             int32_t *rule_idx);

#endif /* INC_PKT_FILTER_H_ */
