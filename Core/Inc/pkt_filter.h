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
#define RULE_TCP_FLAGS      (1u << 6)   /**< TCP only: (flags & mask) == value. */

/** Most rules one filter can hold (size of the per-rule hit counter array). */
#define PKT_FILTER_MAX_RULES    (16u)

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
 *
 * TCP flags are compared the same way: tcp_flags_mask picks the bits to look
 * at, tcp_flags says what they must be. "New connection attempt" is
 * mask = SYN|ACK, value = SYN (SYN set, ACK clear).
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
    uint8_t      tcp_flags;
    uint8_t      tcp_flags_mask;
} pkt_rule_t;

/** Why a frame was dropped. Later stages (spoofing, scans, rate limit) add more. */
typedef enum
{
    DROP_REASON_NONE = 0,       /**< Not dropped: the frame passed.               */
    DROP_REASON_MALFORMED,      /**< A header the frame claims to have is broken. */
    DROP_REASON_TCP_SCAN,       /**< TCP flag combination no real stack sends.    */
    DROP_REASON_RULE,           /**< A rule with action DROP matched.             */
    DROP_REASON_DEFAULT,        /**< No rule matched and the default is DROP.     */
    DROP_REASON_COUNT           /**< Number of reasons (array size), not a reason. */
} pkt_drop_reason_t;

/** The decision for one frame. */
typedef struct
{
    pkt_action_t      action;
    pkt_drop_reason_t reason;   /**< DROP_REASON_NONE when action is PKT_PASS.     */
    int32_t           rule_idx; /**< Matching rule, or -1 (default or malformed).  */
} pkt_verdict_t;

/**
 * @brief A filter instance: the rule table plus its statistics.
 *
 * Counters are only written by pkt_filter_process(), from one context
 * (the main loop), so they need no locking.
 */
typedef struct
{
    const pkt_rule_t *rules;
    uint32_t          rule_count;
    pkt_action_t      default_action;

    uint32_t rule_hits[PKT_FILTER_MAX_RULES]; /**< Frames matched by each rule.       */
    uint32_t default_hits;                    /**< Well-formed frames no rule matched. */
    uint32_t passed;                          /**< Frames with action PASS.            */
    uint32_t dropped[DROP_REASON_COUNT];      /**< Drops per reason ([NONE] stays 0).  */
} pkt_filter_t;

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

/**
 * @brief  Set up a filter and zero its counters.
 * @return false if count is larger than PKT_FILTER_MAX_RULES.
 */
bool pkt_filter_init(pkt_filter_t *f, const pkt_rule_t *rules, uint32_t count,
                     pkt_action_t default_action);

/**
 * @brief  Full pipeline for one frame: parse, drop if malformed, else run the
 *         rules. Updates the filter's counters.
 * @param  hdr  Filled with the parsed headers (useful for logging).
 */
pkt_verdict_t pkt_filter_process(pkt_filter_t *f, const uint8_t *frame, uint16_t len,
                                 pkt_hdr_t *hdr);

/**
 * @brief  Is this TCP flag combination one a real TCP stack can send?
 *
 * NULL scans (no flags), FIN scans (FIN alone), XMAS scans (FIN+PSH+URG),
 * SYN+FIN, SYN+RST and friends return false. PSH, ECE and CWR do not change
 * the answer. Stateless: an ACK or FIN+ACK scan looks like normal traffic and
 * would need connection tracking to catch.
 */
bool pkt_tcp_flags_valid(uint8_t flags);

/** Short name of a drop reason for logs, e.g. "malformed". */
const char *pkt_drop_reason_name(pkt_drop_reason_t reason);

#endif /* INC_PKT_FILTER_H_ */
