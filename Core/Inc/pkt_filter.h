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

#include <stdbool.h>
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
    PKT_DROP,
    PKT_RATE_LIMIT  /**< Rule action only: pass while the rule's token bucket
                         has a token, else drop. A verdict is PASS or DROP. */
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
 *
 * With action PKT_RATE_LIMIT, matching frames pass at most rate_pps per
 * second on average, with bursts of up to `burst` frames (token bucket).
 * Both must be > 0.
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
    uint16_t     rate_pps;   /**< PKT_RATE_LIMIT: tokens added per second. */
    uint16_t     burst;      /**< PKT_RATE_LIMIT: bucket size in frames.   */
} pkt_rule_t;

/**
 * @brief Token bucket state of one rate-limited rule.
 *
 * Tokens are stored in thousandths (1 frame = 1000), so a refill of
 * elapsed_ms * rate_pps is exact integer math: no float, no rounding loss.
 */
typedef struct
{
    uint32_t tokens_milli;  /**< Current tokens x 1000.                      */
    uint32_t last_ms;       /**< Time of the last refill.                    */
    bool     started;       /**< false until the first frame (bucket full). */
} pkt_bucket_t;

/** Why a frame was dropped, in pipeline order. */
typedef enum
{
    DROP_REASON_NONE = 0,       /**< Not dropped: the frame passed.               */
    DROP_REASON_MALFORMED,      /**< A header the frame claims to have is broken. */
    DROP_REASON_SPOOFED,        /**< Source address that cannot be real.          */
    DROP_REASON_TCP_SCAN,      /**< TCP flag combination no real stack sends.    */
    DROP_REASON_RATE_LIMIT,     /**< A PKT_RATE_LIMIT rule's bucket was empty.    */
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

    pkt_bucket_t buckets[PKT_FILTER_MAX_RULES]; /**< One per rule (used by RATE_LIMIT). */
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
 * @return false if count is larger than PKT_FILTER_MAX_RULES, or a
 *         PKT_RATE_LIMIT rule has rate_pps or burst 0.
 */
bool pkt_filter_init(pkt_filter_t *f, const pkt_rule_t *rules, uint32_t count,
                     pkt_action_t default_action);

/**
 * @brief  Full pipeline for one frame: sanity (malformed) -> anti-spoofing ->
 *         TCP scan check -> rule table. Updates the filter's counters.
 * @param  now_ms  Current time in ms (HAL_GetTick() on the board), for the
 *                 rate limiter. Wrap-around at 2^32 is handled.
 * @param  hdr     Filled with the parsed headers (useful for logging).
 */
pkt_verdict_t pkt_filter_process(pkt_filter_t *f, const uint8_t *frame, uint16_t len,
                                 uint32_t now_ms, pkt_hdr_t *hdr);

/**
 * @brief  Token bucket: refill for the time since the last call, then try to
 *         take one token.
 *
 * A new bucket starts full (burst tokens), so a quiet source can send a short
 * burst at once; after that it gets rate_pps tokens per second, never more
 * than burst.
 * @return true if a token was taken (frame may pass).
 */
bool pkt_bucket_take(pkt_bucket_t *b, uint16_t rate_pps, uint16_t burst, uint32_t now_ms);

/**
 * @brief  Is this TCP flag combination one a real TCP stack can send?
 *
 * NULL scans (no flags), FIN scans (FIN alone), XMAS scans (FIN+PSH+URG),
 * SYN+FIN, SYN+RST and friends return false. PSH, ECE and CWR do not change
 * the answer. Stateless: an ACK or FIN+ACK scan looks like normal traffic and
 * would need connection tracking to catch.
 */
bool pkt_tcp_flags_valid(uint8_t flags);

/**
 * @brief  Does the frame carry a source address no honest sender can have?
 *
 * Stateless "martian" checks (RFC 1812, RFC 5735):
 * - source MAC is multicast/broadcast (a frame always comes from one card);
 * - source IP is loopback 127.0.0.0/8 (never leaves a machine);
 * - source IP is multicast, reserved or broadcast (224.0.0.0 and above);
 * - source IP is 0.0.0.0, except a DHCP request (UDP 68 -> 67), the only
 *   legal use: a client that has no address yet;
 * - source IP == destination IP (LAND attack: the target answers itself).
 *
 * "Is this source allowed on this link" (ingress filtering, BCP 38) is a
 * policy, so it is a rule in the table, not a fixed check here.
 */
bool pkt_src_is_spoofed(const pkt_hdr_t *hdr);

/** Short name of a drop reason for logs, e.g. "malformed". */
const char *pkt_drop_reason_name(pkt_drop_reason_t reason);

#endif /* INC_PKT_FILTER_H_ */
