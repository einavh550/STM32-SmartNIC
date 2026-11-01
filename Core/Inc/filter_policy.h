/**
 * @file    filter_policy.h
 * @brief   The filter policy for the BeagleBone Black test link.
 *
 * @note    Kept in its own file (not in main.c) so the host unit tests compile
 *          and check exactly the table the board runs.
 *
 *          Link: direct cable, static addresses on 192.168.10.0/24.
 *            board (protected host)  192.168.10.1
 *            BeagleBone Black        192.168.10.2
 *          (192.168.6.x / 192.168.7.x are avoided: the BBB uses them for USB
 *          networking.)
 */

#ifndef INC_FILTER_POLICY_H_
#define INC_FILTER_POLICY_H_

#include <stdint.h>
#include "pkt_filter.h"

#define POLICY_NET              (0xC0A80A00u)   /**< 192.168.10.0           */
#define POLICY_NET_MASK         (0xFFFFFF00u)   /**< /24                    */
#define POLICY_BOARD_IP         (0xC0A80A01u)   /**< 192.168.10.1           */
#define POLICY_TCP_PORT         (80u)           /**< the protected service  */
#define POLICY_UDP_TEST_PORT    (5000u)         /**< throughput test stream */

/** Rule indexes, in table order (first match wins). */
typedef enum
{
    POLICY_ARP = 0,     /**< ARP, rate-limited (ARP storm).             */
    POLICY_PING,        /**< ICMP from the link, rate-limited (ping flood). */
    POLICY_TCP_NEW,     /**< New TCP connections, rate-limited (SYN flood). */
    POLICY_TCP,         /**< Rest of those TCP connections: pass.       */
    POLICY_UDP_TEST,    /**< UDP test stream: pass, no limit.           */
    POLICY_RULE_COUNT   /**< Number of rules, not a rule.               */
} policy_rule_id_t;

/** Anything no rule allows is dropped (default deny). */
#define POLICY_DEFAULT_ACTION   PKT_DROP

extern const pkt_rule_t filter_policy[POLICY_RULE_COUNT];

/** Short name of a policy rule for logs, e.g. "tcp-new". */
const char *filter_policy_rule_name(int32_t rule_idx);

#endif /* INC_FILTER_POLICY_H_ */
