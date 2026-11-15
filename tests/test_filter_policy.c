/**
 * @file    test_filter_policy.c
 * @brief   Tests for the real policy the board runs (filter_policy.c):
 *          the traffic the BBB will send in Phase 4, attacks against it, and
 *          what happens to the laptop traffic seen during development.
 */

#include "test_framework.h"
#include "test_frames.h"
#include "filter_policy.h"

#define BBB_IP      IP4(192, 168, 10, 2)
#define BOARD_IP    IP4(192, 168, 10, 1)

static uint8_t      frame[128];
static pkt_filter_t f;
static pkt_hdr_t    hdr;

/* Fresh filter with the real policy (all counters and buckets reset). */
static void setup(void)
{
    CHECK(pkt_filter_init(&f, filter_policy, POLICY_RULE_COUNT, POLICY_DEFAULT_ACTION));
}

static pkt_verdict_t send(uint16_t len, uint32_t now_ms)
{
    return pkt_filter_process(&f, frame, len, 0u, now_ms, &hdr);
}

/* ------------------------------------------------------------------------- */
/* Allowed traffic                                                           */
/* ------------------------------------------------------------------------- */

static void test_policy_is_valid(void)
{
    setup();
    CHECK_EQ(f.rule_count, (uint32_t)POLICY_RULE_COUNT);
}

static void test_udp_test_stream_has_no_limit(void)
{
    uint16_t len = build_udp(frame, BBB_IP, BOARD_IP, 40000u, POLICY_UDP_TEST_PORT);

    setup();
    /* 1000 frames in the same millisecond: all pass, a throughput test must
     * measure the board, not the limiter. */
    for (uint32_t i = 0u; i < 1000u; i++)
    {
        (void)send(len, 0u);
    }
    CHECK_EQ(f.passed, 1000u);
    CHECK_EQ(f.rule_hits[POLICY_UDP_TEST], 1000u);
}

static void test_tcp_connection_from_bbb(void)
{
    uint16_t      len = build_tcp(frame, BBB_IP, BOARD_IP, 40000u, POLICY_TCP_PORT);
    pkt_verdict_t v;

    setup();

    set_tcp_flags(frame, TCP_FLAG_SYN);                              /* connect */
    v = send(len, 0u);
    CHECK_EQ(v.action, PKT_PASS);
    CHECK_EQ(v.rule_idx, POLICY_TCP_NEW);

    set_tcp_flags(frame, TCP_FLAG_ACK | TCP_FLAG_PSH);               /* data    */
    v = send(len, 1u);
    CHECK_EQ(v.action, PKT_PASS);
    CHECK_EQ(v.rule_idx, POLICY_TCP);

    set_tcp_flags(frame, TCP_FLAG_FIN | TCP_FLAG_ACK);               /* close   */
    CHECK_EQ(send(len, 2u).rule_idx, POLICY_TCP);
}

/* ------------------------------------------------------------------------- */
/* Attacks                                                                   */
/* ------------------------------------------------------------------------- */

static void test_syn_flood_is_cut(void)
{
    uint16_t len = build_tcp(frame, BBB_IP, BOARD_IP, 40000u, POLICY_TCP_PORT);

    setup();
    for (uint32_t i = 0u; i < 100u; i++)
    {
        (void)send(len, 0u);                                         /* SYN flood */
    }
    CHECK_EQ(f.passed, 5u);                                          /* burst 5   */
    CHECK_EQ(f.dropped[DROP_REASON_RATE_LIMIT], 95u);

    /* Data of an open connection still passes during the flood. */
    set_tcp_flags(frame, TCP_FLAG_ACK);
    CHECK_EQ(send(len, 0u).action, PKT_PASS);

    /* 20/s: one new connection every 50 ms. */
    set_tcp_flags(frame, TCP_FLAG_SYN);
    CHECK_EQ(send(len, 49u).action, PKT_DROP);
    CHECK_EQ(send(len, 50u).action, PKT_PASS);
}

static void test_ping_flood_is_cut(void)
{
    uint16_t len = (uint16_t)(build_ipv4(frame, IP_PROTO_ICMP, BBB_IP, BOARD_IP, 8u) + 8u);

    setup();
    for (uint32_t i = 0u; i < 20u; i++)
    {
        CHECK_EQ(send(len, 0u).rule_idx, POLICY_PING);
    }
    CHECK_EQ(f.passed, 5u);
    CHECK_EQ(f.dropped[DROP_REASON_RATE_LIMIT], 15u);
}

static void test_arp_storm_is_cut(void)
{
    uint16_t len = build_eth(frame, ETHERTYPE_ARP);

    setup();
    for (uint32_t i = 0u; i < 30u; i++)
    {
        (void)send(len, 0u);
    }
    CHECK_EQ(f.passed, 10u);                                         /* burst 10  */
    CHECK_EQ(send(len, 50u).action, PKT_PASS);                       /* 20/s      */
}

static void test_ingress_filter(void)
{
    uint16_t len;

    setup();

    /* Allowed service, but the source is outside the link subnet. */
    len = build_udp(frame, IP4(10, 0, 0, 5), BOARD_IP, 40000u, POLICY_UDP_TEST_PORT);
    CHECK_EQ(send(len, 0u).reason, DROP_REASON_DEFAULT);

    len = build_tcp(frame, IP4(192, 168, 11, 2), BOARD_IP, 40000u, POLICY_TCP_PORT);
    CHECK_EQ(send(len, 0u).reason, DROP_REASON_DEFAULT);

    /* From the link, but to another address: the board protects only itself. */
    len = build_udp(frame, BBB_IP, IP4(192, 168, 10, 7), 40000u, POLICY_UDP_TEST_PORT);
    CHECK_EQ(send(len, 0u).reason, DROP_REASON_DEFAULT);
}

static void test_unlisted_services_are_dropped(void)
{
    setup();
    CHECK_EQ(send(build_tcp(frame, BBB_IP, BOARD_IP, 40000u, 22u), 0u).reason,
             DROP_REASON_DEFAULT);                                   /* SSH       */
    CHECK_EQ(send(build_udp(frame, BBB_IP, BOARD_IP, 40000u, 53u), 0u).reason,
             DROP_REASON_DEFAULT);                                   /* DNS       */
    CHECK_EQ(send(build_eth(frame, 0x86DDu), 0u).reason,
             DROP_REASON_DEFAULT);                                   /* IPv6      */
}

static void test_fixed_stages_run_first(void)
{
    uint16_t len = build_tcp(frame, BBB_IP, BOARD_IP, 40000u, POLICY_TCP_PORT);

    setup();
    set_tcp_flags(frame, TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG);  /* XMAS     */
    CHECK_EQ(send(len, 0u).reason, DROP_REASON_TCP_SCAN);

    len = build_udp(frame, BOARD_IP, BOARD_IP, 1u, POLICY_UDP_TEST_PORT);  /* LAND */
    CHECK_EQ(send(len, 0u).reason, DROP_REASON_SPOOFED);
}

/* ------------------------------------------------------------------------- */
/* Development setup: laptop on the cable instead of the BBB                 */
/* ------------------------------------------------------------------------- */

static void test_laptop_traffic(void)
{
    setup();
    /* NetBIOS and DHCP from a laptop are not part of the policy. */
    CHECK_EQ(send(build_udp(frame, IP4(169, 254, 236, 228), IP4(169, 254, 255, 255),
                            137u, 137u), 0u).reason, DROP_REASON_DEFAULT);
    CHECK_EQ(send(build_udp(frame, IP4(0, 0, 0, 0), IP4(255, 255, 255, 255),
                            68u, 67u), 0u).reason, DROP_REASON_DEFAULT);
    /* ARP passes (rate-limited). */
    CHECK_EQ(send(build_eth(frame, ETHERTYPE_ARP), 0u).action, PKT_PASS);
}

static void test_rule_names(void)
{
    CHECK(strcmp(filter_policy_rule_name(POLICY_ARP), "arp") == 0);
    CHECK(strcmp(filter_policy_rule_name(POLICY_TCP_NEW), "tcp-new") == 0);
    CHECK(strcmp(filter_policy_rule_name(POLICY_UDP_TEST), "udp-test") == 0);
    CHECK(strcmp(filter_policy_rule_name(-1), "default") == 0);
}

/* ------------------------------------------------------------------------- */

void run_filter_policy_tests(void)
{
    RUN_TEST(test_policy_is_valid);
    RUN_TEST(test_udp_test_stream_has_no_limit);
    RUN_TEST(test_tcp_connection_from_bbb);

    RUN_TEST(test_syn_flood_is_cut);
    RUN_TEST(test_ping_flood_is_cut);
    RUN_TEST(test_arp_storm_is_cut);
    RUN_TEST(test_ingress_filter);
    RUN_TEST(test_unlisted_services_are_dropped);
    RUN_TEST(test_fixed_stages_run_first);

    RUN_TEST(test_laptop_traffic);
    RUN_TEST(test_rule_names);
}
