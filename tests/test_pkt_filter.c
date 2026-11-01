/**
 * @file    test_pkt_filter.c
 * @brief   Unit tests for pkt_filter.c (first-match rule list).
 */

#include "test_framework.h"
#include "test_frames.h"

static uint8_t frame[128];

/* Parse a built frame into hdr, then run the filter on it. */
static pkt_action_t eval(const pkt_rule_t *rules, uint32_t count, pkt_action_t dflt,
                         uint16_t len, int32_t *idx)
{
    pkt_hdr_t hdr;

    CHECK(parse_all(frame, len, &hdr));
    return pkt_filter_eval(rules, count, dflt, &hdr, idx);
}

/* ------------------------------------------------------------------------- */
/* Rule list behaviour                                                       */
/* ------------------------------------------------------------------------- */

static void test_no_rules_gives_default(void)
{
    int32_t  idx = 99;
    uint16_t len = build_eth(frame, ETHERTYPE_ARP);

    CHECK_EQ(eval(NULL, 0u, PKT_DROP, len, &idx), PKT_DROP);
    CHECK_EQ(idx, -1);
    CHECK_EQ(eval(NULL, 0u, PKT_PASS, len, &idx), PKT_PASS);
}

static void test_empty_match_matches_everything(void)
{
    const pkt_rule_t rules[] = { { .match = 0u, .action = PKT_PASS } };
    int32_t  idx;
    uint16_t len = build_eth(frame, ETHERTYPE_ARP);

    CHECK_EQ(eval(rules, 1u, PKT_DROP, len, &idx), PKT_PASS);
    CHECK_EQ(idx, 0);
}

static void test_first_match_wins(void)
{
    const pkt_rule_t rules[] =
    {
        { .match = RULE_ETHERTYPE, .ethertype = ETHERTYPE_IPV4, .action = PKT_DROP },
        { .match = RULE_ETHERTYPE, .ethertype = ETHERTYPE_ARP,  .action = PKT_PASS },
        { .match = 0u,                                          .action = PKT_PASS },
    };
    int32_t  idx;
    uint16_t len = build_eth(frame, ETHERTYPE_ARP);

    /* Rules 1 and 2 both match ARP: the earlier one (1) must decide. */
    CHECK_EQ(eval(rules, 3u, PKT_DROP, len, &idx), PKT_PASS);
    CHECK_EQ(idx, 1);
}

/* ------------------------------------------------------------------------- */
/* Single fields                                                             */
/* ------------------------------------------------------------------------- */

static void test_ethertype_rule(void)
{
    const pkt_rule_t rules[] =
    {
        { .match = RULE_ETHERTYPE, .ethertype = ETHERTYPE_ARP, .action = PKT_PASS },
    };
    int32_t  idx;
    uint16_t len;

    len = build_eth(frame, ETHERTYPE_ARP);
    CHECK_EQ(eval(rules, 1u, PKT_DROP, len, &idx), PKT_PASS);

    len = build_udp(frame, 1u, 2u, 1u, 2u);
    CHECK_EQ(eval(rules, 1u, PKT_DROP, len, &idx), PKT_DROP);
    CHECK_EQ(idx, -1);
}

static void test_src_subnet_mask(void)
{
    const pkt_rule_t rules[] =
    {
        { .match = RULE_SRC_IP, .src_ip = IP4(192, 168, 7, 0), .src_mask = IP4(255, 255, 255, 0),
          .action = PKT_PASS },
    };
    int32_t  idx;
    uint16_t len;

    len = build_udp(frame, IP4(192, 168, 7, 42), IP4(10, 0, 0, 1), 1u, 2u);
    CHECK_EQ(eval(rules, 1u, PKT_DROP, len, &idx), PKT_PASS);

    len = build_udp(frame, IP4(192, 168, 8, 42), IP4(10, 0, 0, 1), 1u, 2u);
    CHECK_EQ(eval(rules, 1u, PKT_DROP, len, &idx), PKT_DROP);
}

static void test_dst_single_address(void)
{
    const pkt_rule_t rules[] =
    {
        { .match = RULE_DST_IP, .dst_ip = IP4(10, 0, 0, 1), .dst_mask = 0xFFFFFFFFu,
          .action = PKT_PASS },
    };
    int32_t  idx;
    uint16_t len;

    len = build_tcp(frame, 1u, IP4(10, 0, 0, 1), 1u, 2u);
    CHECK_EQ(eval(rules, 1u, PKT_DROP, len, &idx), PKT_PASS);

    len = build_tcp(frame, 1u, IP4(10, 0, 0, 2), 1u, 2u);
    CHECK_EQ(eval(rules, 1u, PKT_DROP, len, &idx), PKT_DROP);
}

static void test_all_fields_must_match(void)
{
    /* UDP AND port 137: TCP to port 137 must not match. */
    const pkt_rule_t rules[] =
    {
        { .match = RULE_IP_PROTO | RULE_DST_PORT, .ip_proto = IP_PROTO_UDP, .dst_port = 137u,
          .action = PKT_DROP },
    };
    int32_t  idx;
    uint16_t len;

    len = build_udp(frame, 1u, 2u, 1u, 137u);
    CHECK_EQ(eval(rules, 1u, PKT_PASS, len, &idx), PKT_DROP);

    len = build_tcp(frame, 1u, 2u, 1u, 137u);
    CHECK_EQ(eval(rules, 1u, PKT_PASS, len, &idx), PKT_PASS);

    len = build_udp(frame, 1u, 2u, 1u, 138u);
    CHECK_EQ(eval(rules, 1u, PKT_PASS, len, &idx), PKT_PASS);
}

/* ------------------------------------------------------------------------- */
/* Missing layers                                                            */
/* ------------------------------------------------------------------------- */

static void test_port_rule_ignores_stale_ports(void)
{
    const pkt_rule_t rules[] =
    {
        { .match = RULE_DST_PORT, .dst_port = 137u, .action = PKT_DROP },
    };
    pkt_hdr_t hdr;
    int32_t   idx;
    uint16_t  len;

    /* Frame 1 (UDP to 137) leaves dst_port = 137 in hdr. */
    len = build_udp(frame, 1u, 2u, 1u, 137u);
    CHECK(parse_all(frame, len, &hdr));
    CHECK_EQ(pkt_filter_eval(rules, 1u, PKT_PASS, &hdr, &idx), PKT_DROP);

    /* Frame 2 (ARP) in the same hdr: the old 137 is still in memory, but
     * PKT_HAS_L4 is clear, so the port rule must not match. */
    len = build_eth(frame, ETHERTYPE_ARP);
    CHECK(parse_all(frame, len, &hdr));
    CHECK_EQ(hdr.dst_port, 137u);
    CHECK_EQ(pkt_filter_eval(rules, 1u, PKT_PASS, &hdr, &idx), PKT_PASS);
    CHECK_EQ(idx, -1);
}

static void test_ip_rule_ignores_non_ip(void)
{
    /* Matches any IP address (mask 0), but only if the frame IS IPv4. */
    const pkt_rule_t rules[] =
    {
        { .match = RULE_SRC_IP, .src_ip = 0u, .src_mask = 0u, .action = PKT_DROP },
    };
    int32_t  idx;
    uint16_t len;

    len = build_eth(frame, ETHERTYPE_ARP);
    CHECK_EQ(eval(rules, 1u, PKT_PASS, len, &idx), PKT_PASS);

    len = build_udp(frame, 1u, 2u, 1u, 2u);
    CHECK_EQ(eval(rules, 1u, PKT_PASS, len, &idx), PKT_DROP);
}

static void test_port_rule_ignores_fragment(void)
{
    const pkt_rule_t rules[] =
    {
        { .match = RULE_DST_PORT, .dst_port = 67u, .action = PKT_PASS },
    };
    int32_t  idx;
    uint16_t len = build_udp(frame, 1u, 2u, 68u, 67u);

    wr_be16(&frame[ETH_HDR_LEN + 6], 185u);           /* non-first fragment */
    CHECK_EQ(eval(rules, 1u, PKT_DROP, len, &idx), PKT_DROP);
}

/* ------------------------------------------------------------------------- */
/* The demo rule table from main.c, end to end                               */
/* ------------------------------------------------------------------------- */

static void test_demo_rule_table(void)
{
    /* Same table as filter_rules[] in main.c. */
    const pkt_rule_t rules[] =
    {
        { .match = RULE_IP_PROTO | RULE_DST_PORT, .ip_proto = IP_PROTO_UDP, .dst_port = 137u,
          .action = PKT_DROP },
        { .match = RULE_ETHERTYPE, .ethertype = ETHERTYPE_ARP, .action = PKT_PASS },
        { .match = RULE_IP_PROTO | RULE_DST_PORT, .ip_proto = IP_PROTO_UDP, .dst_port = 67u,
          .action = PKT_PASS },
    };
    const uint32_t n = sizeof(rules) / sizeof(rules[0]);
    int32_t  idx;
    uint16_t len;

    /* NetBIOS broadcast from the laptop -> r0 DROP */
    len = build_udp(frame, IP4(169, 254, 236, 228), IP4(169, 254, 255, 255), 137u, 137u);
    CHECK_EQ(eval(rules, n, PKT_DROP, len, &idx), PKT_DROP);
    CHECK_EQ(idx, 0);

    /* ARP -> r1 PASS */
    len = build_eth(frame, ETHERTYPE_ARP);
    CHECK_EQ(eval(rules, n, PKT_DROP, len, &idx), PKT_PASS);
    CHECK_EQ(idx, 1);

    /* DHCP Discover -> r2 PASS */
    len = build_udp(frame, IP4(0, 0, 0, 0), IP4(255, 255, 255, 255), 68u, 67u);
    CHECK_EQ(eval(rules, n, PKT_DROP, len, &idx), PKT_PASS);
    CHECK_EQ(idx, 2);

    /* Anything else (TCP to port 80) -> default DROP */
    len = build_tcp(frame, IP4(10, 0, 0, 1), IP4(10, 0, 0, 2), 40000u, 80u);
    CHECK_EQ(eval(rules, n, PKT_DROP, len, &idx), PKT_DROP);
    CHECK_EQ(idx, -1);
}

/* ------------------------------------------------------------------------- */
/* Pipeline + counters: pkt_filter_process()                                 */
/* ------------------------------------------------------------------------- */

static const pkt_rule_t demo_rules[] =
{
    { .match = RULE_IP_PROTO | RULE_DST_PORT, .ip_proto = IP_PROTO_UDP, .dst_port = 137u,
      .action = PKT_DROP },
    { .match = RULE_ETHERTYPE, .ethertype = ETHERTYPE_ARP, .action = PKT_PASS },
    { .match = RULE_IP_PROTO | RULE_DST_PORT, .ip_proto = IP_PROTO_UDP, .dst_port = 67u,
      .action = PKT_PASS },
};

static void test_init_rejects_too_many_rules(void)
{
    static pkt_rule_t many[PKT_FILTER_MAX_RULES + 1u];
    pkt_filter_t f;

    CHECK(pkt_filter_init(&f, many, PKT_FILTER_MAX_RULES, PKT_DROP));
    CHECK(!pkt_filter_init(&f, many, PKT_FILTER_MAX_RULES + 1u, PKT_DROP));
}

static void test_process_verdicts(void)
{
    pkt_filter_t  f;
    pkt_hdr_t     hdr;
    pkt_verdict_t v;
    uint16_t      len;

    CHECK(pkt_filter_init(&f, demo_rules, 3u, PKT_DROP));

    /* PASS by a rule: reason NONE. */
    len = build_eth(frame, ETHERTYPE_ARP);
    v   = pkt_filter_process(&f, frame, len, &hdr);
    CHECK_EQ(v.action, PKT_PASS);
    CHECK_EQ(v.reason, DROP_REASON_NONE);
    CHECK_EQ(v.rule_idx, 1);

    /* DROP by a rule. */
    len = build_udp(frame, 1u, 2u, 137u, 137u);
    v   = pkt_filter_process(&f, frame, len, &hdr);
    CHECK_EQ(v.action, PKT_DROP);
    CHECK_EQ(v.reason, DROP_REASON_RULE);
    CHECK_EQ(v.rule_idx, 0);

    /* DROP by the default. */
    len = build_tcp(frame, 1u, 2u, 40000u, 80u);
    v   = pkt_filter_process(&f, frame, len, &hdr);
    CHECK_EQ(v.action, PKT_DROP);
    CHECK_EQ(v.reason, DROP_REASON_DEFAULT);
    CHECK_EQ(v.rule_idx, -1);

    /* DROP as malformed: UDP to port 67 would PASS, but the header is cut. */
    len = build_udp(frame, 1u, 2u, 68u, 67u);
    v   = pkt_filter_process(&f, frame, len - 1u, &hdr);
    CHECK_EQ(v.action, PKT_DROP);
    CHECK_EQ(v.reason, DROP_REASON_MALFORMED);
    CHECK_EQ(v.rule_idx, -1);
}

static void test_process_counters(void)
{
    pkt_filter_t f;
    pkt_hdr_t    hdr;
    uint16_t     len;

    CHECK(pkt_filter_init(&f, demo_rules, 3u, PKT_DROP));

    len = build_udp(frame, 1u, 2u, 137u, 137u);       /* r0 DROP   */
    (void)pkt_filter_process(&f, frame, len, &hdr);
    (void)pkt_filter_process(&f, frame, len, &hdr);
    len = build_eth(frame, ETHERTYPE_ARP);            /* r1 PASS   */
    (void)pkt_filter_process(&f, frame, len, &hdr);
    len = build_udp(frame, 0u, 0xFFFFFFFFu, 68u, 67u);/* r2 PASS   */
    (void)pkt_filter_process(&f, frame, len, &hdr);
    len = build_tcp(frame, 1u, 2u, 40000u, 80u);      /* default   */
    (void)pkt_filter_process(&f, frame, len, &hdr);
    (void)pkt_filter_process(&f, frame, 10u, &hdr);   /* malformed */

    CHECK_EQ(f.passed, 2u);
    CHECK_EQ(f.dropped[DROP_REASON_RULE], 2u);
    CHECK_EQ(f.dropped[DROP_REASON_DEFAULT], 1u);
    CHECK_EQ(f.dropped[DROP_REASON_MALFORMED], 1u);
    CHECK_EQ(f.dropped[DROP_REASON_NONE], 0u);
    CHECK_EQ(f.rule_hits[0], 2u);
    CHECK_EQ(f.rule_hits[1], 1u);
    CHECK_EQ(f.rule_hits[2], 1u);
    CHECK_EQ(f.default_hits, 1u);                     /* malformed is not a default hit */
}

static void test_malformed_never_reaches_rules(void)
{
    /* A catch-all PASS rule must still not let a broken frame through. */
    const pkt_rule_t pass_all[] = { { .match = 0u, .action = PKT_PASS } };
    pkt_filter_t  f;
    pkt_hdr_t     hdr;
    pkt_verdict_t v;
    uint16_t      len = build_udp(frame, 1u, 2u, 1u, 2u);

    CHECK(pkt_filter_init(&f, pass_all, 1u, PKT_PASS));
    frame[ETH_HDR_LEN] = 0x44;                        /* IHL 4: impossible */

    v = pkt_filter_process(&f, frame, len, &hdr);
    CHECK_EQ(v.action, PKT_DROP);
    CHECK_EQ(v.reason, DROP_REASON_MALFORMED);
    CHECK_EQ(f.rule_hits[0], 0u);
}

static void test_reason_names(void)
{
    CHECK(strcmp(pkt_drop_reason_name(DROP_REASON_MALFORMED), "malformed") == 0);
    CHECK(strcmp(pkt_drop_reason_name(DROP_REASON_RULE), "rule") == 0);
    CHECK(strcmp(pkt_drop_reason_name(DROP_REASON_DEFAULT), "default") == 0);
    CHECK(strcmp(pkt_drop_reason_name(DROP_REASON_COUNT), "?") == 0);
}

/* ------------------------------------------------------------------------- */

void run_pkt_filter_tests(void)
{
    RUN_TEST(test_no_rules_gives_default);
    RUN_TEST(test_empty_match_matches_everything);
    RUN_TEST(test_first_match_wins);

    RUN_TEST(test_ethertype_rule);
    RUN_TEST(test_src_subnet_mask);
    RUN_TEST(test_dst_single_address);
    RUN_TEST(test_all_fields_must_match);

    RUN_TEST(test_port_rule_ignores_stale_ports);
    RUN_TEST(test_ip_rule_ignores_non_ip);
    RUN_TEST(test_port_rule_ignores_fragment);

    RUN_TEST(test_demo_rule_table);

    RUN_TEST(test_init_rejects_too_many_rules);
    RUN_TEST(test_process_verdicts);
    RUN_TEST(test_process_counters);
    RUN_TEST(test_malformed_never_reaches_rules);
    RUN_TEST(test_reason_names);
}
