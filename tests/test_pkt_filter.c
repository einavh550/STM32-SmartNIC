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
    v   = pkt_filter_process(&f, frame, len, 0u, &hdr);
    CHECK_EQ(v.action, PKT_PASS);
    CHECK_EQ(v.reason, DROP_REASON_NONE);
    CHECK_EQ(v.rule_idx, 1);

    /* DROP by a rule. */
    len = build_udp(frame, 1u, 2u, 137u, 137u);
    v   = pkt_filter_process(&f, frame, len, 0u, &hdr);
    CHECK_EQ(v.action, PKT_DROP);
    CHECK_EQ(v.reason, DROP_REASON_RULE);
    CHECK_EQ(v.rule_idx, 0);

    /* DROP by the default. */
    len = build_tcp(frame, 1u, 2u, 40000u, 80u);
    v   = pkt_filter_process(&f, frame, len, 0u, &hdr);
    CHECK_EQ(v.action, PKT_DROP);
    CHECK_EQ(v.reason, DROP_REASON_DEFAULT);
    CHECK_EQ(v.rule_idx, -1);

    /* DROP as malformed: UDP to port 67 would PASS, but the header is cut. */
    len = build_udp(frame, 1u, 2u, 68u, 67u);
    v   = pkt_filter_process(&f, frame, len - 1u, 0u, &hdr);
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
    (void)pkt_filter_process(&f, frame, len, 0u, &hdr);
    (void)pkt_filter_process(&f, frame, len, 0u, &hdr);
    len = build_eth(frame, ETHERTYPE_ARP);            /* r1 PASS   */
    (void)pkt_filter_process(&f, frame, len, 0u, &hdr);
    len = build_udp(frame, 0u, 0xFFFFFFFFu, 68u, 67u);/* r2 PASS   */
    (void)pkt_filter_process(&f, frame, len, 0u, &hdr);
    len = build_tcp(frame, 1u, 2u, 40000u, 80u);      /* default   */
    (void)pkt_filter_process(&f, frame, len, 0u, &hdr);
    (void)pkt_filter_process(&f, frame, 10u, 0u, &hdr);   /* malformed */

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

    v = pkt_filter_process(&f, frame, len, 0u, &hdr);
    CHECK_EQ(v.action, PKT_DROP);
    CHECK_EQ(v.reason, DROP_REASON_MALFORMED);
    CHECK_EQ(f.rule_hits[0], 0u);
}

static void test_reason_names(void)
{
    CHECK(strcmp(pkt_drop_reason_name(DROP_REASON_MALFORMED), "malformed") == 0);
    CHECK(strcmp(pkt_drop_reason_name(DROP_REASON_SPOOFED), "spoofed") == 0);
    CHECK(strcmp(pkt_drop_reason_name(DROP_REASON_TCP_SCAN), "tcp-scan") == 0);
    CHECK(strcmp(pkt_drop_reason_name(DROP_REASON_RATE_LIMIT), "rate-limit") == 0);
    CHECK(strcmp(pkt_drop_reason_name(DROP_REASON_RULE), "rule") == 0);
    CHECK(strcmp(pkt_drop_reason_name(DROP_REASON_DEFAULT), "default") == 0);
    CHECK(strcmp(pkt_drop_reason_name(DROP_REASON_COUNT), "?") == 0);
}

/* ------------------------------------------------------------------------- */
/* Step 3: TCP scan detection and TCP flag rules                             */
/* ------------------------------------------------------------------------- */

static void test_tcp_flags_real_traffic_is_valid(void)
{
    CHECK(pkt_tcp_flags_valid(TCP_FLAG_SYN));                               /* connect   */
    CHECK(pkt_tcp_flags_valid(TCP_FLAG_SYN | TCP_FLAG_ACK));                /* accept    */
    CHECK(pkt_tcp_flags_valid(TCP_FLAG_ACK));                               /* ack       */
    CHECK(pkt_tcp_flags_valid(TCP_FLAG_ACK | TCP_FLAG_PSH));                /* data      */
    CHECK(pkt_tcp_flags_valid(TCP_FLAG_FIN | TCP_FLAG_ACK));                /* close     */
    CHECK(pkt_tcp_flags_valid(TCP_FLAG_FIN | TCP_FLAG_ACK | TCP_FLAG_PSH)); /* last data */
    CHECK(pkt_tcp_flags_valid(TCP_FLAG_RST));                               /* refuse    */
    CHECK(pkt_tcp_flags_valid(TCP_FLAG_RST | TCP_FLAG_ACK));
    CHECK(pkt_tcp_flags_valid(TCP_FLAG_SYN | TCP_FLAG_ECE | TCP_FLAG_CWR)); /* ECN setup */
}

static void test_tcp_flags_scans_are_invalid(void)
{
    CHECK(!pkt_tcp_flags_valid(0u));                                        /* NULL scan */
    CHECK(!pkt_tcp_flags_valid(TCP_FLAG_FIN));                              /* FIN scan  */
    CHECK(!pkt_tcp_flags_valid(TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG));/* XMAS scan */
    CHECK(!pkt_tcp_flags_valid(TCP_FLAG_SYN | TCP_FLAG_FIN));
    CHECK(!pkt_tcp_flags_valid(TCP_FLAG_SYN | TCP_FLAG_RST));
    CHECK(!pkt_tcp_flags_valid(TCP_FLAG_FIN | TCP_FLAG_RST));
    CHECK(!pkt_tcp_flags_valid(TCP_FLAG_PSH));
    CHECK(!pkt_tcp_flags_valid(TCP_FLAG_URG));
    CHECK(!pkt_tcp_flags_valid(0xFFu));                                     /* all flags */
}

static void test_scan_is_dropped_before_rules(void)
{
    /* Even a catch-all PASS rule must not let a scan through. */
    const pkt_rule_t pass_all[] = { { .match = 0u, .action = PKT_PASS } };
    pkt_filter_t  f;
    pkt_hdr_t     hdr;
    pkt_verdict_t v;
    uint16_t      len = build_tcp(frame, 1u, 2u, 40000u, 22u);

    CHECK(pkt_filter_init(&f, pass_all, 1u, PKT_PASS));

    set_tcp_flags(frame, TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG);  /* XMAS */
    v = pkt_filter_process(&f, frame, len, 0u, &hdr);
    CHECK_EQ(v.action, PKT_DROP);
    CHECK_EQ(v.reason, DROP_REASON_TCP_SCAN);
    CHECK_EQ(v.rule_idx, -1);

    set_tcp_flags(frame, 0u);                                          /* NULL */
    (void)pkt_filter_process(&f, frame, len, 0u, &hdr);

    set_tcp_flags(frame, TCP_FLAG_SYN);                                /* real */
    v = pkt_filter_process(&f, frame, len, 0u, &hdr);
    CHECK_EQ(v.action, PKT_PASS);

    CHECK_EQ(f.dropped[DROP_REASON_TCP_SCAN], 2u);
    CHECK_EQ(f.rule_hits[0], 1u);                     /* only the real SYN */
    CHECK_EQ(f.default_hits, 0u);
    CHECK_EQ(f.passed, 1u);
}

static void test_udp_is_not_checked_for_flags(void)
{
    const pkt_rule_t pass_all[] = { { .match = 0u, .action = PKT_PASS } };
    pkt_filter_t f;
    pkt_hdr_t    hdr;
    uint16_t     len = build_udp(frame, 1u, 2u, 1u, 2u);

    CHECK(pkt_filter_init(&f, pass_all, 1u, PKT_DROP));
    CHECK_EQ(pkt_filter_process(&f, frame, len, 0u, &hdr).action, PKT_PASS);
}

static void test_rule_on_tcp_flags(void)
{
    /* "New connection attempt": SYN set, ACK clear. */
    const pkt_rule_t rules[] =
    {
        { .match = RULE_TCP_FLAGS, .tcp_flags = TCP_FLAG_SYN,
          .tcp_flags_mask = TCP_FLAG_SYN | TCP_FLAG_ACK, .action = PKT_DROP },
    };
    int32_t  idx;
    uint16_t len = build_tcp(frame, 1u, 2u, 40000u, 22u);

    set_tcp_flags(frame, TCP_FLAG_SYN);
    CHECK_EQ(eval(rules, 1u, PKT_PASS, len, &idx), PKT_DROP);

    set_tcp_flags(frame, TCP_FLAG_SYN | TCP_FLAG_ECE | TCP_FLAG_CWR);  /* bits outside the mask */
    CHECK_EQ(eval(rules, 1u, PKT_PASS, len, &idx), PKT_DROP);

    set_tcp_flags(frame, TCP_FLAG_SYN | TCP_FLAG_ACK);                 /* reply, not a new one */
    CHECK_EQ(eval(rules, 1u, PKT_PASS, len, &idx), PKT_PASS);

    set_tcp_flags(frame, TCP_FLAG_ACK);
    CHECK_EQ(eval(rules, 1u, PKT_PASS, len, &idx), PKT_PASS);

    /* UDP has no flags: never matches, even though tcp_flags reads 0. */
    len = build_udp(frame, 1u, 2u, 1u, 2u);
    CHECK_EQ(eval(rules, 1u, PKT_PASS, len, &idx), PKT_PASS);
}

/* ------------------------------------------------------------------------- */
/* Step 4: anti-spoofing                                                     */
/* ------------------------------------------------------------------------- */

/* Parse a built frame and ask the spoofing check about it. */
static bool spoofed(uint16_t len)
{
    pkt_hdr_t hdr;

    CHECK(parse_all(frame, len, &hdr));
    return pkt_src_is_spoofed(&hdr);
}

static void test_real_sources_are_not_spoofed(void)
{
    CHECK(!spoofed(build_udp(frame, IP4(192, 168, 7, 2), IP4(192, 168, 7, 1), 5000u, 5000u)));
    CHECK(!spoofed(build_udp(frame, IP4(169, 254, 236, 228), IP4(169, 254, 255, 255), 137u, 137u)));
    CHECK(!spoofed(build_tcp(frame, IP4(10, 0, 0, 1), IP4(10, 0, 0, 2), 40000u, 80u)));
    CHECK(!spoofed(build_udp(frame, IP4(223, 255, 255, 255), IP4(10, 0, 0, 1), 1u, 2u))); /* last unicast */
    CHECK(!spoofed(build_eth(frame, ETHERTYPE_ARP)));
}

static void test_martian_sources_are_spoofed(void)
{
    const uint32_t dst = IP4(192, 168, 7, 1);

    CHECK(spoofed(build_udp(frame, IP4(127, 0, 0, 1), dst, 1u, 2u)));       /* loopback   */
    CHECK(spoofed(build_udp(frame, IP4(127, 255, 0, 9), dst, 1u, 2u)));
    CHECK(spoofed(build_udp(frame, IP4(224, 0, 0, 1), dst, 1u, 2u)));       /* multicast  */
    CHECK(spoofed(build_udp(frame, IP4(240, 0, 0, 1), dst, 1u, 2u)));       /* reserved   */
    CHECK(spoofed(build_udp(frame, IP4(255, 255, 255, 255), dst, 1u, 2u))); /* broadcast  */
    CHECK(spoofed(build_tcp(frame, IP4(0, 0, 0, 0), dst, 40000u, 80u)));    /* 0.0.0.0    */
}

static void test_dhcp_request_may_use_zero_source(void)
{
    const uint32_t any = IP4(0, 0, 0, 0), bcast = IP4(255, 255, 255, 255);

    CHECK(!spoofed(build_udp(frame, any, bcast, 68u, 67u)));   /* DHCP Discover   */
    CHECK(spoofed(build_udp(frame, any, bcast, 67u, 68u)));    /* wrong direction */
    CHECK(spoofed(build_udp(frame, any, bcast, 68u, 53u)));    /* not DHCP        */

    /* A fragment has no ports, so it cannot prove it is DHCP. */
    uint16_t len = build_udp(frame, any, bcast, 68u, 67u);
    wr_be16(&frame[ETH_HDR_LEN + 6u], 0x0001u);                /* frag offset 1   */
    CHECK(spoofed(len));
}

static void test_land_attack_is_spoofed(void)
{
    const uint32_t victim = IP4(192, 168, 7, 1);

    CHECK(spoofed(build_tcp(frame, victim, victim, 80u, 80u)));
    CHECK(spoofed(build_udp(frame, victim, victim, 1u, 2u)));
}

static void test_group_source_mac_is_spoofed(void)
{
    uint16_t len = build_eth(frame, ETHERTYPE_ARP);

    frame[6] = 0x01;                                           /* multicast MAC   */
    CHECK(spoofed(len));
    memset(&frame[6], 0xFF, ETH_MAC_LEN);                      /* broadcast MAC   */
    CHECK(spoofed(len));
    frame[6] = 0x02;                                           /* unicast again   */
    CHECK(!spoofed(len));
}

static void test_spoofed_is_dropped_before_rules(void)
{
    const pkt_rule_t pass_all[] = { { .match = 0u, .action = PKT_PASS } };
    pkt_filter_t  f;
    pkt_hdr_t     hdr;
    pkt_verdict_t v;
    uint16_t      len;

    CHECK(pkt_filter_init(&f, pass_all, 1u, PKT_PASS));

    len = build_udp(frame, IP4(127, 0, 0, 1), IP4(192, 168, 7, 1), 1u, 2u);
    v = pkt_filter_process(&f, frame, len, 0u, &hdr);
    CHECK_EQ(v.action, PKT_DROP);
    CHECK_EQ(v.reason, DROP_REASON_SPOOFED);
    CHECK_EQ(v.rule_idx, -1);

    /* Spoofed AND a scan: the earlier stage (spoofing) gets the blame. */
    len = build_tcp(frame, IP4(10, 0, 0, 1), IP4(10, 0, 0, 1), 80u, 80u);
    set_tcp_flags(frame, 0u);
    CHECK_EQ(pkt_filter_process(&f, frame, len, 0u, &hdr).reason, DROP_REASON_SPOOFED);

    CHECK_EQ(f.dropped[DROP_REASON_SPOOFED], 2u);
    CHECK_EQ(f.dropped[DROP_REASON_TCP_SCAN], 0u);
    CHECK_EQ(f.rule_hits[0], 0u);
    CHECK_EQ(f.passed, 0u);
}

/* ------------------------------------------------------------------------- */
/* Step 5: token bucket rate limiting                                        */
/* ------------------------------------------------------------------------- */

static void test_bucket_starts_full_then_empties(void)
{
    pkt_bucket_t b = { 0 };

    /* burst 3: three frames at the same moment pass, the fourth does not. */
    CHECK(pkt_bucket_take(&b, 10u, 3u, 1000u));
    CHECK(pkt_bucket_take(&b, 10u, 3u, 1000u));
    CHECK(pkt_bucket_take(&b, 10u, 3u, 1000u));
    CHECK(!pkt_bucket_take(&b, 10u, 3u, 1000u));
}

static void test_bucket_refills_at_rate(void)
{
    pkt_bucket_t b = { 0 };

    CHECK(pkt_bucket_take(&b, 10u, 1u, 0u));        /* 10/s = 1 token per 100 ms */
    CHECK(!pkt_bucket_take(&b, 10u, 1u, 99u));      /* 0.99 token: not yet       */
    CHECK(pkt_bucket_take(&b, 10u, 1u, 100u));      /* 99 ms + 1 ms add up       */
    CHECK(!pkt_bucket_take(&b, 10u, 1u, 150u));
    CHECK(pkt_bucket_take(&b, 10u, 1u, 200u));
}

static void test_bucket_never_exceeds_burst(void)
{
    pkt_bucket_t b = { 0 };

    CHECK(pkt_bucket_take(&b, 100u, 2u, 0u));
    /* An hour of silence earns 2 tokens (the burst), not 360000. */
    CHECK(pkt_bucket_take(&b, 100u, 2u, 3600000u));
    CHECK(pkt_bucket_take(&b, 100u, 2u, 3600000u));
    CHECK(!pkt_bucket_take(&b, 100u, 2u, 3600000u));
}

static void test_bucket_survives_tick_wrap(void)
{
    pkt_bucket_t b = { 0 };

    /* HAL_GetTick() wraps to 0 after ~49.7 days. */
    CHECK(pkt_bucket_take(&b, 10u, 1u, 0xFFFFFFC0u));        /* 64 ms before the wrap */
    CHECK(!pkt_bucket_take(&b, 10u, 1u, 0xFFFFFFF0u));
    CHECK(pkt_bucket_take(&b, 10u, 1u, 36u));                /* 100 ms later, wrapped */
}

static void test_bucket_no_overflow(void)
{
    pkt_bucket_t b = { 0 };

    /* Largest rate and burst, longest gap: the math must not wrap around. */
    CHECK(pkt_bucket_take(&b, 0xFFFFu, 0xFFFFu, 0u));
    CHECK(pkt_bucket_take(&b, 0xFFFFu, 0xFFFFu, 0xFFFFFFFFu));
    CHECK_EQ(b.tokens_milli, (uint32_t)0xFFFFu * 1000u - 1000u);
}

static void test_init_rejects_bad_rate_limit(void)
{
    const pkt_rule_t no_rate[]  = { { .action = PKT_RATE_LIMIT, .rate_pps = 0u, .burst = 5u } };
    const pkt_rule_t no_burst[] = { { .action = PKT_RATE_LIMIT, .rate_pps = 5u, .burst = 0u } };
    const pkt_rule_t ok[]       = { { .action = PKT_RATE_LIMIT, .rate_pps = 5u, .burst = 5u } };
    pkt_filter_t f;

    CHECK(!pkt_filter_init(&f, no_rate, 1u, PKT_DROP));
    CHECK(!pkt_filter_init(&f, no_burst, 1u, PKT_DROP));
    CHECK(pkt_filter_init(&f, ok, 1u, PKT_DROP));
}

static void test_syn_flood_is_rate_limited(void)
{
    /* Limit new TCP connections to 10/s, burst 3. Other traffic is free. */
    const pkt_rule_t rules[] =
    {
        { .match = RULE_TCP_FLAGS, .tcp_flags = TCP_FLAG_SYN,
          .tcp_flags_mask = TCP_FLAG_SYN | TCP_FLAG_ACK,
          .action = PKT_RATE_LIMIT, .rate_pps = 10u, .burst = 3u },
        { .match = 0u, .action = PKT_PASS },
    };
    pkt_filter_t  f;
    pkt_hdr_t     hdr;
    pkt_verdict_t v;
    uint16_t      len = build_tcp(frame, IP4(10, 0, 0, 1), IP4(10, 0, 0, 2), 40000u, 80u);

    CHECK(pkt_filter_init(&f, rules, 2u, PKT_DROP));

    /* Flood: 10 SYNs in the same millisecond. */
    for (uint32_t i = 0u; i < 10u; i++)
    {
        v = pkt_filter_process(&f, frame, len, 1000u, &hdr);
        CHECK_EQ(v.rule_idx, 0);
    }
    CHECK_EQ(f.passed, 3u);                                  /* the burst      */
    CHECK_EQ(f.dropped[DROP_REASON_RATE_LIMIT], 7u);
    CHECK_EQ(f.rule_hits[0], 10u);                           /* all matched r0 */

    /* Data packets (ACK) of open connections are not slowed down. */
    set_tcp_flags(frame, TCP_FLAG_ACK);
    v = pkt_filter_process(&f, frame, len, 1000u, &hdr);
    CHECK_EQ(v.action, PKT_PASS);
    CHECK_EQ(v.rule_idx, 1);

    /* 100 ms later one new connection may start again. */
    set_tcp_flags(frame, TCP_FLAG_SYN);
    v = pkt_filter_process(&f, frame, len, 1100u, &hdr);
    CHECK_EQ(v.action, PKT_PASS);
    CHECK_EQ(v.reason, DROP_REASON_NONE);
}

static void test_each_rule_has_its_own_bucket(void)
{
    const pkt_rule_t rules[] =
    {
        { .match = RULE_DST_PORT, .dst_port = 1000u, .action = PKT_RATE_LIMIT, .rate_pps = 1u, .burst = 1u },
        { .match = RULE_DST_PORT, .dst_port = 2000u, .action = PKT_RATE_LIMIT, .rate_pps = 1u, .burst = 1u },
    };
    pkt_filter_t f;
    pkt_hdr_t    hdr;
    uint16_t     len;

    CHECK(pkt_filter_init(&f, rules, 2u, PKT_DROP));

    len = build_udp(frame, IP4(10, 0, 0, 1), IP4(10, 0, 0, 2), 5u, 1000u);
    CHECK_EQ(pkt_filter_process(&f, frame, len, 0u, &hdr).action, PKT_PASS);
    CHECK_EQ(pkt_filter_process(&f, frame, len, 0u, &hdr).action, PKT_DROP);   /* r0 empty */

    len = build_udp(frame, IP4(10, 0, 0, 1), IP4(10, 0, 0, 2), 5u, 2000u);
    CHECK_EQ(pkt_filter_process(&f, frame, len, 0u, &hdr).action, PKT_PASS);   /* r1 full  */
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

    RUN_TEST(test_init_rejects_too_many_rules);
    RUN_TEST(test_process_verdicts);
    RUN_TEST(test_process_counters);
    RUN_TEST(test_malformed_never_reaches_rules);
    RUN_TEST(test_reason_names);

    RUN_TEST(test_tcp_flags_real_traffic_is_valid);
    RUN_TEST(test_tcp_flags_scans_are_invalid);
    RUN_TEST(test_scan_is_dropped_before_rules);
    RUN_TEST(test_udp_is_not_checked_for_flags);
    RUN_TEST(test_rule_on_tcp_flags);

    RUN_TEST(test_real_sources_are_not_spoofed);
    RUN_TEST(test_martian_sources_are_spoofed);
    RUN_TEST(test_dhcp_request_may_use_zero_source);
    RUN_TEST(test_land_attack_is_spoofed);
    RUN_TEST(test_group_source_mac_is_spoofed);
    RUN_TEST(test_spoofed_is_dropped_before_rules);

    RUN_TEST(test_bucket_starts_full_then_empties);
    RUN_TEST(test_bucket_refills_at_rate);
    RUN_TEST(test_bucket_never_exceeds_burst);
    RUN_TEST(test_bucket_survives_tick_wrap);
    RUN_TEST(test_bucket_no_overflow);
    RUN_TEST(test_init_rejects_bad_rate_limit);
    RUN_TEST(test_syn_flood_is_rate_limited);
    RUN_TEST(test_each_rule_has_its_own_bucket);
}
