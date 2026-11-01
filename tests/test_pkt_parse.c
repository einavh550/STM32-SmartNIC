/**
 * @file    test_pkt_parse.c
 * @brief   Unit tests for pkt_parse.c (Ethernet, IPv4, TCP/UDP headers).
 */

#include "test_framework.h"
#include "test_frames.h"

/* Big enough for every test frame; real frames go up to 1522 bytes. */
static uint8_t frame[128];

/* ------------------------------------------------------------------------- */
/* Ethernet                                                                  */
/* ------------------------------------------------------------------------- */

static void test_eth_arp_frame(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_eth(frame, ETHERTYPE_ARP);

    CHECK(pkt_parse_eth(frame, len, &hdr));
    CHECK_EQ(hdr.ethertype, ETHERTYPE_ARP);
    CHECK_EQ(hdr.dst_mac[0], 0xFF);
    CHECK_EQ(hdr.dst_mac[5], 0xFF);
    CHECK_EQ(hdr.src_mac[0], 0x02);
    CHECK_EQ(hdr.src_mac[5], 0x01);
    CHECK_EQ(hdr.valid, PKT_HAS_ETH);
}

static void test_eth_too_short_is_rejected(void)
{
    pkt_hdr_t hdr;

    memset(&hdr, 0xAA, sizeof(hdr));                 /* marker bytes */
    build_eth(frame, ETHERTYPE_IPV4);

    CHECK(!pkt_parse_eth(frame, ETH_HDR_LEN - 1u, &hdr));
    CHECK_EQ(hdr.ethertype, 0xAAAA);                  /* *out untouched */
    CHECK(!pkt_parse_eth(frame, 0u, &hdr));
}

static void test_eth_clears_layers_of_previous_frame(void)
{
    pkt_hdr_t hdr;

    /* Frame 1: full UDP packet, all three layers valid. */
    uint16_t len = build_udp(frame, IP4(10, 0, 0, 1), IP4(10, 0, 0, 2), 1000u, 137u);
    CHECK(parse_all(frame, len, &hdr));
    CHECK_EQ(hdr.valid, PKT_HAS_ETH | PKT_HAS_IPV4 | PKT_HAS_L4);

    /* Frame 2: ARP, same hdr struct. The old IP/port bits must be gone. */
    len = build_eth(frame, ETHERTYPE_ARP);
    CHECK(parse_all(frame, len, &hdr));
    CHECK_EQ(hdr.valid, PKT_HAS_ETH);
}

/* ------------------------------------------------------------------------- */
/* IPv4                                                                      */
/* ------------------------------------------------------------------------- */

static void test_ipv4_dhcp_discover(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_udp(frame, IP4(0, 0, 0, 0), IP4(255, 255, 255, 255), 68u, 67u);

    CHECK(pkt_parse_eth(frame, len, &hdr));
    CHECK(pkt_parse_ipv4(frame, len, &hdr));
    CHECK_EQ(hdr.src_ip, 0x00000000u);
    CHECK_EQ(hdr.dst_ip, 0xFFFFFFFFu);
    CHECK_EQ(hdr.ip_proto, IP_PROTO_UDP);
    CHECK_EQ(hdr.l4_offset, 34u);
    CHECK_EQ(hdr.ip_frag_off, 0u);
    CHECK_EQ(hdr.valid, PKT_HAS_ETH | PKT_HAS_IPV4);
}

static void test_ipv4_address_byte_order(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_udp(frame, IP4(192, 168, 7, 1), IP4(10, 1, 2, 3), 1u, 2u);

    CHECK(parse_all(frame, len, &hdr));
    CHECK_EQ(hdr.src_ip, 0xC0A80701u);   /* 192.168.7.1, not 1.7.168.192 */
    CHECK_EQ(hdr.dst_ip, 0x0A010203u);
}

static void test_ipv4_truncated_is_rejected(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_ipv4(frame, IP_PROTO_UDP, 1u, 2u);

    CHECK(pkt_parse_eth(frame, len, &hdr));
    CHECK(!pkt_parse_ipv4(frame, len - 1u, &hdr));   /* 19-byte IP header */
    CHECK_EQ(hdr.valid, PKT_HAS_ETH);
}

static void test_ipv4_wrong_version_is_rejected(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_ipv4(frame, IP_PROTO_UDP, 1u, 2u);

    frame[ETH_HDR_LEN] = 0x65;                        /* version 6, IHL 5 */
    CHECK(pkt_parse_eth(frame, len, &hdr));
    CHECK(!pkt_parse_ipv4(frame, len, &hdr));
}

static void test_ipv4_ihl_below_5_is_rejected(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_ipv4(frame, IP_PROTO_UDP, 1u, 2u);

    frame[ETH_HDR_LEN] = 0x44;                        /* IHL 4 = 16 bytes: impossible */
    CHECK(pkt_parse_eth(frame, len, &hdr));
    CHECK(!pkt_parse_ipv4(frame, len, &hdr));
}

static void test_ipv4_options_move_l4_offset(void)
{
    pkt_hdr_t hdr;
    uint8_t  *ip = &frame[ETH_HDR_LEN];

    /* IHL 6: 20-byte header + 4 bytes of options. UDP starts at 14 + 24 = 38. */
    build_ipv4(frame, IP_PROTO_UDP, 1u, 2u);
    ip[0] = 0x46;
    memset(&ip[20], 0x01, 4);                         /* 4 x NOP option     */
    wr_be16(&frame[38], 5000u);                       /* UDP src port       */
    wr_be16(&frame[40], 53u);                         /* UDP dst port       */
    wr_be16(&frame[42], UDP_HDR_LEN);
    wr_be16(&frame[44], 0u);

    CHECK(parse_all(frame, 46u, &hdr));
    CHECK_EQ(hdr.l4_offset, 38u);
    CHECK_EQ(hdr.src_port, 5000u);
    CHECK_EQ(hdr.dst_port, 53u);
}

static void test_ipv4_options_past_end_are_rejected(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_ipv4(frame, IP_PROTO_UDP, 1u, 2u);

    /* IHL 15 claims a 60-byte header, but the frame only has 20 IP bytes. */
    frame[ETH_HDR_LEN] = 0x4F;
    CHECK(pkt_parse_eth(frame, len, &hdr));
    CHECK(!pkt_parse_ipv4(frame, len, &hdr));
}

static void test_ipv4_fragment_offset_ignores_flags(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_udp(frame, 1u, 2u, 1u, 2u);
    uint8_t  *ip  = &frame[ETH_HDR_LEN];

    wr_be16(&ip[6], 0x4000u);                         /* Don't Fragment, offset 0 */
    CHECK(parse_all(frame, len, &hdr));
    CHECK_EQ(hdr.ip_frag_off, 0u);

    wr_be16(&ip[6], 0x2000u | 185u);                  /* More Fragments, offset 185 */
    CHECK(parse_all(frame, len, &hdr));
    CHECK_EQ(hdr.ip_frag_off, 185u);
}

/* ------------------------------------------------------------------------- */
/* TCP / UDP                                                                 */
/* ------------------------------------------------------------------------- */

static void test_l4_udp_ports(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_udp(frame, 1u, 2u, 68u, 67u);

    CHECK(parse_all(frame, len, &hdr));
    CHECK_EQ(hdr.src_port, 68u);
    CHECK_EQ(hdr.dst_port, 67u);
    CHECK(hdr.valid & PKT_HAS_L4);
}

static void test_l4_port_byte_order(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_udp(frame, 1u, 2u, 5000u, 2u);

    CHECK_EQ(frame[34], 0x13);                        /* 5000 = 0x1388 on the wire */
    CHECK_EQ(frame[35], 0x88);
    CHECK(parse_all(frame, len, &hdr));
    CHECK_EQ(hdr.src_port, 5000u);                    /* not 0x8813 = 34835 */
}

static void test_l4_tcp_ports(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_tcp(frame, 1u, 2u, 40000u, 80u);

    CHECK(parse_all(frame, len, &hdr));
    CHECK_EQ(hdr.ip_proto, IP_PROTO_TCP);
    CHECK_EQ(hdr.src_port, 40000u);
    CHECK_EQ(hdr.dst_port, 80u);
}

static void test_l4_truncated_udp_is_rejected(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_udp(frame, 1u, 2u, 1u, 2u);

    CHECK(parse_all(frame, len - 1u, &hdr));          /* only 7 UDP bytes */
    CHECK((hdr.valid & PKT_HAS_L4) == 0u);
}

static void test_l4_short_tcp_is_rejected(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_tcp(frame, 1u, 2u, 1u, 2u);

    /* 8 bytes is enough for UDP, but TCP needs 20. */
    CHECK(parse_all(frame, len - 12u, &hdr));
    CHECK((hdr.valid & PKT_HAS_L4) == 0u);
}

static void test_l4_icmp_has_no_ports(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_ipv4(frame, IP_PROTO_ICMP, 1u, 2u);

    memset(&frame[len], 0, 8);                        /* echo request body */
    frame[len] = 8;
    CHECK(parse_all(frame, len + 8u, &hdr));
    CHECK(!pkt_parse_l4(frame, len + 8u, &hdr));
    CHECK_EQ(hdr.valid, PKT_HAS_ETH | PKT_HAS_IPV4);
}

static void test_l4_non_first_fragment_has_no_ports(void)
{
    pkt_hdr_t hdr;
    uint16_t  len = build_udp(frame, 1u, 2u, 68u, 67u);

    wr_be16(&frame[ETH_HDR_LEN + 6], 185u);           /* later piece: payload, not ports */
    CHECK(parse_all(frame, len, &hdr));
    CHECK((hdr.valid & PKT_HAS_L4) == 0u);
}

/* ------------------------------------------------------------------------- */

void run_pkt_parse_tests(void)
{
    RUN_TEST(test_eth_arp_frame);
    RUN_TEST(test_eth_too_short_is_rejected);
    RUN_TEST(test_eth_clears_layers_of_previous_frame);

    RUN_TEST(test_ipv4_dhcp_discover);
    RUN_TEST(test_ipv4_address_byte_order);
    RUN_TEST(test_ipv4_truncated_is_rejected);
    RUN_TEST(test_ipv4_wrong_version_is_rejected);
    RUN_TEST(test_ipv4_ihl_below_5_is_rejected);
    RUN_TEST(test_ipv4_options_move_l4_offset);
    RUN_TEST(test_ipv4_options_past_end_are_rejected);
    RUN_TEST(test_ipv4_fragment_offset_ignores_flags);

    RUN_TEST(test_l4_udp_ports);
    RUN_TEST(test_l4_port_byte_order);
    RUN_TEST(test_l4_tcp_ports);
    RUN_TEST(test_l4_truncated_udp_is_rejected);
    RUN_TEST(test_l4_short_tcp_is_rejected);
    RUN_TEST(test_l4_icmp_has_no_ports);
    RUN_TEST(test_l4_non_first_fragment_has_no_ports);
}
