/**
 * @file    test_pkt_reflect.c
 * @brief   Host tests for pkt_reflect.c: in-place UDP reply.
 */

#include "test_framework.h"
#include "test_frames.h"
#include "pkt_reflect.h"

#define BOARD_IP   IP4(192, 168, 10, 1)
#define BBB_IP     IP4(192, 168, 10, 2)

static const uint8_t board_mac[ETH_MAC_LEN] = { 0x00, 0x80, 0xE1, 0x00, 0x00, 0x00 };
static const uint8_t bbb_mac[ETH_MAC_LEN]   = { 0x64, 0x70, 0x60, 0xDE, 0x5A, 0xD9 };

/* One's-complement sum of 16-bit big-endian words (RFC 1071), not folded. */
static uint32_t sum16(const uint8_t *p, uint32_t n, uint32_t sum)
{
    for (uint32_t i = 0u; i + 1u < n; i += 2u)
    {
        sum += ((uint32_t)p[i] << 8) | p[i + 1u];
    }
    if ((n & 1u) != 0u)
    {
        sum += (uint32_t)p[n - 1u] << 8;
    }
    return sum;
}

static uint16_t fold(uint32_t sum)
{
    while ((sum >> 16) != 0u)
    {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/* IPv4 header checksum over 20 bytes (0 = valid when the field is filled). */
static uint16_t ip_csum(const uint8_t *ip)
{
    return fold(sum16(ip, IPV4_MIN_HDR_LEN, 0u));
}

/* UDP checksum incl. the pseudo-header (0 = valid when the field is filled). */
static uint16_t udp_csum(const uint8_t *f, uint16_t udp_len)
{
    const uint8_t *ip  = &f[ETH_HDR_LEN];
    const uint8_t *udp = &ip[IPV4_MIN_HDR_LEN];
    uint32_t s = sum16(&ip[12], 8u, 0u);         /* src + dst IP */
    s += IP_PROTO_UDP;
    s += udp_len;
    return fold(sum16(udp, udp_len, s));
}

/* A valid UDP frame BBB:40000 -> board:5000 with 6 payload bytes and both
 * checksums filled in, like nic_test.py sends. Returns the frame length. */
static uint16_t build_bbb_udp(uint8_t *f)
{
    const uint16_t udp_len = UDP_HDR_LEN + 6u;
    uint16_t l4 = build_ipv4(f, IP_PROTO_UDP, BBB_IP, BOARD_IP, udp_len);
    memcpy(&f[0], board_mac, ETH_MAC_LEN);
    memcpy(&f[6], bbb_mac, ETH_MAC_LEN);
    wr_be16(&f[ETH_HDR_LEN + 10], ip_csum(&f[ETH_HDR_LEN]));

    uint8_t *udp = &f[l4];
    wr_be16(&udp[0], 40000u);
    wr_be16(&udp[2], 5000u);
    wr_be16(&udp[4], udp_len);
    wr_be16(&udp[6], 0u);
    memcpy(&udp[8], "abcdef", 6u);
    wr_be16(&udp[6], udp_csum(f, udp_len));
    return (uint16_t)(l4 + udp_len);
}

static void test_swaps_mac_ip_ports(void)
{
    uint8_t f[128] = { 0 };
    uint16_t len = build_bbb_udp(f);
    pkt_hdr_t hdr;
    CHECK(pkt_parse_frame(f, len, &hdr));

    CHECK(pkt_reflect_udp(f, len, &hdr, board_mac, BOARD_IP));

    CHECK(memcmp(&f[0], bbb_mac, ETH_MAC_LEN) == 0);     /* to the sender */
    CHECK(memcmp(&f[6], board_mac, ETH_MAC_LEN) == 0);   /* from us       */

    pkt_hdr_t out;
    CHECK(pkt_parse_frame(f, len, &out));
    CHECK_EQ(out.src_ip, BOARD_IP);
    CHECK_EQ(out.dst_ip, BBB_IP);
    CHECK_EQ(out.src_port, 5000u);
    CHECK_EQ(out.dst_port, 40000u);
    CHECK(memcmp(&f[42], "abcdef", 6u) == 0);           /* payload untouched */
}

static void test_checksums_stay_valid(void)
{
    uint8_t f[128] = { 0 };
    uint16_t len = build_bbb_udp(f);
    const uint16_t udp_len = (uint16_t)(len - ETH_HDR_LEN - IPV4_MIN_HDR_LEN);
    CHECK_EQ(ip_csum(&f[ETH_HDR_LEN]), 0u);              /* valid before */
    CHECK_EQ(udp_csum(f, udp_len), 0u);

    pkt_hdr_t hdr;
    CHECK(pkt_parse_frame(f, len, &hdr));
    CHECK(pkt_reflect_udp(f, len, &hdr, board_mac, BOARD_IP));

    /* Not recomputed, still valid: the swaps only reorder the summed words. */
    CHECK_EQ(ip_csum(&f[ETH_HDR_LEN]), 0u);
    CHECK_EQ(udp_csum(f, udp_len), 0u);
}

/* Each case must return false and leave every byte as it was. */
static void expect_untouched(uint8_t *f, uint16_t len, const pkt_hdr_t *hdr)
{
    uint8_t before[128];
    memcpy(before, f, len);
    CHECK(!pkt_reflect_udp(f, len, hdr, board_mac, BOARD_IP));
    CHECK(memcmp(before, f, len) == 0);
}

static void test_tcp_not_reflected(void)
{
    uint8_t f[128] = { 0 };
    uint16_t len = build_tcp(f, BBB_IP, BOARD_IP, 40001u, 80u);
    pkt_hdr_t hdr;
    CHECK(pkt_parse_frame(f, len, &hdr));
    expect_untouched(f, len, &hdr);
}

static void test_not_for_us_not_reflected(void)
{
    uint8_t f[128] = { 0 };
    uint16_t len = build_udp(f, BBB_IP, IP4(192, 168, 10, 255), 68u, 67u);
    pkt_hdr_t hdr;
    CHECK(pkt_parse_frame(f, len, &hdr));
    expect_untouched(f, len, &hdr);                      /* subnet broadcast */

    len = build_udp(f, BBB_IP, IP4(192, 168, 10, 7), 40000u, 5000u);
    CHECK(pkt_parse_frame(f, len, &hdr));
    expect_untouched(f, len, &hdr);                      /* another host */
}

static void test_fragment_not_reflected(void)
{
    uint8_t f[128] = { 0 };
    uint16_t len = build_bbb_udp(f);
    f[ETH_HDR_LEN + 6] |= 0x20u;                         /* more fragments */
    pkt_hdr_t hdr;
    CHECK(pkt_parse_frame(f, len, &hdr));
    expect_untouched(f, len, &hdr);
}

static void test_unparsed_not_reflected(void)
{
    uint8_t f[128] = { 0 };
    uint16_t len = build_bbb_udp(f);
    pkt_hdr_t hdr;
    CHECK(pkt_parse_frame(f, len, &hdr));
    hdr.valid &= (uint8_t)~PKT_HAS_L4;                   /* e.g. truncated L4 */
    expect_untouched(f, len, &hdr);
}

void run_pkt_reflect_tests(void)
{
    RUN_TEST(test_swaps_mac_ip_ports);
    RUN_TEST(test_checksums_stay_valid);
    RUN_TEST(test_tcp_not_reflected);
    RUN_TEST(test_not_for_us_not_reflected);
    RUN_TEST(test_fragment_not_reflected);
    RUN_TEST(test_unparsed_not_reflected);
}
