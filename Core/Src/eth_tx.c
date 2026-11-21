/**
 * @file    eth_tx.c
 * @brief   Ethernet TX path (Phase 6): lean TX descriptor driver, main loop only.
 */

#include "eth_tx.h"
#include "eth_rx.h"
#include "stm32h7xx_hal.h"
#include <stdio.h>
#include <string.h>

extern ETH_HandleTypeDef heth;           /* main.c (CubeMX) */

/* Ring state (main loop only, so plain variables):
 *   tx_head = next descriptor to fill,
 *   tx_tail = oldest descriptor not yet reclaimed,
 *   tx_used = descriptors between them, owned by the DMA or waiting to be
 *             reclaimed.
 * tx_desc_buf[] remembers each descriptor's buffer, in cached RAM. */
static uint8_t *tx_desc_buf[ETH_TX_DESC_CNT];
static uint32_t tx_head;
static uint32_t tx_tail;
static uint32_t tx_used;
static eth_tx_stats_t stats;

static inline uint32_t tx_idx_next(uint32_t i)
{
    return (i + 1u == ETH_TX_DESC_CNT) ? 0u : (i + 1u);
}

void eth_tx_init(void)
{
    /* HAL_ETH_Init() cleared the 4 TX descriptors (OWN = 0) and pointed the
     * DMA's ring base and tail pointer at descriptor 0; HAL_ETH_Start_IT()
     * started the TX DMA, which found nothing to send and suspended. The
     * HAL TX functions are never called, so the ring is ours from index 0. */
    tx_head = 0u;
    tx_tail = 0u;
    tx_used = 0u;
    for (uint32_t i = 0u; i < ETH_TX_DESC_CNT; i++)
    {
        tx_desc_buf[i] = NULL;
    }
}

bool eth_tx_send(uint8_t *buf, uint16_t len)
{
    if (tx_used == ETH_TX_DESC_CNT)
    {
        stats.busy++;                    /* ring full: never wait */
        return false;
    }

    ETH_DMADescTypeDef *desc = &heth.Init.TxDesc[tx_head];
    tx_desc_buf[tx_head] = buf;

    desc->DESC0 = (uint32_t)buf;         /* buffer 1 address */
    desc->DESC1 = 0u;                    /* no buffer 2 */
    desc->DESC2 = len & ETH_DMATXNDESCRF_B1L;   /* buffer 1 length, no IOC */
    /* The DMA must see the address and length BEFORE it sees OWN. */
    __DMB();
    /* One whole frame (first + last), MAC inserts CRC + padding, no
     * checksum insertion (the frame's checksums are already right). */
    desc->DESC3 = ETH_DMATXNDESCRF_OWN | ETH_DMATXNDESCRF_FD | ETH_DMATXNDESCRF_LD |
                  ETH_DMATXNDESCRF_CPC_CRCPAD_INSERT | ETH_DMATXNDESCRF_CIC_DISABLE |
                  (len & ETH_DMATXNDESCRF_FL);

    tx_head = tx_idx_next(tx_head);
    tx_used++;
    stats.sent++;

    /* Tail pointer = the descriptor AFTER the last valid one: the DMA sends
     * up to it and then suspends. Writing it also wakes a suspended DMA. */
    __DMB();
    heth.Instance->DMACTDTPR = (uint32_t)&heth.Init.TxDesc[tx_head];
    return true;
}

uint32_t eth_tx_reclaim(void)
{
    uint32_t n = 0u;

    while (tx_used > 0u)
    {
        const uint32_t d3 = heth.Init.TxDesc[tx_tail].DESC3;   /* ONE read */
        if ((d3 & ETH_DMATXNDESCWBF_OWN) != 0u)
        {
            break;                       /* still being sent */
        }
        if ((d3 & ETH_DMATXNDESCWBF_ES) != 0u)
        {
            stats.errors++;
        }

        uint8_t *buf = tx_desc_buf[tx_tail];
        tx_desc_buf[tx_tail] = NULL;
        if (eth_rx_buf_is_pool(buf))
        {
            eth_rx_buf_free(buf);        /* forwarded RX buffer: back to the pool */
        }

        tx_tail = tx_idx_next(tx_tail);
        tx_used--;
        stats.done++;
        n++;
    }
    return n;
}

void eth_tx_get_stats(eth_tx_stats_t *out)
{
    *out = stats;
    out->in_flight = tx_used;
}

/* ------------------------------------------------------------------------- */
/* Test frame                                                                */
/* ------------------------------------------------------------------------- */

/* In D2 SRAM next to the RX pool: the ETH DMA can read it and it is not
 * cached (MPU region 1). A normal variable would sit in D1 SRAM, which is
 * cached: the DMA could send stale bytes unless the cache is cleaned. */
static uint8_t test_frame[128] __attribute__((section(".RxBuffSection"), aligned(32)));

/* Internet checksum (RFC 1071) of the IPv4 header. */
static uint16_t ip_checksum(const uint8_t *p, uint32_t len)
{
    uint32_t sum = 0u;
    for (uint32_t i = 0u; i + 1u < len; i += 2u)
    {
        sum += ((uint32_t)p[i] << 8) | p[i + 1u];
    }
    while ((sum >> 16) != 0u)
    {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

bool eth_tx_send_test(uint32_t seq)
{
    /* The test frame has one buffer: do not rewrite it while the previous
     * one is still queued (reclaim clears its tx_desc_buf[] slot). */
    for (uint32_t i = 0u; i < ETH_TX_DESC_CNT; i++)
    {
        if (tx_desc_buf[i] == test_frame)
        {
            return false;
        }
    }

    char payload[40];
    int plen = snprintf(payload, sizeof payload, "STM32-SmartNIC TX test #%lu",
                        (unsigned long)seq);
    if (plen < 0)
    {
        return false;
    }
    if ((uint32_t)plen >= sizeof payload)
    {
        plen = (int)sizeof payload - 1;
    }

    uint8_t *f = test_frame;
    const uint16_t udp_len = (uint16_t)(8 + plen);
    const uint16_t ip_len  = (uint16_t)(20 + udp_len);

    /* Ethernet: broadcast <- board MAC (00:80:E1:00:00:00, see MX_ETH_Init), IPv4 */
    memset(f, 0xFF, 6);
    memcpy(&f[6], heth.Init.MACAddr, 6);
    put16(&f[12], 0x0800u);

    /* IPv4: no options, DF, TTL 64, UDP, 192.168.10.1 -> 192.168.10.255 */
    uint8_t *ip = &f[14];
    ip[0] = 0x45u;
    ip[1] = 0u;
    put16(&ip[2], ip_len);
    put16(&ip[4], (uint16_t)seq);        /* identification */
    put16(&ip[6], 0x4000u);              /* DF, offset 0 */
    ip[8] = 64u;
    ip[9] = 17u;
    put16(&ip[10], 0u);                  /* checksum: computed below */
    ip[12] = 192u; ip[13] = 168u; ip[14] = 10u; ip[15] = 1u;
    ip[16] = 192u; ip[17] = 168u; ip[18] = 10u; ip[19] = 255u;
    put16(&ip[10], ip_checksum(ip, 20u));

    /* UDP 5000 -> 5001, checksum 0 = "not computed" (allowed in IPv4) */
    uint8_t *udp = &ip[20];
    put16(&udp[0], 5000u);
    put16(&udp[2], 5001u);
    put16(&udp[4], udp_len);
    put16(&udp[6], 0u);
    memcpy(&udp[8], payload, (size_t)plen);

    /* test_frame is non-cacheable, so the bytes are in RAM already; the
     * __DMB() inside eth_tx_send() orders them before the OWN bit. */
    return eth_tx_send(test_frame, (uint16_t)(14u + ip_len));
}
