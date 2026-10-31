/**
 * @file    ring_buffer_test.c
 * @brief   On-target self-test for the SPSC ring buffer.
 *
 * @note    Compiled only when RB_SELF_TEST is defined in ring_buffer_test.h.
 */

#include "ring_buffer_test.h"

#ifdef RB_SELF_TEST

#include <stdio.h>
#include "ring_buffer.h"

static ring_buffer_t s_test_ring;
static uint32_t      s_failures;

/* Count a failure and print which check failed. */
#define RB_CHECK(cond)                                              \
    do {                                                            \
        if (!(cond)) {                                              \
            s_failures++;                                           \
            printf("FAIL line %d: %s\r\n", __LINE__, #cond);        \
        }                                                           \
    } while (0)

uint32_t rb_self_test(void)
{
    ring_buffer_t *rb = &s_test_ring;
    uint8_t fake_frame[4];
    pkt_desc_t in = { fake_frame, 64u, 0u };
    pkt_desc_t out;

    s_failures = 0u;

    /* 1. A fresh ring is empty. */
    rb_init(rb);
    RB_CHECK(rb_count(rb) == 0u);
    RB_CHECK(rb_pop(rb, &out) == false);

    /* 2. One in, the same one out. */
    RB_CHECK(rb_push(rb, &in) == true);
    RB_CHECK(rb_count(rb) == 1u);
    RB_CHECK(rb_pop(rb, &out) == true);
    RB_CHECK(out.data == fake_frame && out.len == 64u);
    RB_CHECK(rb_count(rb) == 0u);

    /* 3. Fill it completely, then one more must be dropped. */
    for (uint32_t i = 0u; i < RB_CAPACITY; i++)
    {
        in.len = (uint16_t)i;
        RB_CHECK(rb_push(rb, &in) == true);
    }
    RB_CHECK(rb_count(rb) == RB_CAPACITY);
    RB_CHECK(rb_push(rb, &in) == false);
    RB_CHECK(rb_dropped(rb) == 1u);

    /* 4. Empty it: frames come out in the same order they went in (FIFO). */
    for (uint32_t i = 0u; i < RB_CAPACITY; i++)
    {
        RB_CHECK(rb_pop(rb, &out) == true && out.len == (uint16_t)i);
    }
    RB_CHECK(rb_pop(rb, &out) == false);

    /* 5. Counters wrap past 2^32. Test-only shortcut: start them near the top. */
    rb_init(rb);
    atomic_store(&rb->head, 0xFFFFFFFEu);
    atomic_store(&rb->tail, 0xFFFFFFFEu);
    for (uint32_t i = 0u; i < 4u; i++)
    {
        in.len = (uint16_t)(100u + i);
        RB_CHECK(rb_push(rb, &in) == true);
    }
    RB_CHECK(rb_count(rb) == 4u);        /* head wrapped to 2, tail still 0xFFFFFFFE */
    for (uint32_t i = 0u; i < 4u; i++)
    {
        RB_CHECK(rb_pop(rb, &out) == true && out.len == (uint16_t)(100u + i));
    }
    RB_CHECK(rb_count(rb) == 0u);

    printf("RB self-test: %s (%lu failures)\r\n",
           (s_failures == 0u) ? "PASS" : "FAIL",
           (unsigned long)s_failures);
    return s_failures;
}

#endif /* RB_SELF_TEST */
