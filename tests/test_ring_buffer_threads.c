/**
 * @file    test_ring_buffer_threads.c
 * @brief   Two-thread stress test of the SPSC ring buffer, run under
 *          ThreadSanitizer (TSan) in CI.
 *
 * On the board the producer is the ETH RX interrupt and the consumer is the
 * main loop. Here they are two real threads on two CPU cores, which is a
 * harsher test: they truly run at the same time, and the compiler and the CPU
 * are both free to reorder memory accesses.
 *
 * The producer pushes N descriptors numbered 0..N-1; when the ring is full it
 * retries, so nothing is lost on purpose. The consumer checks it gets every
 * number exactly once, in order, with the payload fields intact. TSan checks
 * that every shared access is properly synchronised: if the acquire/release
 * pairing in ring_buffer.c were wrong, it reports a data race and the test
 * fails even when the numbers happen to come out right.
 *
 * Linux/macOS only (pthreads + TSan):  make -C tests tsan
 */

#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>

#include "ring_buffer.h"

#define N_FRAMES  (2000000u)   /* ~7800 times around the 256-slot ring */

static ring_buffer_t ring;
static uint32_t      push_full;   /* producer only: pushes refused (ring full) */

/* Build a descriptor whose every field depends on the sequence number, so a
 * torn or stale slot (fields from two different pushes) is caught. The data
 * pointer is never dereferenced; it only carries the number. */
static pkt_desc_t make_desc(uint32_t seq)
{
    pkt_desc_t d;
    d.data  = (uint8_t *)(uintptr_t)(seq + 1u);
    d.len   = (uint16_t)(seq & 0xFFFFu);
    d.flags = (uint16_t)(seq >> 16);
    return d;
}

static void *producer(void *arg)
{
    (void)arg;
    for (uint32_t seq = 0u; seq < N_FRAMES; seq++)
    {
        const pkt_desc_t d = make_desc(seq);
        while (!rb_push(&ring, &d))
        {
            push_full++;
            sched_yield();   /* ring full: let the consumer catch up */
        }
    }
    return NULL;
}

static void *consumer(void *arg)
{
    uint32_t *errors = (uint32_t *)arg;
    uint32_t  expect = 0u;

    while (expect < N_FRAMES)
    {
        pkt_desc_t d;
        if (!rb_pop(&ring, &d))
        {
            sched_yield();   /* ring empty: let the producer run */
            continue;
        }

        const pkt_desc_t want = make_desc(expect);
        if ((d.data != want.data) || (d.len != want.len) || (d.flags != want.flags))
        {
            if (*errors < 5u)   /* print the first few only */
            {
                printf("  FAIL: frame %" PRIu32 ": got data=%p len=%u flags=%u\n",
                       expect, (void *)d.data, (unsigned)d.len, (unsigned)d.flags);
            }
            (*errors)++;
        }
        expect++;
    }
    return NULL;
}

int main(void)
{
    uint32_t errors = 0u;
    pthread_t prod;
    pthread_t cons;

    rb_init(&ring);

    if ((pthread_create(&cons, NULL, consumer, &errors) != 0) ||
        (pthread_create(&prod, NULL, producer, NULL) != 0))
    {
        printf("FAIL: could not start threads\n");
        return 1;
    }
    pthread_join(prod, NULL);
    pthread_join(cons, NULL);

    /* Every refused push must be counted as dropped, and the ring must end empty. */
    if (rb_dropped(&ring) != push_full)
    {
        printf("  FAIL: dropped %" PRIu32 " != refused pushes %" PRIu32 "\n",
               rb_dropped(&ring), push_full);
        errors++;
    }
    if (rb_count(&ring) != 0u)
    {
        printf("  FAIL: ring not empty at the end (%" PRIu32 ")\n", rb_count(&ring));
        errors++;
    }

    printf("ring buffer 2-thread test: %" PRIu32 " frames, %" PRIu32
           " pushes refused (ring full), %" PRIu32 " errors -> %s\n",
           (uint32_t)N_FRAMES, push_full, errors, (errors == 0u) ? "PASS" : "FAIL");
    return (errors == 0u) ? 0 : 1;
}
