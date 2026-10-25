/**
 * @file    ring_buffer.c
 * @brief   Lock-free SPSC ring buffer implementation.
 *
 * @note    Memory-ordering rule used throughout this file:
 *          - A side reads ITS OWN index with relaxed order (it is the only writer).
 *          - A side reads the OTHER side's index with acquire order.
 *          - A side publishes its own index with release order, AFTER touching the slot.
 *          Each release store pairs with the other side's acquire load.
 */

#include "ring_buffer.h"

void rb_init(ring_buffer_t *rb)
{
    /* Runs before the ETH IRQ is enabled, so there is no concurrency yet and
     * relaxed stores are enough. The slots in buf[] are not cleared: a slot is
     * always written before head makes it visible, so old contents are never read. */
    atomic_store_explicit(&rb->head,    0u, memory_order_relaxed);
    atomic_store_explicit(&rb->tail,    0u, memory_order_relaxed);
    atomic_store_explicit(&rb->dropped, 0u, memory_order_relaxed);
}

bool rb_push(ring_buffer_t *rb, const pkt_desc_t *desc)
{
    /* Our own index: only this ISR writes head, so no ordering is needed. */
    const uint32_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);

    /* The consumer's index: acquire pairs with the release store in rb_pop(),
     * so the consumer has finished reading a slot before we see it as free. */
    const uint32_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);

    if ((head - tail) >= RB_CAPACITY)
    {
        /* Full: drop the frame instead of waiting. We are the only writer of
         * dropped, so a plain load + store is enough (no read-modify-write). */
        const uint32_t d = atomic_load_explicit(&rb->dropped, memory_order_relaxed);
        atomic_store_explicit(&rb->dropped, d + 1u, memory_order_relaxed);
        return false;
    }

    /* Fill the slot first ... */
    rb->buf[head & RB_MASK] = *desc;

    /* ... then publish it. Release guarantees the slot write above is visible
     * to the consumer before it can observe the new head value. */
    atomic_store_explicit(&rb->head, head + 1u, memory_order_release);
    return true;
}

bool rb_pop(ring_buffer_t *rb, pkt_desc_t *out)
{
    /* Our own index: only main writes tail, so no ordering is needed. */
    const uint32_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);

    /* The producer's index: acquire pairs with the release store in rb_push(),
     * so the slot contents are visible before we read them. */
    const uint32_t head = atomic_load_explicit(&rb->head, memory_order_acquire);

    if (head == tail)
    {
        return false; /* Empty. *out is left untouched. */
    }

    /* Read the slot first ... */
    *out = rb->buf[tail & RB_MASK];

    /* ... then free it. Release guarantees the read above is finished
     * before the producer can see the slot as free and overwrite it. */
    atomic_store_explicit(&rb->tail, tail + 1u, memory_order_release);
    return true;
}

uint32_t rb_count(const ring_buffer_t *rb)
{
    /* Snapshot only: no slot data is read, so relaxed is enough. */
    const uint32_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);
    const uint32_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);
    return head - tail;
}

uint32_t rb_dropped(const ring_buffer_t *rb)
{
    return atomic_load_explicit(&rb->dropped, memory_order_relaxed);
}
