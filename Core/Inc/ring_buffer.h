/**
 * @file    ring_buffer.h
 * @brief   Lock-free Single-Producer Single-Consumer (SPSC) ring buffer for packet descriptors.
 *
 * @note    Concurrency Contract:
 *          - Single-Producer (ISR): Strictly ONE interrupt context (ETH RX ISR) may call rb_push().
 *            Calling rb_push() from multiple ISRs of different priorities will cause a race condition.
 *          - Single-Consumer (Main): Strictly the main loop context may call rb_pop().
 *          - Lock-free synchronization using C11 acquire/release atomics, interrupts are never disabled.
 */

#ifndef INC_RING_BUFFER_H_
#define INC_RING_BUFFER_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/* ------------------------------------------------------------------------- */
/* Configuration                                                             */
/* ------------------------------------------------------------------------- */

/** Number of descriptor slots in the ring. MUST be a power of two (2^8). */
#define RB_CAPACITY     (256u)

/** Mask that maps a free-running index to a slot number: slot = index & RB_MASK. */
#define RB_MASK         (RB_CAPACITY - 1u)

/* Compile-time guard: the masking trick (index & RB_MASK) is only correct
 * when RB_CAPACITY is a non-zero power of two. Break the build otherwise. */
_Static_assert((RB_CAPACITY != 0u) && ((RB_CAPACITY & RB_MASK) == 0u),
               "RB_CAPACITY must be a non-zero power of two");

/* ------------------------------------------------------------------------- */
/* Types                                                                     */
/* ------------------------------------------------------------------------- */

/**
 * @brief Describes one received Ethernet frame without containing it.
 *
 * The ring stores these small descriptors (8 bytes) instead of whole frames
 * (up to 1518 bytes), so the ISR never copies payload data.
 * Fields are ordered largest-alignment first so the struct has no padding.
 */
typedef struct
{
    uint8_t  *data;   /**< Start of the frame in a DMA-capable RX buffer.         */
    uint16_t  len;    /**< Frame length in bytes (max 1518 fits in 16 bits).      */
    uint16_t  flags;  /**< Status bits from the ETH DMA (e.g. CRC error), Phase 2. */
} pkt_desc_t;

/**
 * @brief SPSC ring of packet descriptors.
 *
 * head and tail are free-running counters: they only ever increase and wrap
 * naturally at 2^32. The slot is (index & RB_MASK), and the number of used
 * slots is (head - tail), which stays correct across the wrap because
 * unsigned arithmetic is modulo 2^32 and RB_CAPACITY divides 2^32.
 *
 * Each index has exactly ONE writer, so no locks are needed.
 * The full type is public only so it can be allocated statically;
 * access it through the rb_* functions, never by touching fields directly.
 */
typedef struct
{
    pkt_desc_t       buf[RB_CAPACITY]; /**< Slot storage. Producer fills a slot, consumer empties it. */
    _Atomic uint32_t head;             /**< Next slot to write. Written ONLY by producer (ISR), read by consumer. */
    _Atomic uint32_t tail;             /**< Next slot to read. Written ONLY by consumer (main), read by producer. */
    _Atomic uint32_t dropped;          /**< Frames rejected because the ring was full. Written ONLY by producer. */
} ring_buffer_t;

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

/**
 * @brief  Reset the ring to empty and clear the drop counter.
 * @note   Call once from main BEFORE the ETH RX interrupt is enabled.
 *         It is not safe to call while the producer or consumer is running.
 */
void rb_init(ring_buffer_t *rb);

/**
 * @brief  Copy one descriptor into the ring.
 * @note   PRODUCER ONLY (ETH RX ISR). Never blocks.
 * @return true if stored, false if the ring was full (dropped is incremented).
 */
bool rb_push(ring_buffer_t *rb, const pkt_desc_t *desc);

/**
 * @brief  Copy the oldest descriptor out of the ring into *out.
 * @note   CONSUMER ONLY (main loop). Never blocks.
 * @return true if *out was filled, false if the ring was empty (*out untouched).
 */
bool rb_pop(ring_buffer_t *rb, pkt_desc_t *out);

/**
 * @brief  Number of descriptors currently waiting in the ring.
 * @note   Safe from either side, but only a snapshot: the other side may
 *         change it immediately after it is read. Use for stats, not decisions.
 */
uint32_t rb_count(const ring_buffer_t *rb);

/**
 * @brief  Total frames rejected because the ring was full since rb_init().
 * @note   Safe from either side.
 */
uint32_t rb_dropped(const ring_buffer_t *rb);

#endif /* INC_RING_BUFFER_H_ */
