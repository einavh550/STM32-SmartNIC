/**
 * @file    ring_buffer_test.h
 * @brief   On-target self-test for the SPSC ring buffer.
 */

#ifndef INC_RING_BUFFER_TEST_H_
#define INC_RING_BUFFER_TEST_H_

#include <stdint.h>

/** On/off switch: comment this line out to remove the self-test from the firmware. */
#define RB_SELF_TEST

#ifdef RB_SELF_TEST
/**
 * @brief  Run all ring buffer checks and print the result over the COM port.
 * @note   Single-threaded: call from main before any interrupt uses a ring.
 * @return Number of failed checks (0 = all passed).
 */
uint32_t rb_self_test(void);
#endif

#endif /* INC_RING_BUFFER_TEST_H_ */
