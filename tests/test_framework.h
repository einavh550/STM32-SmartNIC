/**
 * @file    test_framework.h
 * @brief   Minimal unit-test helpers for host (PC) tests. No external library.
 *
 * A CHECK that fails prints the file, line and expression, then the test
 * keeps going, so one run shows every failure, not only the first.
 */

#ifndef TESTS_TEST_FRAMEWORK_H_
#define TESTS_TEST_FRAMEWORK_H_

#include <stdio.h>

/* Counters live in test_main.c. */
extern int tf_checks;     /**< CHECKs run so far.           */
extern int tf_failures;   /**< CHECKs that failed so far.   */

/** Fail if cond is false. */
#define CHECK(cond)                                                         \
    do {                                                                    \
        tf_checks++;                                                        \
        if (!(cond)) {                                                      \
            tf_failures++;                                                  \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
        }                                                                   \
    } while (0)

/** Fail if a != b, and print both values (as unsigned long, in hex). */
#define CHECK_EQ(a, b)                                                      \
    do {                                                                    \
        unsigned long tf_a = (unsigned long)(a);                            \
        unsigned long tf_b = (unsigned long)(b);                            \
        tf_checks++;                                                        \
        if (tf_a != tf_b) {                                                 \
            tf_failures++;                                                  \
            printf("  FAIL %s:%d: %s == %s (got 0x%lX, expected 0x%lX)\n",  \
                   __FILE__, __LINE__, #a, #b, tf_a, tf_b);                 \
        }                                                                   \
    } while (0)

/** Run one test function and print its name. */
#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        printf("%s\n", #fn);                                                \
        fn();                                                               \
    } while (0)

#endif /* TESTS_TEST_FRAMEWORK_H_ */
