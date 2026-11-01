/**
 * @file    test_main.c
 * @brief   Host test runner: runs every test suite and reports the result.
 *
 * Exit code 0 = all passed, 1 = something failed. CI uses the exit code.
 */

#include "test_framework.h"

int tf_checks   = 0;
int tf_failures = 0;

void run_pkt_parse_tests(void);
void run_pkt_filter_tests(void);
void run_filter_policy_tests(void);

int main(void)
{
    printf("== pkt_parse ==\n");
    run_pkt_parse_tests();

    printf("== pkt_filter ==\n");
    run_pkt_filter_tests();

    printf("== filter_policy ==\n");
    run_filter_policy_tests();

    printf("\n%d checks, %d failed: %s\n", tf_checks, tf_failures,
           (tf_failures == 0) ? "PASS" : "FAIL");

    return (tf_failures == 0) ? 0 : 1;
}
