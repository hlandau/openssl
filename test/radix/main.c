/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

OPT_TEST_DECLARE_USAGE("cert_file key_file\n")

/*
 * A RADIX test suite binding must define:
 *
 *   static SCRIPT_INFO *const scripts[];
 *
 *   int bindings_process_init(size_t node_idx, size_t process_idx);
 *   void bindings_process_finish();
 *
 */
static int test_script(int idx)
{
    SCRIPT_INFO *script_info = scripts[idx];
    int testresult;

    if (!TEST_true(bindings_process_init(0, 0)))
        return 0;

    testresult = TERP_run(script_info);

    if (!TEST_true(bindings_process_finish()))
        testresult = 0;

    return testresult;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert_file = test_get_argument(0))
        || !TEST_ptr(key_file = test_get_argument(1)))
        return 0;

    ADD_ALL_TESTS(test_script, OSSL_NELEM(scripts));
    return 1;
}
