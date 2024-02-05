/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Test Scripts
 * ============================================================================
 */
static int some_helper(FUNC_CTX *fctx)
{
    int ok;
    const char *buf = NULL;
    size_t buf_len = 0;

    F_POP2(buf, buf_len);

    TEST_info("some_helper: %p(%s) %p", (char*)buf, (char *)buf, (void*)buf_len);

    F_POP2(buf, buf_len);

    TEST_info("some_helper: %p(%s) %p", (char*)buf, (char *)buf, (void*)buf_len);
    ok = 1;
err:
    return ok;
}

DEF_SCRIPT(simple_conn, "simple connection to server")
{
    OP_PUSH_BUF("apple");
    OP_PUSH_BUF("orange");
    OP_FUNC(some_helper);
}

/*
 * List of Test Scripts
 * ============================================================================
 */
#define USE(name) &script_info_##name,

static SCRIPT_INFO *const scripts[] = {
    USE(simple_conn)
};
