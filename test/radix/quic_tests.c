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
#if 0
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

DEF_FUNC(hf_sleep) {
    int ok = 0;
    sleep(1);
    F_SPIN_AGAIN();
    ok = 1;
err:
    return ok;
}

DEF_FUNC(push_error) {
    ERR_raise_data(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "oh no, don't call this");
    ERR_raise_data(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "no really");
    return 0;
}

DEF_SCRIPT(err_test, "error test")
{
    OP_FUNC(push_error);
}

DEF_SCRIPT(simple_conn, "simple connection to server")
{
    OP_PUSH_BUF("apple");
    OP_LABEL("1");
    OP_PUSH_BUF("orange");
    OP_FUNC(some_helper);
    OP_FUNC(hf_sleep);
}

DEF_SCRIPT(simple_thread_child, "threaded test (child)")
{
}

DEF_SCRIPT(simple_thread, "threaded test")
{
    OP_SPAWN_THREAD(simple_thread_child);
    OP_SPAWN_THREAD(simple_thread_child);
}
#endif

DEF_SCRIPT(simple_conn, "simple connection to server")
{
    OP_NEW_SSL_C("a");
}

/*
 * List of Test Scripts
 * ============================================================================
 */
static SCRIPT_INFO *const scripts[] = {
    USE(simple_conn)
    //USE(err_test)
    //USE(simple_conn)
    //USE(simple_thread)
};
