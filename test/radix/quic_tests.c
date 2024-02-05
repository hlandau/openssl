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

DEF_SCRIPT(simple_conn, "simple connection to server")
{
    OP_NEW_SSL_L_LISTEN(L);
    OP_NEW_SSL_C(C);
}

/*
 * List of Test Scripts
 * ============================================================================
 */
static SCRIPT_INFO *const scripts[] = {
    USE(simple_conn)
};
