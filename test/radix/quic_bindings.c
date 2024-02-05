/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/lhash.h>
#include <assert.h>

#include "internal/quic_engine.h"
#include "internal/quic_channel.h"
#include "internal/quic_ssl.h"

/*
 * RADIX 6D QUIC Test Framework
 * =============================================================================
 *
 * The radix test framework is a six-dimension script-driven facility to support
 * execution of
 *
 *   multi-stream
 *   multi-client
 *   multi-server
 *   multi-thread
 *   multi-process
 *   multi-node
 *
 * test vignettes for QUIC. Unlike the older multistream test framework, it does
 * not assume a single client and a single server. Examples of vignettes
 * designed to be supported by the radix test framework in future include:
 *
 *      single client    <-> single server
 *      multiple clients <-> single server
 *      single client    <-> multiple servers
 *      multiple clients <-> multiple servers
 *
 * 'Multi-process' and 'multi-node' means there has been some consideration
 * given to support of multi-process and multi-node testing in the future,
 * though this is not currently supported.
 */

/*

Requirements:

  - multiple SSL objects, assign names

  - async. expect wait etc., timeouts

  - multithreading


global context:

    ssl_objects: (const char *) -> (SSL *)




 */

/*
 * An object is something associated with a name in the process-level state. The
 * process-level state primarily revolves around a global dictionary of SSL
 * objects.
 */
typedef struct radix_obj_st {
    char                *name;  /* owned, zero-terminated */
    SSL                 *ssl;   /* owns one reference */
    unsigned int        registered      : 1; /* in LHASH? */
} RADIX_OBJ;

DEFINE_LHASH_OF_EX(RADIX_OBJ);

/* Process-level state (i.e. "globals" in the normal sense of the word) */
typedef struct radix_process_st {
    LHASH_OF(RADIX_OBJ) *objs;
} RADIX_PROCESS;

#define NUM_SLOTS       4

/* Thread-level state within a process */
typedef struct radix_thread_st {
    RADIX_PROCESS       *rp;
    RADIX_OBJ           *slot[NUM_SLOTS];
    SSL                 *ssl[NUM_SLOTS];
} RADIX_THREAD;

/* ssl reference is transferred. name is copied and is required. */
static RADIX_OBJ *RADIX_OBJ_new(const char *name, SSL *ssl)
{
    RADIX_OBJ *obj;

    if (!TEST_ptr(name) || !TEST_ptr(ssl))
        return NULL;

    if (!TEST_ptr(obj = OPENSSL_zalloc(sizeof(*obj))))
       return NULL;

    obj->name = OPENSSL_strdup(name);
    obj->ssl  = ssl;
    return obj;
}

static void RADIX_OBJ_free(RADIX_OBJ *obj)
{
    if (obj == NULL)
        return;

    assert(!obj->registered);

    SSL_free(obj->ssl);
    OPENSSL_free(obj->name);
    OPENSSL_free(obj);
}

static unsigned long RADIX_OBJ_hash(const RADIX_OBJ *obj)
{
    return OPENSSL_LH_strhash(obj->name);
}

static int RADIX_OBJ_cmp(const RADIX_OBJ *a, const RADIX_OBJ *b)
{
    return strcmp(a->name, b->name);
}

static int RADIX_PROCESS_init(RADIX_PROCESS *rp)
{
    if (!TEST_ptr(rp->objs = lh_RADIX_OBJ_new(RADIX_OBJ_hash, RADIX_OBJ_cmp)))
        return 0;

    return 1;
}

static void cleanup_one(RADIX_OBJ *obj)
{
    obj->registered = 0;
    RADIX_OBJ_free(obj);
}

static void RADIX_PROCESS_cleanup(RADIX_PROCESS *rp)
{
    lh_RADIX_OBJ_doall(rp->objs, cleanup_one);
    lh_RADIX_OBJ_free(rp->objs);
    rp->objs = NULL;
}

static RADIX_OBJ *RADIX_PROCESS_get_obj(RADIX_PROCESS *rp, const char *name)
{
    RADIX_OBJ key;

    key.name = (char *)name;
    return lh_RADIX_OBJ_retrieve(rp->objs, &key);
}

static int RADIX_PROCESS_set_obj(RADIX_PROCESS *rp,
                                 const char *name, RADIX_OBJ *obj)
{
    RADIX_OBJ *existing;

    if (obj != NULL && !TEST_false(obj->registered))
        return 0;

    existing = RADIX_PROCESS_get_obj(rp, name);
    if (existing != NULL && obj != existing) {
        if (!TEST_true(existing->registered))
            return 0;

        lh_RADIX_OBJ_delete(rp->objs, existing);
        existing->registered = 0;
        RADIX_OBJ_free(existing);
    }

    if (obj != NULL) {
        lh_RADIX_OBJ_insert(rp->objs, obj);
        obj->registered = 1;
    }

    return 1;
}

static int RADIX_PROCESS_set_ssl(RADIX_PROCESS *rp, const char *name, SSL *ssl)
{
    RADIX_OBJ *obj;

    if (!TEST_ptr(obj = RADIX_OBJ_new(name, ssl)))
        return 0;

    if (!TEST_true(RADIX_PROCESS_set_obj(rp, name, obj))) {
        RADIX_OBJ_free(obj);
        return 0;
    }

    return 1;
}

static SSL *RADIX_PROCESS_get_ssl(RADIX_PROCESS *rp, const char *name)
{
    RADIX_OBJ *obj = RADIX_PROCESS_get_obj(rp, name);

    if (obj == NULL)
        return NULL;

    return obj->ssl;
}

static int RADIX_THREAD_init(RADIX_THREAD *rt, RADIX_PROCESS *rp)
{
    size_t i;

    rt->rp = rp;
    for (i = 0; i < OSSL_NELEM(rt->slot); ++i) {
        rt->slot[i] = NULL;
        rt->ssl[i]  = NULL;
    }

    return 1;
}

static void RADIX_THREAD_cleanup(RADIX_THREAD *rt)
{
    rt->rp = NULL;
}

static RADIX_PROCESS radix_process;
static RADIX_THREAD *radix_thread;

#define RP()    (&radix_process)
#define RT()    (radix_thread) /* TODO */

static int expect_slot_ssl(FUNC_CTX *fctx, size_t idx, SSL **p_ssl)
{
    if (!TEST_size_t_lt(idx, NUM_SLOTS)
        || !TEST_ptr(*p_ssl = RT()->ssl[idx]))
        return 0;

    return 1;
}

#define REQUIRE_SSL_N(idx, ssl)                                 \
    do {                                                        \
        if (!TEST_true(expect_slot_ssl(fctx, (idx), &(ssl))))   \
            goto err;                                           \
    } while (0)
#define REQUIRE_SSL(ssl)    REQUIRE_SSL_N(0, (ssl))

#define C_BIDI_ID(ordinal) \
    (((ordinal) << 2) | QUIC_STREAM_INITIATOR_CLIENT | QUIC_STREAM_DIR_BIDI)
#define S_BIDI_ID(ordinal) \
    (((ordinal) << 2) | QUIC_STREAM_INITIATOR_SERVER | QUIC_STREAM_DIR_BIDI)
#define C_UNI_ID(ordinal) \
    (((ordinal) << 2) | QUIC_STREAM_INITIATOR_CLIENT | QUIC_STREAM_DIR_UNI)
#define S_UNI_ID(ordinal) \
    (((ordinal) << 2) | QUIC_STREAM_INITIATOR_SERVER | QUIC_STREAM_DIR_UNI)
