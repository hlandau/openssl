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
    LHASH_OF(RADIX_OBJ)     *objs;
    size_t                  node_idx;
    size_t                  process_idx;
    size_t                  next_thread_idx;
    STACK_OF(RADIX_THREAD)  *threads;

    int                     done_join_all_threads;

    /*
     * Valid if done_join_all threads. Logical AND of all child worker results.
     */
    int                     thread_composite_testresult;
} RADIX_PROCESS;

#define NUM_SLOTS       4

/* Thread-level state within a process */
typedef struct radix_thread_st {
    RADIX_PROCESS       *rp;
    CRYPTO_THREAD       *t;
    RADIX_OBJ           *slot[NUM_SLOTS];
    SSL                 *ssl[NUM_SLOTS];
    unsigned char       *tmp_buf;
    size_t              tmp_buf_offset;
    size_t              thread_idx; /* 0=main thread */

    /* child thread spawn arguments */
    SCRIPT_INFO         *child_script_info;

    /* m protects all of the below values */
    CRYPTO_MUTEX        *m;
    int                 done;
    int                 testresult; /* valid if done */
} RADIX_THREAD;

DEFINE_STACK_OF(RADIX_THREAD)

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

static int RADIX_PROCESS_init(RADIX_PROCESS *rp, size_t node_idx, size_t process_idx)
{
    if (!TEST_ptr(rp->objs = lh_RADIX_OBJ_new(RADIX_OBJ_hash, RADIX_OBJ_cmp)))
        return 0;

    if (!TEST_ptr(rp->threads = sk_RADIX_THREAD_new(NULL))) {
        lh_RADIX_OBJ_free(rp->objs);
        rp->objs = NULL;
        return 0;
    }

    rp->node_idx                = node_idx;
    rp->process_idx             = process_idx;
    rp->done_join_all_threads   = 0;
    return 1;
}

static int RADIX_THREAD_join(RADIX_THREAD *rt);

static int RADIX_PROCESS_join_all_threads(RADIX_PROCESS *rp, int *testresult)
{
    int ok = 1;
    size_t i;
    RADIX_THREAD *rt;
    int composite_testresult = 1;

    if (rp->done_join_all_threads) {
        *testresult = rp->thread_composite_testresult;
        return 1;
    }

    for (i = 1; i < (size_t)sk_RADIX_THREAD_num(rp->threads); ++i) {
        rt = sk_RADIX_THREAD_value(rp->threads, i);

        if (!TEST_true(RADIX_THREAD_join(rt)))
            ok = 0;

        if (!rt->testresult)
            composite_testresult = 0;
    }

    rp->thread_composite_testresult = composite_testresult;
    *testresult                     = composite_testresult;
    rp->done_join_all_threads       = 1;
    return ok;
}

static void cleanup_one(RADIX_OBJ *obj)
{
    obj->registered = 0;
    RADIX_OBJ_free(obj);
}

static void RADIX_PROCESS_cleanup(RADIX_PROCESS *rp)
{
    assert(rp->done_join_all_threads);
    lh_RADIX_OBJ_doall(rp->objs, cleanup_one);
    lh_RADIX_OBJ_free(rp->objs);
    rp->objs = NULL;
    sk_RADIX_THREAD_free(rp->threads);
    rp->threads = NULL;
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

static RADIX_THREAD *RADIX_THREAD_new(RADIX_PROCESS *rp)
{
    RADIX_THREAD *rt;

    if (!TEST_ptr(rp)
        || !TEST_ptr(rt = OPENSSL_zalloc(sizeof(rt))))
        return 0;

    rt->rp          = rp;

    if (!TEST_ptr(rt->m = ossl_crypto_mutex_new())) {
        OPENSSL_free(rt);
        return 0;
    }

    if (!TEST_true(sk_RADIX_THREAD_push(rp->threads, rt))) {
        OPENSSL_free(rt);
        return 0;
    }

    rt->thread_idx  = rp->next_thread_idx++;
    assert(rt->thread_idx == (size_t)sk_RADIX_THREAD_num(rp->threads));
    return rt;
}

static void RADIX_THREAD_free(RADIX_THREAD *rt)
{
    if (rt == NULL)
        return;

    assert(rt->t == NULL);
    OPENSSL_free(rt->tmp_buf);
    ossl_crypto_mutex_free(&rt->m);
    OPENSSL_free(rt);
}

static int RADIX_THREAD_join(RADIX_THREAD *rt)
{
    CRYPTO_THREAD_RETVAL rv;

    if (rt->t != NULL)
        ossl_crypto_thread_native_join(rt->t, &rv);

    ossl_crypto_thread_native_clean(rt->t);
    rt->t = NULL;

    if (!TEST_true(rt->done))
        return 0;

    return 1;
}

static RADIX_PROCESS        radix_process;
static CRYPTO_THREAD_LOCAL  radix_thread;

static void radix_thread_cleanup(void *p)
{
    /* Should already have been cleaned up. */
    if (!TEST_ptr_null(p))
        abort();
}

static RADIX_THREAD *radix_get_thread(void)
{
    return CRYPTO_THREAD_get_local(&radix_thread);
}

static int bindings_process_init(size_t node_idx, size_t process_idx)
{
    if (!TEST_true(RADIX_PROCESS_init(&radix_process, node_idx, process_idx)))
        return 0;

    if (!TEST_true(CRYPTO_THREAD_init_local(&radix_thread,
                                            radix_thread_cleanup)))
        return 0;

    return 1;
}

static int bindings_thread_init_with(RADIX_THREAD *rt)
{
    int did_alloc = 0;

    if (!TEST_ptr_null(CRYPTO_THREAD_get_local(&radix_thread)))
        return 0;

    if (rt == NULL) {
        did_alloc = 1;
        if (!TEST_ptr(rt = RADIX_THREAD_new(&radix_process)))
            return 0;
    }

    if (!TEST_true(CRYPTO_THREAD_set_local(&radix_thread, rt))) {
        if (did_alloc)
            RADIX_THREAD_free(rt);

        return 0;
    }

    return 1;
}

static int bindings_thread_init(void)
{
    return bindings_thread_init_with(NULL);
}

static void bindings_thread_cleanup(void)
{
    RADIX_THREAD *rt = radix_get_thread();

    if (!TEST_ptr(rt))
        return;

    if (!TEST_true(CRYPTO_THREAD_set_local(&radix_thread, NULL)))
        return;

    RADIX_THREAD_free(rt);
}

static int bindings_join_all_threads(int *testresult)
{
    return RADIX_PROCESS_join_all_threads(&radix_process, testresult);
}

static void bindings_process_cleanup(void)
{
    RADIX_PROCESS_cleanup(&radix_process);
}

#define RP()    (&radix_process)
#define RT()    (radix_get_thread())

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

static int RADIX_THREAD_worker_run(RADIX_THREAD *rt)
{
    return TERP_run(rt->child_script_info);
}

static unsigned int RADIX_THREAD_worker_main(void *p)
{
    int testresult = 0;
    RADIX_THREAD *rt = p;

    if (!TEST_true(bindings_thread_init_with(rt)))
        return 0;

    /* Wait until thread-specific init is done (e.g. setting rt->t) */
    ossl_crypto_mutex_lock(rt->m);
    ossl_crypto_mutex_unlock(rt->m);

    testresult = RADIX_THREAD_worker_run(rt);

    ossl_crypto_mutex_lock(rt->m);
    rt->testresult  = testresult;
    rt->done        = 1;
    ossl_crypto_mutex_unlock(rt->m);

    bindings_thread_cleanup();
    return 1;
}

DEF_FUNC(hf_spawn_thread)
{
    int ok = 0;
    RADIX_THREAD *child_rt = NULL;
    SCRIPT_INFO *script_info = NULL;

    F_POP(script_info);
    if (!TEST_ptr(script_info))
        goto err;

#if !defined(OPENSSL_THREADS)
    TEST_skip("threading not supported, skipping");
    F_SKIP_REST();
#else
    if (!TEST_ptr(child_rt = RADIX_THREAD_new(&radix_process)))
        return 0;

    ossl_crypto_mutex_lock(child_rt->m);

    child_rt->child_script_info = script_info;
    if (!TEST_ptr(child_rt->t = ossl_crypto_thread_native_start(RADIX_THREAD_worker_main,
                                                                child_rt, 1))) {
        ossl_crypto_mutex_unlock(child_rt->m);
        RADIX_THREAD_free(child_rt);
        goto err;
    }

    ossl_crypto_mutex_unlock(child_rt->m);
    ok = 1;
#endif
err:
    return ok;
}
