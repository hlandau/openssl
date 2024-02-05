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

DEF_FUNC(hf_unbind)
{
    int ok = 0;
    const char *name;

    F_POP(name);
    RADIX_PROCESS_set_obj(RP(), name, NULL);

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_new_ssl)
{
    int ok = 0;
    const char *name;
    SSL *ssl;

    F_POP(name);

    if (!TEST_ptr(ssl = SSL_new(NULL /* TODO */)))
        goto err;

    if (!TEST_true(RADIX_PROCESS_set_ssl(RP(), name, ssl))) {
        SSL_free(ssl);
        goto err;
    }

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_new_stream)
{
    int ok = 0;
    const char *conn_name, *stream_name;
    SSL *conn, *stream;
    uint64_t flags, do_accept;

    F_POP2(flags, do_accept);
    F_POP2(conn_name, stream_name);

    if (!TEST_ptr_null(RADIX_PROCESS_get_obj(RP(), stream_name)))
        goto err;

    if (!TEST_ptr(conn = RADIX_PROCESS_get_ssl(RP(), conn_name)))
        goto err;

    if (do_accept) {
        stream = SSL_accept_stream(conn, flags);

        if (stream == NULL)
            F_SPIN_AGAIN();
    } else {
        stream = SSL_new_stream(conn, flags);
    }

    if (!TEST_ptr(stream))
        goto err;

    /* XXX; wait behaviour; XXX; */

    if (stream != NULL
        && !TEST_true(RADIX_PROCESS_set_ssl(RP(), stream_name, stream))) {
        SSL_free(stream);
        goto err;
    }

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_accept_stream_none)
{
    int ok = 0;
    const char *conn_name;
    uint64_t flags;
    SSL *conn, *stream;

    F_POP2(conn_name, flags);

    if (!TEST_ptr(conn = RADIX_PROCESS_get_ssl(RP(), conn_name)))
        goto err;

    stream = SSL_accept_stream(conn, flags);
    if (!TEST_ptr_null(stream)) {
        SSL_free(stream);
        goto err;
    }

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_pop_err)
{
    int ok = 0;

    ERR_pop();

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_stream_reset)
{
    int ok = 0;
    const char *name;
    SSL_STREAM_RESET_ARGS args = {0};
    SSL *ssl;

    F_POP2(name, args.quic_error_code);
    REQUIRE_SSL(ssl);

    if (!TEST_true(SSL_stream_reset(ssl, &args, sizeof(args))))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_set_default_stream_mode)
{
    int ok = 0;
    uint64_t mode;
    SSL *ssl;

    F_POP(mode);
    REQUIRE_SSL(ssl);

    if (!TEST_true(SSL_set_default_stream_mode(ssl, mode)))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_set_incoming_stream_policy)
{
    int ok = 0;
    uint64_t policy, error_code;
    SSL *ssl;

    F_POP(error_code);
    F_POP(policy);
    REQUIRE_SSL(ssl);

    if (!TEST_true(SSL_set_incoming_stream_policy(ssl, policy, error_code)))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_shutdown_wait)
{
    int ok = 0, ret;
    uint64_t flags;
    SSL *ssl;
    SSL_SHUTDOWN_EX_ARGS args = {0};
    QUIC_CHANNEL *ch;

    F_POP(args.quic_reason);
    F_POP(args.quic_error_code);
    F_POP(flags);
    REQUIRE_SSL(ssl);

    ch = ossl_quic_conn_get_channel(ssl);
    ossl_quic_engine_set_inhibit_tick(ossl_quic_channel_get0_engine(ch), 0);

    ret = SSL_shutdown_ex(ssl, flags, &args, sizeof(args));
    if (!TEST_int_ge(ret, 0))
        goto err;

    if (ret == 0)
        F_SPIN_AGAIN();

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_conclude)
{
    int ok = 0;
    SSL *ssl;

    REQUIRE_SSL(ssl);

    if (!TEST_true(SSL_stream_conclude(ssl, 0)))
        goto err;

    ok = 1;
err:
    return ok;
}

static int is_want(SSL *s, int ret)
{
    int ec = SSL_get_error(s, ret);

    return ec == SSL_ERROR_WANT_READ || ec == SSL_ERROR_WANT_WRITE;
}

static int check_consistent_want(SSL *s, int ret)
{
    int ec = SSL_get_error(s, ret);
    int w = SSL_want(s);

    int ok = TEST_true(
        (ec == SSL_ERROR_NONE                 && w == SSL_NOTHING)
    ||  (ec == SSL_ERROR_ZERO_RETURN          && w == SSL_NOTHING)
    ||  (ec == SSL_ERROR_SSL                  && w == SSL_NOTHING)
    ||  (ec == SSL_ERROR_SYSCALL              && w == SSL_NOTHING)
    ||  (ec == SSL_ERROR_WANT_READ            && w == SSL_READING)
    ||  (ec == SSL_ERROR_WANT_WRITE           && w == SSL_WRITING)
    ||  (ec == SSL_ERROR_WANT_CLIENT_HELLO_CB && w == SSL_CLIENT_HELLO_CB)
    ||  (ec == SSL_ERROR_WANT_X509_LOOKUP     && w == SSL_X509_LOOKUP)
    ||  (ec == SSL_ERROR_WANT_RETRY_VERIFY    && w == SSL_RETRY_VERIFY)
    );

    if (!ok)
        TEST_error("got error=%d, want=%d", ec, w);

    return ok;
}

DEF_FUNC(hf_write)
{
    int ok = 0, r;
    SSL *ssl;
    const void *buf;
    size_t buf_len, bytes_written = 0;

    F_POP2(buf, buf_len);
    REQUIRE_SSL(ssl);

    r = SSL_write_ex(ssl, buf, buf_len, &bytes_written);
    if (!TEST_true(r)
        || check_consistent_want(ssl, r)
        || !TEST_size_t_eq(bytes_written, buf_len))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_write_ex2)
{
    int ok = 0, r;
    SSL *ssl;
    const void *buf;
    size_t buf_len, bytes_written = 0;
    uint64_t flags;

    F_POP(flags);
    F_POP2(buf, buf_len);
    REQUIRE_SSL(ssl);

    r = SSL_write_ex2(ssl, buf, buf_len, flags, &bytes_written);
    if (!TEST_true(r)
        || check_consistent_want(ssl, r)
        || !TEST_size_t_eq(bytes_written, buf_len))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_write_fail)
{
    int ok = 0, ret;
    SSL *ssl;
    size_t bytes_written = 0;

    REQUIRE_SSL(ssl);

    ret = SSL_write_ex(ssl, "apple", 5, &bytes_written);
    if (!TEST_false(ret)
        || !TEST_true(check_consistent_want(ssl, ret))
        || !TEST_size_t_eq(bytes_written, 0))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_read_expect)
{
    int ok = 0, r;
    SSL *ssl;
    const void *buf;
    size_t buf_len, bytes_read = 0;

    F_POP2(buf, buf_len);
    REQUIRE_SSL(ssl);

/* TODO: TMP BUF */
#if 0
    r = SSL_read_ex(ssl, tmp_buf + offset, buf_len - offset,
                    &bytes_read);
    if (!TEST_true(check_consistent_want(ssl, r)))
        goto out;
#endif

    if (!r)
        F_SPIN_AGAIN();

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_read_fail)
{
    int ok = 0, r;
    SSL *ssl;
    char buf[1] = {0};
    size_t bytes_read = 0;
    uint64_t do_wait;

    F_POP(do_wait);
    REQUIRE_SSL(ssl);

    r = SSL_read_ex(ssl, buf, sizeof(buf), &bytes_read);
    if (!TEST_false(r)
        || !TEST_true(check_consistent_want(ssl, r))
        || !TEST_size_t_eq(bytes_read, 0))
        goto err;

    if (do_wait && is_want(ssl, 0))
        F_SPIN_AGAIN();

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_connect_wait)
{
    int ok = 0, ret;
    SSL *ssl;

    REQUIRE_SSL(ssl);

    /* if not started */
    if (0) {
        static const unsigned char alpn_buf[] = {
            /* "\x08ossltest" (hex for EBCDIC resilience) */
            0x08, 0x6f, 0x73, 0x73, 0x6c, 0x74, 0x65, 0x73, 0x74
        };

        /* 0 is the success case for SSL_set_alpn_protos(). */
        if (!TEST_false(SSL_set_alpn_protos(ssl, alpn_buf, sizeof(alpn_buf))))
            goto err;
    }

    /* TODO connect started */

    ret = SSL_connect(ssl);
    if (!TEST_true(check_consistent_want(ssl, ret)))
        goto err;

    if (ret != 1) {
        if (1 /* TODO */ && is_want(ssl, ret))
            F_SPIN_AGAIN();

        if (!TEST_int_eq(ret, 1))
            goto err;
    }

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_detach)
{
    int ok = 0, ret;
    const char *conn_name, *stream_name;
    SSL *conn, *stream;

    F_POP2(conn_name, stream_name);
    if (!TEST_ptr(conn = RADIX_PROCESS_get_ssl(RP(), conn_name)))
        goto err;

    if (!TEST_ptr(stream = ossl_quic_detach_stream(conn)))
        goto err;

    if (!TEST_true(RADIX_PROCESS_set_ssl(RP(), stream_name, stream))) {
        SSL_free(stream);
        goto err;
    }

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_attach)
{
    int ok = 0, ret;
    const char *conn_name, *stream_name;
    SSL *conn, *stream;

    F_POP2(conn_name, stream_name);

    if (!TEST_ptr(conn = RADIX_PROCESS_get_ssl(RP(), conn_name)))
        goto err;

    if (!TEST_ptr(stream = RADIX_PROCESS_get_ssl(RP(), stream_name)))
        goto err;

    if (!TEST_true(ossl_quic_attach_stream(conn, stream)))
        goto err;

    if (!TEST_true(RADIX_PROCESS_set_ssl(RP(), stream_name, NULL)))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_expect_fin)
{
    int ok = 0, ret;
    SSL *ssl;
    char buf[1];
    size_t bytes_read = 0;

    REQUIRE_SSL(ssl);

    ret = SSL_read_ex(ssl, buf, sizeof(buf), &bytes_read);
    if (!TEST_true(check_consistent_want(ssl, ret))
        || !TEST_false(ret)
        || !TEST_size_t_eq(bytes_read, 0))
        goto err;

    if (is_want(ssl, 0))
        F_SPIN_AGAIN();

    if (!TEST_int_eq(SSL_get_error(ssl, 0),
                     SSL_ERROR_ZERO_RETURN))
        goto err;

    if (!TEST_int_eq(SSL_want(ssl), SSL_NOTHING))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_expect_conn_close_info)
{
    int ok = 0;
    SSL *ssl;
    SSL_CONN_CLOSE_INFO cc_info = {0};
    uint64_t error_code, expect_app, expect_remote;

    F_POP(error_code);
    F_POP2(expect_app, expect_remote);
    REQUIRE_SSL(ssl);

    /* TODO BLOCKING */

    if (!SSL_get_conn_close_info(ssl, &cc_info, sizeof(cc_info)))
        F_SPIN_AGAIN();

    if (!TEST_int_eq(expect_app,
                     (cc_info.flags & SSL_CONN_CLOSE_FLAG_TRANSPORT) == 0)
        || !TEST_int_eq(expect_remote,
                        (cc_info.flags & SSL_CONN_CLOSE_FLAG_LOCAL) == 0)
        || !TEST_uint64_t_eq(error_code, cc_info.error_code)) {
        TEST_info("connection close reason: %s", cc_info.reason);
        goto err;
    }

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_wait_for_data)
{
    int ok = 0;
    SSL *ssl;
    char buf[1];
    size_t bytes_read = 0;

    REQUIRE_SSL(ssl);

    if (!SSL_peek_ex(ssl, buf, sizeof(buf), &bytes_read)
        || bytes_read == 0)
        F_SPIN_AGAIN();

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_expect_err)
{
    int ok = 0;
    uint64_t lib, reason;

    F_POP2(lib, reason);
    if (!TEST_size_t_eq((size_t)ERR_GET_LIB(ERR_peek_last_error()), lib)
        || !TEST_size_t_eq((size_t)ERR_GET_REASON(ERR_peek_last_error()), reason))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_expect_ssl_err)
{
    int ok = 0;
    uint64_t expected;
    SSL *ssl;

    F_POP(expected);
    REQUIRE_SSL(ssl);

    if (!TEST_size_t_eq((size_t)SSL_get_error(ssl, 0), expected)
        || !TEST_int_eq(SSL_want(ssl), SSL_NOTHING))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_expect_stream_id)
{
    int ok = 0;
    SSL *ssl;
    uint64_t expected, actual;

    F_POP(expected);
    REQUIRE_SSL(ssl);

    actual = SSL_get_stream_id(ssl);
    if (!TEST_uint64_t_eq(actual, expected))
        goto err;

    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_select_ssl)
{
    int ok = 0;
    uint64_t slot;
    const char *name;
    RADIX_OBJ *obj;

    F_POP2(slot, name);
    if (!TEST_ptr(obj = RADIX_PROCESS_get_obj(RP(), name)))
        goto err;

    if (!TEST_uint64_t_lt(slot, NUM_SLOTS))
        goto err;

    RT()->slot[slot]    = obj;
    RT()->ssl[slot]     = obj->ssl;
    ok = 1;
err:
    return ok;
}

DEF_FUNC(hf_clear_slot)
{
    int ok = 0;
    uint64_t slot;

    F_POP(slot);
    if (!TEST_uint64_t_lt(slot, NUM_SLOTS))
        goto err;

    RT()->slot[slot]    = NULL;
    RT()->ssl[slot]     = NULL;
    ok = 1;
err:
    return ok;
}

#define OP_UNBIND(name) \
    OP_PUSH_P(name) OP_FUNC(hf_unbind)
#define OP_NEW_SSL(name) \
    OP_PUSH_P(name) OP_FUNC(hf_new_ssl)
#define OP_NEW_STREAM(conn_name, stream_name, flags) \
    OP_PUSH_P(conn_name) OP_PUSH_P(stream_name) \
    OP_PUSH_U64(flags) OP_PUSH_U64(0) OP_FUNC(hf_new_stream)
#define OP_ACCEPT_STREAM_WAIT(conn_name, stream_name, flags) \
    OP_PUSH_P(conn_name) OP_PUSH_P(stream_name) \
    OP_PUSH_U64(flags) OP_PUSH_U64(1) OP_FUNC(hf_new_stream)
#define OP_ACCEPT_STREAM_NONE(conn_name, flags) \
    OP_FUNC(hf_accept_stream_none)

#define OP_STREAM_RESET(error_code) \
    OP_PUSH_U64(flags) OP_FUNC(hf_stream_reset)
#define OP_SET_DEFAULT_STREAM_MODE(mode) \
    OP_PUSH_U64(mode) OP_FUNC(hf_set_default_stream_mode)
#define OP_SET_INCOMING_STREAM_POLICY(policy, error_code) \
    OP_PUSH_U64(policy) OP_PUSH_U64(error_code) \
    OP_FUNC(hf_set_incoming_stream_policy)
#define OP_POP_ERR() OP_FUNC(hf_pop_err)
#define OP_SHUTDOWN_WAIT(flags, error_code, reason) \
    OP_PUSH_U64(flags) OP_PUSH_U64(error_code) OP_PUSH_P(reason) \
    OP_FUNC(hf_shutdown_wait)
#define OP_CONCLUDE() \
    OP_FUNC(hf_conclude)
#define OP_WRITE(buf, buf_len) \
    OP_PUSH_P(buf) OP_PUSH_U64(buf_len) OP_FUNC(hf_write)
#define OP_WRITE_EX2(buf, buf_len, flags) \
    OP_PUSH_P(buf) OP_PUSH_U64(buf_len) \
    OP_PUSH_U64(flags) OP_FUNC(hf_write_ex2)
#define OP_WRITE_B(buf)   OP_WRITE((buf), sizeof(buf))
#define OP_WRITE_FAIL() \
    OP_FUNC(hf_write_fail)
#define OP_READ_EXPECT(buf, buf_len) \
    OP_PUSH_P(buf) OP_PUSH_U64(buf_len) OP_FUNC(hf_read_expect)
#define OP_READ_EXPECT_B(buf) \
    OP_READ_EXPECT((buf), sizeof(buf))
#define OP_READ_FAIL() \
    OP_PUSH_U64(0) OP_FUNC(hf_read_fail)
#define OP_READ_FAIL_WAIT() \
    OP_PUSH_U64(1) OP_FUNC(hf_read_fail)
#define OP_CONNECT_WAIT() \
    OP_FUNC(hf_connect_wait)
#define OP_DETACH(conn_name, stream_name) \
    OP_PUSH_P(conn_name) OP_PUSH_P(stream_name) OP_FUNC(hf_detach)
#define OP_ATTACH(conn_name, stream_name) \
    OP_PUSH_P(conn_name) OP_PUSH_P(stream_name) OP_FUNC(hf_attach)
#define OP_EXPECT_FIN() \
    OP_FUNC(hf_expect_fin)
#define OP_EXPECT_CONN_CLOSE_INFO(error_code, expect_app, expect_remote) \
    OP_PUSH_U64(expect_app) OP_PUSH_U64(expect_remote) \
    OP_PUSH_U64(error_code) OP_FUNC(hf_expect_conn_close_info)
#define OP_WAIT_FOR_DATA() \
    OP_FUNC(hf_wait_for_data)
#define OP_EXPECT_ERR(lib, reason) \
    OP_PUSH_U64(lib) OP_PUSH_U64(reason) OP_FUNC(hf_expect_err)
#define OP_EXPECT_SSL_ERR(expected) \
    OP_PUSH_U64(expected) OP_FUNC(hf_expect_ssl_err)
#define OP_EXPECT_STREAM_ID(expected) \
    OP_PUSH_U64(expected) OP_FUNC(hf_expect_stream_id)

#define OP_SELECT_SSL(slot, name) \
    OP_PUSH_U64(slot) OP_PUSH_P(name) OP_FUNC(hf_select_ssl)
#define OP_CLEAR_SLOT(slot) \
    OP_PUSH_U64(slot) OP_FUNC(hf_clear_slot)

// TODO: NEW_THREAD
// TODO: BEGIN_REPEAT
// TODO: END_REPEAT
