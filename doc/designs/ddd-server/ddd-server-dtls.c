#define USE_DTLS
#define USE_LIBUV
#include "ddd-server-common.h"
#include <uv.h>
#include <stdarg.h>
#include <assert.h>

/*
 * ddd-server-dtls
 * ===============
 *
 * This demo exhibits a simple non-blocking multi-threaded DTLSv1.2 echo server
 * using the bind-connect group (BCG) model discussed in the DTLS discussion
 * document. A single thread handles accepting incoming DTLS connections on
 * multiple listeners, handling different sockets using OS poll APIs (via libuv)
 * as needed. Accepted connections are transferred to a worker thread dedicated
 * to handling one or more connections, again via OS poll APIs via libuv as
 * needed. Thus, it is similar to ddd-server-uv-pollable. Connections have
 * affinity to a specific worker thread and do not move between threads after
 * they are assigned to one.
 *
 *
 *      |  main thread            |  |  worker thread          |  ...
 *      |-------------------------|  |-------------------------|
 *      |  listening socket 1230  |  |                         |
 *      |  listening socket 1231  |  |                         |
 *      |  ...                    |  |                         |
 *      |                         |  |                         |
 *      |  -----------            |  |  ----  ----             |
 *      |  listen loop            |  |  conn  conn  ...        |
 *      |  -----------            |  |  ----  ----             |
 *      |                         |  |                         |
 *
 * Cardinality:
 *
 *   number of workers                  = p
 *   number of listening ports, sockets = q
 *
 *   1 process
 *     1 main thread servicing all listener sockets
 *     p workers
 *       0..n open connections per worker
 *
 * The design of connection handling is split between infrastructure to plumb
 * libssl into libuv (CONN), and the "application" (echo server) which then uses
 * that infrastructure. The application invokes the CONN_* methods to read and
 * write data from the network, which provide a libuv-like interface. conn_*
 * functions are internal to the CONN infrastructure. Functions which are
 * provided by the application and called into by the infrastructure are named
 * app_*.
 *
 * libssl communication with the network is based around directly passing it a
 * network socket file descriptor (via BIO_s_datagram) and determining readiness
 * using a uv_poll_t instance:
 *
 *    ____________
 *   |            |  "app" |
 *   | CONN infra | <----- |  Application-level I/O requests
 *   |____________|        |
 *   async |^SSL_read
 *       & ||SSL_write
 *         ||
 *         ||
 *         ||                         _________
 *         ||                        |         |
 *         |\--- readiness events ---|  libuv  |
 *         |                         |_________|
 *    _____v______                   poll |
 *   |            |       |               v     |
 *   |   libssl   | <---> |  OS Network Socket  | <---> network
 *   |____________| "net" |                     |
 *
 * The interface to the application is similar to that provided by libuv's
 * uv_poll_t, which is to say the application provides a callback which is
 * called when the application-specified kinds of I/O can potentially be
 * performed.
 *
 * It is important to not get confused between "app" I/O and "net" I/O. An
 * APP-level I/O request is one made by the application 'above' libssl and the
 * CONN infrastructure (and contain application data). NET-level I/O refers to
 * libssl's communication with the socket BIO provided to it (which contain TLS
 * protocol data).
 *
 * QUIC Support
 * ------------
 *
 * This demo exhibits changes for supporting QUIC, called out using preprocessor
 * guards. The preferred model for supporting QUIC is to adopt the SSL Listener
 * API, which abstracts the process of accepting connections from the
 * application and can support TCP, TLS over TCP, DTLS over UDP and QUIC use
 * cases. Most of the changes made are a result of refactoring to use a
 * Listener-based interface. The QUIC-specific changes are extremely minimal.
 *
 * Alternatively, a DTLSv1_listen-style interface may be used. This forces the
 * use of Application Managed BCG (AM-BCG) (see the DDD-SERVER README) much as
 * is done for our existing DTLS API using DTLSv1_listen. This may prevent use
 * of some QUIC functionality such as connection migration.
 *
 * The RX steering model used is determined as follows:
 *
 *   - IPSM: This mode uses a single unconnected UDP socket to do multipoint
 *     communications, where each send/receive operation has L4 addressing
 *     information attached to it.
 *
 *     Pro: This is the most portable model, and the most flexible model
 *          in terms of processing, as it does not rely on special OS
 *          functionality.
 *
 *     Con: There is no RX steering and no thread affinity, by connection or
 *          otherwise. As such, this model is optimal for single-threaded use
 *          but may lead to high lock contention if used in a multithreaded
 *          manner.
 *
 *          Distributing the server's application processing tasks amongst
 *          multiple worker threads may still result in a performance gain if
 *          (and only if) the bulk of the processing load is in the application
 *          and not the QUIC stack, or if there are multiple listening ports
 *          with a balanced distribution of incoming connections among those
 *          ports, facilitating listening port-based allocation amongst the
 *          worker threads.
 *
 *     Supportable by the listener interface only.
 *
 *   - 2P-IPSM: Two-phase IPSM. In this model, the initial RX processing and
 *     software routing to a connection is done under a QUIC domain lock. This
 *     lock is held for as little time as possible. Then connection-specific
 *     processing is done under a connection-specific lock (enabling parallel
 *     processing of different connections).
 *
 *     Supportable by the listener interface only.
 *
 *   - AM-BCG: This is the model used if the application uses the stateless
 *     listen-style API, and the model always used for our existing DTLS server
 *     API.  A separate UDP socket is created for each incoming connection, and
 *     using bind() and connect(), the OS kernel is configured to route incoming
 *     datagrams to the correct socket based on L4 source address.
 *
 *     Con: The application is responsible for calling bind() and
 *          connect() when accepting a new connection.
 *
 *     Con: The QUIC stack is non-address-aware and features which require
 *          addressed-mode operation, such as connection migration or multipath
 *          functionality, cannot be used and are disabled automatically.
 *
 *     Pro: On the other hand, RX steering has thread affinity and processing of
 *          a specific connection can be fully distributed among the separate
 *          threads without contention on any shared state.
 *
 *     Supportable by the stateless-listen interface only.
 *     The listener interface cannot support this without API modifications
 *      (e.g. for an application to learn of an incoming connection and then
 *            generate and donate a specific connected BIO_s_datagram
 *            using a special API on the listener)
 *
 *   - LM-BCG, eBPF: In this model the QUIC stack can generate multiple
 *     BIOs (OS sockets) internally as needed to provide RX steering. As such
 *     incoming datagrams are filtered to those pertinent for a specific
 *     connection and API calls on a specific connection can access (and lock)
 *     a segregated state set that concerns that connection (channel) only
 *     and not the entire QUIC domain. This enables efficient parallel
 *     processing of different connections.
 *
 *     Supportable by the listener interface only.
 *
 *     Pro: Most efficient and most thread-scalable processing model
 *
 *     Con: Requires OS support (LM-BCG) or highly advanced OS support (eBPF)
 *
 *
 *
 * When using the preferred listener interface, IPSM is used.
 *
 *   - The preferred model for supportingThe demo supports both listener-based
 */

#if defined(USE_QUIC) && !defined(USE_QUIC_LEGACY_COMPAT)
# define USE_LISTENER
#endif

/* Number of worker threads. */
#define NUM_WORKERS     5

/* Number of ports to listen on. */
#define NUM_LISTENERS   5

/*
 * Structure to track a worker thread. This owns one or more connections
 * (CONNs).
 */
typedef struct worker_st WORKER;

/*
 * Structure to track a DTLS connection. This belongs to exactly one WORKER.
 */
typedef struct conn_st CONN;

/*
 * Structure to track a listener (one listening port).
 */
typedef struct listener_st LISTENER;

/* Application I/O readiness callback. */
typedef void (app_poll_cb)(CONN *conn, SSL *ssl, int events, void *arg);

struct worker_st {
    uv_thread_t     t;                  /* worker thread */
    uv_loop_t       loop;               /* thread-specific event loop */
    uv_async_t      wakeup;             /* inter-thread wakeup for shutdown */
    size_t          idx;                /* worker idx [0..p) */
    size_t          num_to_close;       /* number of libuv handles to close */
    CONN            *conn_head;         /* list of owned CONNs */
    CONN            *conn_tail;
    int             rc;                 /* thread return code */
    unsigned int    active      : 1;    /* thread running? */
    unsigned int    have_loop   : 1;    /* loop valid? */
    unsigned int    have_wakeup : 1;    /* wakeup valid? */

#ifdef USE_LISTENER
    OSSL_POLL_GROUP *poll_group;
#else
    BIO_ADDR        *peer_addr;         /* incoming peer addr */
#endif

    uv_mutex_t      mutex;              /* protects conn_mbox only */
    CONN            *conn_mbox;         /* incoming connection */
};

struct listener_st {
    size_t          idx;                /* listener idx [0..q) */
    uint16_t        port;               /* port (host byte order) */
    int             listen_fd;          /* bound but unconnected UDP socket */
    BIO             *listen_bio;        /* BIO_s_datagram (unconnected) */
    uv_poll_t       poll;               /* poller for listen_fd */
    unsigned int    have_poll  : 1;     /* poll valid? */

#ifdef USE_LISTENER
    SSL             *listen_ssl;        /* QLSO */
    OSSL_POLL_GROUP *poll_group;        /* QLSO + all connections under it */
#else
    SSL             *spare_ssl;         /* spare SSL object for DTLSv1_listen */
    BIO_ADDR        *peer_addr;         /* scratch BIO_ADDR for DTLSv1_listen */
#endif
};

struct conn_st {
    CONN            *prev, *next;       /* for WORKER conn list */

    WORKER          *w;                 /* owning worker */
#ifndef USE_LISTENER
    int             fd;                 /* connected UDP socket */
    uv_poll_t       poll;               /* polls connected FD */
#endif

    /* Weakref to BIO given to SSL object (SSL object holds only ref) */
    BIO             *ssl_bio;           /* BIO_s_datagram for fd */
    SSL             *ssl;               /* DTLS object for established conn */
#ifndef USE_LISTENER
    BIO_ADDR        *peer_addr;         /* UDP peer address */
#endif

    /* Callback for application when we are potentially ready to do I/O. */
    app_poll_cb     *app_poll_cb;
    void            *app_poll_cb_arg;
    int             app_poll_events;

    unsigned int    teardown    : 1;    /* teardown started? */
    unsigned int    on_list     : 1;    /* on worker list? */
#ifndef USE_LISTENER
    unsigned int    poll_valid  : 1;    /* ->poll is initialized? */
#endif

    /*
     * The following track whether the DTLS engine is internally blocked on
     * network-side read or writes.
     */
    unsigned int    want_read   : 1;    /* DTLS engine blocked on net-side read */
    unsigned int    want_write  : 1;    /* DTLS engine blocked on net-side write */

    /* Fields for application use. */
    uint8_t         *app_buf;
    size_t          app_buf_len;
};

/*
 * Container for state related to the main thread's incoming connection
 * processing.
 */
typedef struct accepter_st {
    uv_loop_t       loop;
    uv_signal_t     signal;
    size_t          num_to_close;
    size_t          next_worker_idx;
    unsigned int    have_loop   : 1; /* loop valid? */
    unsigned int    have_signal : 1; /* signal valid? */
} ACCEPTER;

static LISTENER *g_listeners;
static WORKER *g_workers;
static ACCEPTER g_accepter;

static void app_on_conn(CONN *conn, SSL *ssl);

/*
 * DTLS-Specific Callbacks
 * =======================
 *
 * These are dummy implementations of libssl DTLS cookie callbacks. These are
 * NOT SECURE. Do not use these in real code.
 */
static int on_cookie_generate(SSL *ssl,
                              unsigned char *cookie,
                              unsigned int *cookie_len)
{
    cookie[0] = 0x55;
    *cookie_len = 1;
    return 1;
}

static int on_cookie_verify(SSL *ssl,
                            const unsigned char *cookie,
                            unsigned int cookie_len)
{
    return 1;
}

/*
 * Connection Handling: Lifecycle Handling
 * =======================================
 */

static void worker_add_conn(WORKER *w, CONN *conn);
static void worker_remove_conn(WORKER *w, CONN *conn);

static void conn_delete(CONN *conn)
{
    if (conn == NULL)
        return;

#ifndef USE_LISTENER
    assert(!conn->poll_valid);
#endif

    if (conn->on_list)
        worker_remove_conn(conn->w, conn);

#ifndef USE_LISTENER
    BIO_ADDR_free(conn->peer_addr);
#endif
    SSL_free(conn->ssl);
    conn->ssl = NULL;
    conn->ssl_bio = NULL;
    free(conn->app_buf);
    free(conn);
}

#ifndef USE_LISTENER
static int conn_try_delete(CONN *conn)
{
    if (conn->poll_valid)
        return 0;

    conn_delete(conn);
    return 1;
}

static void conn_poll_on_close(uv_handle_t *h)
{
    CONN *conn = h->data;

    assert(conn->w->num_to_close > 0);
    --conn->w->num_to_close;

    conn->poll_valid = 0;
    conn_delete(conn);
}
#endif

/*
 * Start to teardown the connection. Subsequent calls are ignored. The
 * application may also use this.
 */
static void CONN_teardown(CONN *conn)
{
    if (conn->teardown)
        return;

    conn->teardown = 1;

#ifdef USE_LISTENER
    log_warn("worker %zu: tearing down connection", conn->w->idx);
    conn_delete(conn);
#else
    if (conn->poll_valid)
        uv_poll_stop(&conn->poll);

    if (conn_try_delete(conn))
        return;

    log_warn("worker %zu: tearing down connection", conn->w->idx);

    /* Close the poller, delete once done. */
    assert(conn->poll_valid);
    ++conn->w->num_to_close;
    uv_close((uv_handle_t *)&conn->poll, conn_poll_on_close);
#endif
}

/* Called in the event of a permanent network error. */
static void conn_on_net_error(CONN *conn)
{
    CONN_teardown(conn);
}

/*
 * Connection Handling: Operations
 * ===============================
 */

#ifdef USE_LISTENER
static void conn_on_io_ready(CONN *conn, int status, int events)
#else
static void conn_on_io_ready(uv_poll_t *h, int status, int events)
#endif
{
#ifndef USE_LISTENER
    CONN *conn = h->data;
#endif

    if (status < 0) {
        log_warn_uv(status, "uv ready fail");
        conn_on_net_error(conn);
        return;
    }

    if (conn->app_poll_cb != NULL)
        conn->app_poll_cb(conn, conn->ssl, events, conn->app_poll_cb_arg);
}

static int conn_determine_desired_events(CONN *conn)
{
    int events_mask = 0;

    /*
     * If application wants to read, or we are internally blocked on a network
     * read (e.g. due to an incoming post-handshake message during SSL_write)
     * listen for read events.
     */
    if (conn->want_read || (conn->app_poll_events & UV_READABLE) != 0)
#ifdef USE_LISTENER
        events_mask |= OSSL_POLL_EVENT_R;
#else
        events_mask |= UV_READABLE;
#endif

    /*
     * If application wants to write, or we are internally blocked on a network
     * write (e.g. due to the need to send a post-handshake message during
     * SSL_read) listen for write events.
     */
    if (conn->want_write || (conn->app_poll_events & UV_WRITABLE) != 0)
#ifdef USE_LISTENER
        events_mask |= OSSL_POLL_EVENT_W;
#else
        events_mask |= UV_WRITABLE;
#endif

    return events_mask;
}

static int conn_update_poll(CONN *conn)
{
    int events_mask = conn_determine_desired_events(conn);
#ifdef USE_LISTENER
    OSSL_POLL_CHANGE chg[1];
#else
    int rc;
#endif

    if (conn->teardown)
        return 1;

#ifdef USE_LISTENER
    OSSL_POLL_CHANGE_set(&chg[0], SSL_as_poll_descriptor(conn->ssl), 0,
                         conn, events_mask, 0);
    if (!OSSL_POLL_GROUP_change(conn->w->poll_group, chg, 1, 0)) {
        log_warn_ssl("poll group change failed");
        return 0;
    }
#else
    if (events_mask != 0)
        rc = uv_poll_start(&conn->poll, events_mask, conn_on_io_ready);
    else
        rc = uv_poll_stop(&conn->poll);

    if (rc < 0) {
        log_warn_uv(rc, "uv_poll");
        return 0;
    }
#endif

    return 1;
}

/*
 * Connection Handling: Application Interface
 * ==========================================
 */

/*
 * Request by application to start listening for particular (application data,
 * i.e. above DTLS) I/O readiness events. Set events to 0 to disable callback.
 */
static int CONN_poll_start(CONN *conn, app_poll_cb cb, void *cb_arg, int events)
{
    conn->app_poll_cb       = (events != 0 ? cb : NULL);
    conn->app_poll_cb_arg   = cb_arg;
    conn->app_poll_events   = (cb != NULL ? events : 0);
    return conn_update_poll(conn);
}

/*
 * Request by application to try to read an application datagram. Semantics are
 * the same as SSL_read_ex(3) for DTLS, but we automatically track cases where the
 * TLS stack is blocked on network I/O in the opposite direction so we can
 * update our own internal readiness event mask accordingly.
 */
static int CONN_read(CONN *conn,
                     void *buf, size_t buf_len, size_t *bytes_read)
{
    int ok = 0;

    if (conn->teardown)
        return 0;

    conn->want_read     = 0;
    conn->want_write    = 0;

    *bytes_read = 0;
    if (!SSL_read_ex(conn->ssl, buf, buf_len, bytes_read)) {
        switch (SSL_get_error(conn->ssl, 0)) {
        case SSL_ERROR_WANT_READ:
            break;
        case SSL_ERROR_WANT_WRITE:
            conn->want_write = 1;
            break;
        default:
            conn_on_net_error(conn);
            break;
        }
        goto out;
    }

    ok = 1;
out:
    conn_update_poll(conn);
    return ok;
}

/*
 * As for CONN_write. Semantics are the same as SSL_write_ex(3) for DTLS, but we
 * automatically track cases where the TLS stack is blocked on network I/O in
 * the opposite direction.
 */
static int CONN_write(CONN *conn,
                      const void *buf, size_t buf_len, size_t *bytes_written)
{
    int ok = 0;

    if (conn->teardown)
        return 0;

    conn->want_read     = 0;
    conn->want_write    = 0;

    *bytes_written = 0;
    if (!SSL_write_ex(conn->ssl, buf, buf_len, bytes_written)) {
        switch (SSL_get_error(conn->ssl, 0)) {
        case SSL_ERROR_WANT_READ:
            conn->want_read = 1;
            break;
        case SSL_ERROR_WANT_WRITE:
            break;
        default:
            conn_on_net_error(conn);
            break;
        }
        goto out;
    }

    ok = 1;
out:
    conn_update_poll(conn);
    return ok;
}

/*
 * Worker Thread Processing
 * ========================
 */

/* Add connection to end of list. */
static void worker_add_conn(WORKER *w, CONN *conn)
{
    assert(conn->w == w && !conn->on_list);

    conn->next = NULL;
    conn->prev = w->conn_tail;
    if (conn->prev != NULL)
        conn->prev->next = conn;

    w->conn_tail = conn;
    if (w->conn_head == NULL)
        w->conn_head = conn;

    conn->on_list = 1;
}

/* Remove connection from list. */
static void worker_remove_conn(WORKER *w, CONN *conn)
{
    assert(conn->w == w && w->conn_head != NULL && conn->on_list);

    if (conn->next != NULL)
        conn->next->prev = conn->prev;
    if (conn->prev != NULL)
        conn->prev->next = conn->next;

    if (w->conn_head == conn)
        w->conn_head = conn->next;
    if (w->conn_tail == conn)
        w->conn_tail = conn->prev;

    conn->prev = conn->next = NULL;
    conn->on_list = 0;
}

static void worker_take_conn(WORKER *w, CONN *conn)
{
#ifndef USE_LISTENER
    int rc;
#endif

    assert(conn->w == w);

#ifndef USE_LISTENER
    conn->poll.data = conn;
    if ((rc = uv_poll_init(&w->loop, &conn->poll, conn->fd)) < 0) {
        log_warn_uv(rc, "uv_poll_init failed");
        conn_delete(conn);
        return;
    }

    conn->poll_valid = 1;
#else
    /*
     * Ensure we do not acquire any network RX lock granule (LG) for the QUIC
     * domain when trying to read or write from a connection to ensure we do not
     * contend with the main thread performing listener work.
     */
    SSL_set_autotick(conn->ssl, SSL_AUTOTICK_FLAG_INHIBIT_RX);
#endif

    worker_add_conn(w, conn);
    conn_update_poll(conn);
    app_on_conn(conn, conn->ssl);
    return;
}

static void worker_on_close_wakeup(uv_handle_t *h)
{
    WORKER *w = h->data;

    assert(w->num_to_close > 0);
    --w->num_to_close;
}

static void worker_on_wakeup(uv_async_t *h)
{
    WORKER *w = h->data;
    CONN *new_conn;

    /* Two possible wakeup events: shutdown and new incoming connection. */
    if (g_int) {
        log_warn("stopping worker %zu", w->idx);
        uv_stop(&w->loop);
        return;
    }

    /* Got new connection? */
    uv_mutex_lock(&w->mutex);
    new_conn = w->conn_mbox;
    w->conn_mbox = NULL;
    uv_mutex_unlock(&w->mutex);

    if (new_conn != NULL)
        worker_take_conn(w, new_conn);

#ifdef USE_LISTENER
    /*
     * Drill down into individual connections which may be ready to make
     * progress using our worker-local poll group.
     */
    {
# define EVENTS_PER_CALL 8
        static const struct timeval now = {0};
        OSSL_POLL_EVENT ev_info[EVENTS_PER_CALL];
        size_t i, result_count = 0;

        if (!OSSL_POLL_GROUP_poll(w->poll_group, ev_info, EVENTS_PER_CALL,
                                  &now, 0, &result_count)) {
            log_warn_ssl("OSSL_POLL_GROUP_poll failed");
            return;
        }

        for (i = 0; i < result_count; ++i) {
            if (ev_info[i].desc.type != BIO_POLL_DESCRIPTOR_TYPE_SSL)
                continue;

            assert(!SSL_is_listener(ev_info[i].desc.value.ssl));
            if (SSL_is_connection(ev_info[i].desc.value.ssl)) {
                int events = 0;

                if ((ev_info[i].revents & OSSL_POLL_EVENT_R) != 0)
                    events |= UV_READABLE;
                if ((ev_info[i].revents & OSSL_POLL_EVENT_W) != 0)
                    events |= UV_WRITABLE;
                if ((ev_info[i].revents & OSSL_POLL_EVENT_E) != 0)
                    events |= UV_DISCONNECT;

                conn_on_io_ready((CONN *)ev_info[i].cookie, 0, events);
            }
        }
    }
#endif
}

static void worker_teardown(WORKER *w)
{
    int rc;
    CONN *conn, *cnext;

    if (!w->have_loop)
        return;

    for (conn = w->conn_head; conn != NULL; conn = cnext) {
        cnext = conn->next;
        CONN_teardown(conn);
    }

    if (w->have_wakeup) {
        ++w->num_to_close;
        uv_close((uv_handle_t *)&w->wakeup, worker_on_close_wakeup);
    }

    while (w->num_to_close > 0)
        uv_run(&w->loop, UV_RUN_ONCE);

    if ((rc = uv_loop_close(&w->loop)) < 0)
        log_warn_uv(rc, "uv_loop_close failed");

    w->have_wakeup = 0;
    w->have_loop   = 0;
}

static int worker_main(WORKER *w)
{
    int rc, ok = 0;

    log_warn("worker %zu: running", w->idx);
    if ((rc = uv_run(&w->loop, UV_RUN_DEFAULT)) < 0) {
        log_warn_uv(rc, "uv_run failed");
        goto err;
    }

    log_warn("worker thread %zu: done", w->idx);
    ok = 1;
err:
    return ok;
}

static void worker_main_p(void *arg)
{
    WORKER *w = arg;

    w->rc = worker_main(w);
}

static int worker_start(WORKER *w)
{
    int rc;

    w->loop.data = w;
    if ((rc = uv_loop_init(&w->loop)) < 0) {
        log_warn_uv(rc, "uv_loop_init failed");
        return 0;
    }

    w->have_loop = 1;
    w->wakeup.data = w;
    if ((rc = uv_async_init(&w->loop, &w->wakeup, worker_on_wakeup)) < 0) {
        log_warn_uv(rc, "uv_async_init failed");
        return 0;
    }

    w->have_wakeup = 1;
    if ((rc = uv_thread_create(&w->t, worker_main_p, w)) < 0) {
        log_warn_uv(rc, "failed to create worker thread %zu", w->idx);
        return 0;
    }

    w->active = 1;
    return 1;
}

static void worker_wait(WORKER *w)
{
    if (!w->active)
        return;

    uv_thread_join(&w->t);
    w->active = 0;
}

static void worker_put_new_conn(WORKER *w, CONN *conn)
{
    int rc, done = 0;

    assert(conn->w == NULL || conn->w == w);
    conn->w = w;

    while (!done) {
        uv_mutex_lock(&w->mutex);
        if (w->conn_mbox == NULL) {
            w->conn_mbox = conn;
            done = 1;
        }
        uv_mutex_unlock(&w->mutex);
    }

    if ((rc = uv_async_send(&w->wakeup)) < 0)
        log_warn_uv(rc, "uv_async_send failed");
}

/*
 * Incoming Connection Handling {{{1
 * ============================
 */
static WORKER *accepter_choose_worker(ACCEPTER *a);

static void listener_on_close(uv_handle_t *h)
{
    LISTENER *l = h->data;

    assert(g_accepter.num_to_close > 0);
    --g_accepter.num_to_close;

    l->have_poll = 0;
}

#ifndef USE_LISTENER
static int listener_ensure_spare_ssl(LISTENER *l)
{
    if (l->spare_ssl != NULL)
        return 1;

    if ((l->spare_ssl = SSL_new(g_ssl_ctx)) == NULL) {
        log_warn_ssl("SSL_new failed");
        return 0;
    }

    if (!BIO_up_ref(l->listen_bio)) {
        log_warn_ssl("BIO_up_ref failed");
        return 0;
    }

    SSL_set_bio(l->spare_ssl, l->listen_bio, l->listen_bio);
    return 1;
}
#endif

#ifdef USE_LISTENER
static void listener_process_new_conn(LISTENER *l, SSL *ssl)
#else
static void listener_process_new_conn(LISTENER *l, SSL *ssl,
                                      const BIO_ADDR *peer_addr)
#endif
{
#ifndef USE_LISTENER
    int rc, conn_fd = -1;
#endif
    CONN *conn = NULL;
    WORKER *w;

    w = accepter_choose_worker(&g_accepter);

    if ((conn = calloc(1, sizeof(CONN))) == NULL) {
        log_warn_errno("calloc failed");
        goto err;
    }

#ifndef USE_LISTENER
    if ((conn->peer_addr = BIO_ADDR_new()) == NULL) {
        log_warn_ssl("BIO_ADDR_new failed");
        goto err;
    }

    BIO_ADDR_copy(conn->peer_addr, peer_addr);

    if ((conn_fd = create_socket(l->port, SOCK_DGRAM, /*reuseport=*/0)) < 0)
        goto err;

    if ((rc = connect(conn_fd, (struct sockaddr *)peer_addr,
                      sizeof(struct sockaddr_storage))) < 0) {
        log_warn_errno("connect new accepted socket");
        goto err;
    }
#endif

    conn->ssl = ssl;

#ifndef USE_LISTENER
    conn->fd  = conn_fd;
    if ((conn->ssl_bio = BIO_new_dgram(conn_fd, BIO_NOCLOSE)) == NULL) {
        log_warn_ssl("BIO_new_dgram failed");
        return;
    }

    BIO_ctrl(conn->ssl_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, conn->peer_addr);
    SSL_set_bio(ssl, conn->ssl_bio, conn->ssl_bio);

    SSL_accept(ssl); /* best effort */
#else
    /* Enroll in listener poll group */
    {
        OSSL_POLL_CHANGE chg[1];

        OSSL_POLL_CHANGE_set(&chg[0], SSL_as_poll_descriptor(ssl), 0,
                             conn, OSSL_POLL_EVENT_R, 0);
    }
#endif

    worker_put_new_conn(w, conn);
    return;

err:
#ifdef USE_LISTENER
    free(conn);
#else
    if (conn != NULL) {
        BIO_ADDR_free(conn->peer_addr);
        free(conn);
    }
    if (conn_fd >= 0)
        closesocket(conn_fd);
#endif
}

static void listener_on_ready(uv_poll_t *h, int status, int events)
{
#ifdef USE_LISTENER
    static const struct timeval now = {0};
    LISTENER *l = h->data;
    SSL *conn_ssl;
    size_t i, result_count = 0;
    OSSL_POLL_EVENT ev_info[EVENTS_PER_CALL];

    /*
     * When this demo runs in DTLS mode, the BCG processing model is used and
     * DTLS connections are handled locally on a worker thread after initial
     * acceptance. When this demo runs in QUIC mode, the IPSM processing model
     * is used, which means there is a single socket and no thread affinity for
     * RX network traffic processing. This means that in principle, all threads
     * under the same QUIC domain (in this case, the same QUIC listener object)
     * are contending for access to the same shared state of the QUIC engine and
     * RX BIO resources. This is suboptimal from a performance perspective, but
     * it is the only straightforward implementation model without relying on
     * OS-specific mechanisms and complications to the API between libssl and a
     * network BIO.
     *
     * As such, in the QUIC build of this demo, libuv pollers are removed from
     * the worker threads and all worker thread processing is triggered via
     * uv_async_t wakeup from this thread. A master OSSL_POLL_GROUP in the
     * accepter is polled in non-blocking mode when we might have made progress
     * on any listener or connection/stream, and then wakes up the assigned
     * worker.
     */
    do {
        if (!OSSL_POLL_GROUP_poll(l->poll_group, ev_info, EVENTS_PER_CALL, &now,
                                  0, &result_count)) {
            log_warn_ssl("OSSL_POLL_GROUP_poll failed");
            return;
        }

        for (i = 0; i < result_count; ++i) {
            if (ev_info[i].desc.type != BIO_POLL_DESCRIPTOR_TYPE_SSL)
                continue;

            if (SSL_is_listener(ev_info[i].desc.value.ssl)) {
                assert(ev_info[i].cookie == l);

                while ((conn_ssl
                            = SSL_accept_connection(l->listen_ssl, 0)) != NULL)
                    listener_process_new_conn(l, conn_ssl);
            } else if (SSL_is_connection(ev_info[i].desc.value.ssl)) {
                CONN *conn = ev_info[i].cookie;

                if ((rc = uv_async_send(&conn->w->wakeup)) < 0)
                    log_warn_uv(rc, "uv_async_send failed");
            }
        }
    } while (result_count > 0);

#else
    int rc;
    LISTENER *l = h->data;

    if (!listener_ensure_spare_ssl(l))
        return;

# ifdef USE_QUIC
    /* QUIC but without using a listener */
    rc = OSSL_QUIC_listen(l->spare_ssl, l->peer_addr);
# else
    rc = DTLSv1_listen(l->spare_ssl, l->peer_addr);
# endif
    if (rc < 0) {
        log_warn_ssl("stateless listen failed");
        return;
    }

    if (rc < 1)
        /* Nothing yet, wait again. */
        return;

    listener_process_new_conn(l, l->spare_ssl, l->peer_addr);
    l->spare_ssl = NULL;
#endif
}

static WORKER *accepter_choose_worker(ACCEPTER *a)
{
    size_t idx = a->next_worker_idx;

    a->next_worker_idx = (idx + 1) % NUM_WORKERS;
    return &g_workers[idx];
}

static void accepter_on_signal_close(uv_handle_t *h)
{
    assert(g_accepter.num_to_close > 0);
    --g_accepter.num_to_close;
    g_accepter.have_signal = 0;
}

static void accepter_teardown(ACCEPTER *a)
{
    int rc;
    size_t i;

    if (!a->have_loop)
        return;

    for (i = 0; i < NUM_LISTENERS; ++i)
        if (g_listeners[i].have_poll) {
            ++a->num_to_close;
            uv_close((uv_handle_t *)&g_listeners[i].poll, listener_on_close);
        }

    if (a->have_signal) {
        ++a->num_to_close;
        uv_close((uv_handle_t *)&a->signal, accepter_on_signal_close);
    }

    while (a->num_to_close > 0)
        uv_run(&a->loop, UV_RUN_ONCE);

    if ((rc = uv_loop_close(&a->loop)) < 0) {
        log_warn_uv(rc, "uv_loop_close failed");
        return;
    }

    a->have_loop = 0;
}

static void on_signal(uv_signal_t *h, int s)
{
    g_int = 1;
    uv_stop(&g_accepter.loop);
}

static int accepter_run(ACCEPTER *a)
{
    int ok = 0, rc;
    size_t i;

    if ((rc = uv_loop_init(&a->loop)) < 0) {
        log_warn_uv(rc, "uv_loop_init failed");
        goto err;
    }

    a->have_loop = 1;
    a->signal.data = a;
    if ((rc = uv_signal_init(&a->loop, &a->signal))) {
        log_warn_uv(rc, "uv_signal_init failed");
        goto err;
    }

    a->have_signal = 1;
    if ((rc = uv_signal_start(&a->signal, on_signal, SIGINT)) < 0) {
        log_warn_uv(rc, "uv_signal_start failed");
        goto err;
    }

    for (i = 0; i < NUM_LISTENERS; ++i) {
        g_listeners[i].poll.data = &g_listeners[i];
        if ((rc = uv_poll_init(&a->loop, &g_listeners[i].poll,
                               g_listeners[i].listen_fd)) < 0) {
            log_warn_uv(rc, "uv_poll_init failed");
            goto err;
        }

        g_listeners[i].have_poll = 1;
        if ((rc = uv_poll_start(&g_listeners[i].poll, UV_READABLE,
                                listener_on_ready)) < 0) {
            log_warn_uv(rc, "uv_poll_start failed");
            goto err;
        }
    }

    if ((rc = uv_run(&a->loop, UV_RUN_DEFAULT)) < 0)
        log_warn_uv(rc, "uv_run failed");

    ok = 1;
err:
    accepter_teardown(a);
    return ok;
}

/*
 * Main {{{1
 * ====
 */
int main(int argc, char **argv)
{
    int exit_code = EXIT_FAILURE;
    size_t i;

    /* Parse command line arguments. */
    if (!parse_args(argc, argv, NUM_LISTENERS))
        goto err;

    /* Configure SSL context and set as g_ssl_ctx. */
    if (!create_ssl_ctx())
        goto err;

    /* Mandatory callbacks for DTLS. */
    SSL_CTX_set_cookie_generate_cb(g_ssl_ctx, on_cookie_generate);
    SSL_CTX_set_cookie_verify_cb(g_ssl_ctx, on_cookie_verify);

    /* Create bookkeeping structures for workers. */
    if ((g_workers = calloc(NUM_WORKERS, sizeof(WORKER))) == NULL)
        goto err;

    /* Create bookkeeping structures for listeners. */
    if ((g_listeners = calloc(NUM_LISTENERS, sizeof(LISTENER))) == NULL)
        goto err;

    for (i = 0; i < NUM_LISTENERS; ++i) {
        g_listeners[i].idx          = i;
        g_listeners[i].port         = g_port + i;
        g_listeners[i].listen_fd    = -1;
    }

    /* Create listening UDP sockets. */
    for (i = 0; i < NUM_LISTENERS; ++i) {
        if ((g_listeners[i].listen_fd = create_socket(g_port + i, SOCK_DGRAM,
                                                      /*reuseport=*/0)) < 0)
            goto err;

        if ((g_listeners[i].listen_bio
                = BIO_new_dgram(g_listeners[i].listen_fd, BIO_NOCLOSE)) == NULL) {
            log_warn_ssl("couldn't create listener BIO");
            goto err;
        }

#ifndef USE_LISTENER
        if ((g_listeners[i].peer_addr = BIO_ADDR_new()) == NULL) {
            log_warn_ssl("couldn't create BIO_ADDR");
            goto err;
        }
#else
        if ((g_listeners[i].listen_ssl = SSL_new_listener(g_ssl_ctx)) == NULL) {
            log_warn_ssl("couldn't create listener");
            goto err;
        }

        SSL_set_bio(g_listeners[i].listen_ssl,
                    g_listeners[i].listen_bio,
                    g_listeners[i].listen_bio);

        /*
         * Set INHIBIT_CHILD_CONN on the listener SSL object (QLSO) so that the
         * main thread, which accepts all connections, does not acquire the lock
         * granule (LG) for existing connections and thus create high degrees of
         * contention with worker threads responsible for servicing existing
         * connections.
         */
        SSL_set_autotick(g_listeners[i].listen_ssl,
                         SSL_AUTOTICK_FLAG_INHIBIT_CHILD_CONN);

        if (!SSL_listen(g_listeners[i].listen_ssl)) {
            log_warn_ssl("couldn't start listening");
            goto err;
        }
#endif
    }

    /* Spawn workers. */
    for (i = 0; i < NUM_WORKERS; ++i) {
        g_workers[i].idx = i;

        if (!worker_start(&g_workers[i])) {
            log_warn("failed to start worker %zu", i);
            goto err;
        }
    }

    log_warn("process %lu listening on [::]:%lu..%lu",
              (unsigned long)getpid(), (unsigned long)g_port,
              (unsigned long)g_port + NUM_LISTENERS - 1);

    /* Use main thread to service incoming connection requests. */
    if (!accepter_run(&g_accepter)) {
        log_warn("accepter failed");
        goto err;
    }

    exit_code = EXIT_SUCCESS;
err:
    /* Tell workers to stop. */
    g_int = 1;
    for (i = 0; i < NUM_WORKERS; ++i)
        if (g_workers[i].active)
            uv_async_send(&g_workers[i].wakeup);

    /* Wait for workers and teardown worker state. */
    if (g_workers != NULL) {
        for (i = 0; i < NUM_WORKERS; ++i)
            worker_wait(&g_workers[i]);

        for (i = 0; i < NUM_WORKERS; ++i)
            worker_teardown(&g_workers[i]);

        free(g_workers);
        g_workers = NULL;
    }

    /* Teardown listener state. */
    if (g_listeners != NULL) {
        for (i = 0; i < NUM_LISTENERS; ++i) {
#ifdef USE_LISTENER
            SSL_free(g_listeners[i].listen_ssl);
#else
            SSL_free(g_listeners[i].spare_ssl);
            BIO_ADDR_free(g_listeners[i].peer_addr);
#endif
            BIO_free_all(g_listeners[i].listen_bio);
            if (g_listeners[i].listen_fd >= 0)
                closesocket(g_listeners[i].listen_fd);
        }

        free(g_listeners);
        g_listeners = NULL;
    }

    cleanup_ssl_ctx();
    return exit_code;
}

/*
 * Application {{{1
 * ===========
 */
#define APP_BUF_LEN     4096

static void app_on_io_ready(CONN *conn, SSL *ssl, int events, void *arg)
{
    size_t bytes_read, bytes_written;

    for (;;) {
        while (conn->app_buf_len > 0) {
            bytes_written = 0;
            if (!CONN_write(conn, conn->app_buf, conn->app_buf_len,
                            &bytes_written)) {
                /*
                 * If we are blocked on write, stop listening for incoming data
                 * and now listen only for write readiness.
                 */
                if (SSL_get_error(ssl, 0) == SSL_ERROR_WANT_WRITE)
                    CONN_poll_start(conn, app_on_io_ready, NULL, UV_WRITABLE);
                else
                    diagnose_ssl_io_error(ssl, /*is_write=*/1, 0);

                return;
            }

            /*
             * We have datagram semantics, so datagrams are truncated and we
             * never resume writing datagrams which we partially wrote
             * previously.
             */
            conn->app_buf_len = 0;
        }

        /*
         * If we are not currently trying to flush a write buffer,
         * we always listen for more incoming data.
         */
        CONN_poll_start(conn, app_on_io_ready, NULL, UV_READABLE);

        bytes_read = 0;
        if (!CONN_read(conn, conn->app_buf, APP_BUF_LEN, &bytes_read)) {
            if (SSL_get_error(ssl, 0) != SSL_ERROR_WANT_READ)
                diagnose_ssl_io_error(ssl, /*is_write=*/0, 0);

            return;
        }

        conn->app_buf_len = bytes_read;
    }
}

static void app_on_conn(CONN *conn, SSL *ssl)
{
    if ((conn->app_buf = malloc(APP_BUF_LEN)) == 0) {
        CONN_teardown(conn);
        return;
    }

    CONN_poll_start(conn, app_on_io_ready, NULL, UV_READABLE);
}
