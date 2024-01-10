#define USE_LIBUV
#include "ddd-server-common.h"
#include <uv.h>
#include <stdarg.h>
#include <assert.h>

#if !defined(ADDRESSED)
# error ADDRESSED must be #defined as a boolean value
#endif

/*
 * ddd-server-async
 * ================
 *
 * Asynchronous, event-oriented (and multithreaded) multi-listener TCP-TLS echo
 * server example built using libuv.
 *
 * We support multiple TCP listeners, with incoming connections scheduled over
 * multiple threads and, using libuv, in an event-based manner on each
 * individual thread.
 *
 * libssl API usage is fully non-blocking. Because libuv does not support
 * multithreaded operation, a single libuv event loop object must be confined to
 * use on a particular worker thread. We handle this by creating one socket per
 * listening port (using SO_REUSEPORT) for each worker thread. This ensures that
 * the OS performs fanout of incoming connection requests evenly. Thus a
 * particular connection belongs to a specific worker thread for its entire
 * lifetime.
 *
 *
 *      |  worker thread          |  |  worker thread          |  ...
 *      |-------------------------|  |-------------------------|
 *      |  listening socket 1230  |  |  listening socket 1230  |
 *      |  listening socket 1231  |  |  listening socket 1231  |
 *      |  ...                    |  |  ...                    |
 *      |                         |  |                         |
 *      |  ----  ----             |  |  ----  ----             |
 *      |  conn  conn  ...        |  |  conn  conn  ...        |
 *      |  ----  ----             |  |  ----  ----             |
 *      |                         |  |                         |
 *
 * Cardinality:
 *
 *   number of workers                  = p
 *   number of listening ports          = q
 *   total number of listening sockets  = p * q
 *
 *   1 process
 *     p workers
 *       q listening sockets/ports per worker
 *       0..n open connections per worker
 *
 * The design of connection handling is split between infrastructure to plumb
 * libssl into libuv (CONN), and the "application" (echo server) which then uses
 * that infrastructure. The application invokes the conn_* methods to read and
 * write data from the network, which provide a libuv-like interface. connp_*
 * functions are internal to the CONN infrastructure.
 *
 * libssl communication with the network is based around a memory buffer BIO:
 *
 *    ____________
 *   |            |  "app" |
 *   | CONN infra | <----- |  Application-level I/O requests
 *   |____________|        |
 *   async | SSL_read
 *       & | SSL_write
 *    _____v______
 *   |            |       |  Memory Buffer BIO  | infra |         |
 *   |   libssl   | <---> |                     | <---> |  libuv  | <---> network
 *   |____________| "net" |   for Network I/O   |  glue |         |
 *
 *
 * Each CONN object uses APP_WRITE_OP structures to track application-level
 * write requests. These are fed directly into SSL_write() as soon as
 * possible and then an application-specified callback is called once the buffer
 * provided by the application is no longer needed. Conversely incoming data is
 * fed into libssl via the memory buffer BIO, read out using SSL_read() and used
 * to generate an application callback.
 *
 * It is important to not get confused between "app" I/O and "net" I/O. An
 * APP-level I/O request is one made by the application 'above' libssl and the
 * CONN infrastructure. A NET-level I/O request is generated based on the
 * requests libssl makes to access the network, which the CONN infrastructure
 * does via buffering incoming and outgoing data via the memory buffer BIO.
 *
 * For example, for TLS, app I/O requests will contain application data,
 * whereas net I/O requests will contain TLS protocol data.
 */

#ifdef USE_QUIC
# define USE_LISTENER
#endif

/* Number of worker threads. */
#define NUM_WORKERS 3

/* Number of ports to listen on. */
#define NUM_LISTENERS 3

/*
 * Structure to track a worker thread. This owns one or more worker-listeners
 * (WLISTENERs).
 */
typedef struct worker_st WORKER;

/*
 * Structure to track a listener (one listening port). This owns multiple
 * WLISTENERs.
 */
typedef struct listener_st LISTENER;

/*
 * Structure to track a worker-listener. Each instance belongs to exactly one
 * WORKER (one thread) and owns a listening socket.
 */
typedef struct wlistener_st WLISTENER;

/*
 * Structure to track a connection. This belongs to exactly one WORKER (and
 * originally arrived via exactly one WLISTENER).
 */
typedef struct conn_st CONN;

/*
 * Structure to track an application-level write request, from the time the
 * request is made until the buffer is copied and we no longer need the
 * associated data buffer.
 */
typedef struct app_write_op_st APP_WRITE_OP;

/*
 * Structure to track a network-level write request, from the time the request
 * is made until libuv confirms the write has completed and no longer needs the
 * associated data buffer.
 */
typedef struct net_write_op_st NET_WRITE_OP;

typedef void (app_write_cb)(CONN *conn, int status, void *arg);
typedef void (app_read_cb)(CONN *conn, void *buf, size_t buf_len,
                           void *arg);

struct worker_st {
    uv_thread_t         t;              /* worker thread */
    uv_loop_t           loop;           /* thread-specific event loop */
    uv_async_t          wakeup;
    size_t              idx;            /* worker idx [0..p) */
    size_t              num_to_close;   /* number of libuv handles to close */
    WLISTENER           *listeners;     /* array of WLISTENERs, size q */
    CONN                *conn_head;     /* list of owned CONNs */
    CONN                *conn_tail;
    int                 rc;
    unsigned int        active  : 1;    /* thread running? */
};

struct listener_st {
    size_t              idx;            /* listener idx [0..q) */
    uint16_t            port;           /* port (host byte order) */
};

struct wlistener_st {
    WORKER              *w;             /* owning worker */
    LISTENER            *l;             /* overall listener information */
    uint16_t            port;           /* port (host byte order) */
    int                 fd;             /* listening socket */
    uv_tcp_t            tcp;
    unsigned int        active  : 1;
};

struct conn_st {
    CONN                *prev, *next;   /* for WORKER conn list */

    WORKER              *w;             /* owning worker */
    WLISTENER           *wl;            /* WLISTENER which accepted the conn */
    int                 fd;             /* socket FD */
    uv_tcp_t            tcp;

    /* Weakref to BIO given to SSL object (SSL object holds only ref) */
    BIO                 *ssl_bio;
    /* Network-side BIO (memory buffer) */
    BIO                 *net_bio;

    SSL                 *ssl;           /* TLS object for established conn */
    APP_WRITE_OP        *app_write_op_head, *app_write_op_tail;
    app_read_cb         *app_read_cb;
    void                *app_read_cb_arg;
    /*
     * If this is non-NULL, this is a net RX buffer we still have yet to be able
     * to flush into our memory buffer BIO. We stop net RX during this
     * condition, which will cause the transport protocol (e.g. kernel TCP) to
     * eventually cork the peer.
     */
    void                *read_stashed_buf;
    size_t              read_stashed_buf_len;
    size_t              read_stashed_buf_written;
    unsigned int        handshake_done  : 1; /* TLS handshake done? */
    unsigned int        teardown        : 1; /* teardown started? */
    unsigned int        on_list         : 1; /* on worker list? */
    unsigned int        tcp_valid       : 1; /* ->tcp is initialised? */
};

struct app_write_op_st {
    APP_WRITE_OP        *prev, *next;
    const uint8_t       *buf;
    size_t              buf_len, written;
    app_write_cb        *cb;
    void                *cb_arg;
    CONN                *conn;          /* associated connection */
};

struct net_write_op_st {
    uv_write_t          w;
    uv_buf_t            b;
    uint8_t             *buf;
    CONN                *conn;          /* associated connection */
};

static void connp_try_flush_net_write(CONN *conn);
static void connp_try_flush_net_write(CONN *conn);
static int connp_try_flush_app_read(CONN *conn);
static void conn_delete(CONN *conn);

/*
 * Connection Handling: Lifecycle Handling
 * =======================================
 */

static int conn_try_delete(CONN *conn)
{
    if (conn->tcp_valid)
        return 0;

    conn_delete(conn);
    return 1;
}

static void conn_tcp_on_close(uv_handle_t *h)
{
    CONN *conn = h->data;

    assert(conn->w->num_to_close > 0);
    --conn->w->num_to_close;

    conn->tcp_valid = 0;
    conn_try_delete(conn);
}

/* Start to teardown the connection. Subsequent calls are ignored. */
static void conn_teardown(CONN *conn)
{
    if (conn->teardown)
        return;

    conn->teardown = 1;

    if (conn_try_delete(conn))
        return;

    log_warn("worker %zu(%u): tearing down connection", conn->w->idx, conn->wl->port);

    /* Close the TCP connection. */
    if (conn->tcp_valid) {
        ++conn->w->num_to_close;
        uv_close((uv_handle_t *)&conn->tcp, conn_tcp_on_close);
    }
}

/*
 * Called in the event of a permanent network error; places the connection in a
 * terminal closed state.
 */
static void connp_on_net_error(CONN *conn)
{
    conn_teardown(conn);
}

/*
 * Connection Handling: Application-Level Write Handling
 * =====================================================
 */

/* Add app write op to end of connection's list. */
static void connp_enqueue_app_write_op(CONN *conn, APP_WRITE_OP *op)
{
    assert(op->conn == conn);

    op->next = NULL;
    op->prev = conn->app_write_op_tail;
    if (op->prev != NULL)
        op->prev->next = op;

    conn->app_write_op_tail = op;
    if (conn->app_write_op_head == NULL)
        conn->app_write_op_head = op;
}

/* Remove app write op from connection's list. */
static void connp_dequeue_app_write_op(CONN *conn, APP_WRITE_OP *op)
{
    assert(op->conn == conn && conn->app_write_op_head != NULL);

    if (conn->app_write_op_head->next == NULL) {
        conn->app_write_op_head = NULL;
        conn->app_write_op_tail = NULL;
    } else {
        conn->app_write_op_head = conn->app_write_op_head->next;
        conn->app_write_op_head->prev = NULL;
    }

    op->prev = op->next = NULL;
}

/*
 * Try to flush a given app write op into the SSL object and call the
 * application-provided callback if the operation was completed (successfully or
 * unsuccessfully), returning 1. Returns 0 if still pending.
 */
static int connp_try_flush_app_write(CONN *conn, APP_WRITE_OP *op)
{
    int rc, op_err_code = 0;
    size_t bytes_written;

    while (op->written < op->buf_len) {
        bytes_written = 0;
        rc = SSL_write_ex(conn->ssl, op->buf + op->written,
                          op->buf_len - op->written, &bytes_written);
        op->written += bytes_written;
        if (!rc) {
            rc = SSL_get_error(conn->ssl, rc);
            if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE)
                return 0;

            op_err_code = -rc;
            break;
        }
    }

    /* Call application provided callback, if any. */
    if (op->cb != NULL)
        op->cb(conn, op_err_code, op->cb_arg);

    return 1; /* done - we have succeeded or failed and op can be freed */
}

/*
 * Handle a single write operation, returning 1 if the operation finished
 * processing (successfully or unsuccessfully) or 0 if it is still pending.
 */
static int connp_handle_app_write_op(CONN *conn, APP_WRITE_OP *op)
{
    if (!connp_try_flush_app_write(conn, op))
        return 0;

    /* Op has finished processing */
    connp_dequeue_app_write_op(conn, op);
    free(op);
    return 1;
}

/*
 * Handle all queued pending application write operations.
 */
static void connp_handle_app_write_ops(CONN *conn)
{
    APP_WRITE_OP *op;

    while ((op = conn->app_write_op_head) != NULL)
        if (!connp_handle_app_write_op(conn, op))
            break;

    connp_try_flush_net_write(conn);
}

/*
 * Function used by application to write data to the connection.
 *
 * The callback cb, if non-NULL, is called when the write operation has
 * successfully or unsuccessfully completed. If successful, all data in app_data
 * is written (no short writes). Successive calls to conn_write are completed in
 * the order they are made.
 */
static int conn_write(CONN *conn,
                      const void *app_data, size_t app_data_len,
                      app_write_cb *cb, void *cb_arg)
{
    APP_WRITE_OP *op = NULL;

    if ((op = calloc(1, sizeof(APP_WRITE_OP))) == NULL)
        return 0;

    /* Queue the application-side write (SSL_write). */
    op->buf     = app_data;
    op->buf_len = app_data_len;
    op->conn    = conn;
    op->cb      = cb;
    op->cb_arg  = cb_arg;
    connp_enqueue_app_write_op(conn, op);

    /*
     * Handle any pending ops, including this one. Do not handle this op
     * directly as there may be other operations before it which need to be
     * completed in sequence (bytestream semantics).
     */
    connp_handle_app_write_ops(conn);

    /* Make a best effort attempt to flush to the network immediately. */
    connp_try_flush_net_write(conn);
    return 1;
}

/*
 * Connection Handling: Application-Level Read Handling
 * ====================================================
 */

static void connp_flush_stash(CONN *conn);

/*
 * Try to get any pending data out of the SSL object and use it to generate
 * application read callbacks.
 */
static int connp_try_flush_app_read(CONN *conn)
{
    int rc;
    size_t bytes_read, buf_len = 4096;
    void *buf;

    do {
        if (conn->app_read_cb == NULL)
            return 1;

        if ((buf = malloc(buf_len)) == NULL)
            return 0;

        bytes_read = 0;
        if (!SSL_read_ex(conn->ssl, buf, buf_len, &bytes_read)) {
            rc = SSL_get_error(conn->ssl, 0);
            if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE) {
                free(buf);
                break;
            } else {
                log_warn("worker %zu(%u): conn torn down due to SSL read error %d",
                         conn->w->idx, conn->wl->port, rc);
                diagnose_ssl_io_error(conn->ssl, /*is_write=*/0, 0);
                ERR_print_errors_fp(stderr);
                conn_teardown(conn);
                free(buf);
                return 0;
            }
        }

        connp_flush_stash(conn);
        conn->app_read_cb(conn, buf, bytes_read,
                          conn->app_read_cb_arg);
    } while (bytes_read == buf_len);

    return 1;
}

/*
 * Start trying to read from the connection, in the same vein as uv_read_start.
 * The callback takes ownership of the buffer (which must be freed using free())
 * and may be called multiple times. Returns 1 on success.
 */
static int conn_read_start(CONN *conn, app_read_cb *cb, void *cb_arg)
{
    conn->app_read_cb       = cb;
    conn->app_read_cb_arg   = cb_arg;
    return 1;
}

/*
 * Connection Handling: Network-Side Write Handling
 * ================================================
 */

#define WRITE_BUF_LEN       4096

static void connp_on_net_write_done(uv_write_t *req, int status)
{
    NET_WRITE_OP *op = (NET_WRITE_OP *)req->data;
    CONN *conn = op->conn;

    if (status < 0)
        connp_on_net_error(conn);

    /*
     * Free buffer and write operation tracking structure now that the operation
     * is done.
     */
    free(op->buf);
    free(op);

    /* Try and do another flush. */
    connp_try_flush_net_write(conn);
}

/*
 * Try to flush any pending data in the network BIO write side out to the
 * network (if any).
 */
static void connp_try_flush_net_write(CONN *conn)
{
    int rc;
    NET_WRITE_OP *op = NULL;
    uint8_t *buf = NULL;
    size_t rd;

    if ((buf = malloc(WRITE_BUF_LEN)) == NULL)
        goto err;

    if ((op = calloc(1, sizeof(NET_WRITE_OP))) == NULL)
        goto err;

    if (!BIO_read_ex(conn->net_bio, buf, WRITE_BUF_LEN, &rd))
        goto err;

    op->buf     = buf;
    op->conn    = conn;
    op->w.data  = op;
    op->b.base  = (char *)buf;
    op->b.len   = rd;

    rc = uv_write(&op->w, (uv_stream_t *)&conn->tcp, &op->b, 1,
                  connp_on_net_write_done);
    if (rc < 0) {
        log_warn_uv(rc, "uv_write failed");
        conn_teardown(conn);
        goto err;
    }

    return;

err:
    free(buf);
    free(op);
}

/*
 * Connection Handling: Network-Side Read Handling
 * ===============================================
 */
static void connp_update_net_read_state(CONN *conn);

static void connp_on_net_read_alloc(uv_handle_t *handle, size_t suggested_size,
                                    uv_buf_t *buf)
{
    buf->base   = malloc(suggested_size);
    buf->len    = suggested_size;
}

static void connp_read_stash(CONN *conn, void *buf, size_t buf_len, size_t written)
{
    assert(conn->read_stashed_buf == NULL);

    conn->read_stashed_buf          = buf;
    conn->read_stashed_buf_len      = buf_len;
    conn->read_stashed_buf_written  = written;

    connp_update_net_read_state(conn);
}

static void connp_flush_stash(CONN *conn)
{
    size_t written = 0;

    if (conn->read_stashed_buf != NULL) {
        if (!BIO_write_ex(conn->net_bio,
                          conn->read_stashed_buf + conn->read_stashed_buf_written,
                          conn->read_stashed_buf_len - conn->read_stashed_buf_written,
                          &written))
            goto out;

        conn->read_stashed_buf_written += written;
        if (conn->read_stashed_buf_written == conn->read_stashed_buf_len) {
            free(conn->read_stashed_buf);
            conn->read_stashed_buf = NULL;
            conn->read_stashed_buf_len = conn->read_stashed_buf_written = 0;
        }
    }

out:
    connp_update_net_read_state(conn);
}

/*
 * Called when we get data from the network. We immediately buffer it in our
 * network-side memory buffer BIO so that the SSL object can consume it when we
 * later call an SSL API I/O method.
 */
static void connp_on_net_read_done(uv_stream_t *stream, ssize_t nr,
                                   const uv_buf_t *buf)
{
    CONN *conn = (CONN *)stream->data;
    size_t written = 0;
    int rc, rcx;

    assert(conn->read_stashed_buf == NULL);

    if (nr < 0) {
        free(buf->base);
        connp_on_net_error(conn);
        return;
    }

    if (nr > 0
        && (!BIO_write_ex(conn->net_bio, buf->base, nr, &written)
            || written < (size_t)nr)) {
        /* Buffer is full, so stash. */
        connp_read_stash(conn, buf->base, nr, written);
        return;
    }

    free(buf->base);

    if (!conn->handshake_done) {
        rc = SSL_do_handshake(conn->ssl);
        if (rc > 0)
            conn->handshake_done = 1;
        else
            switch (rcx = SSL_get_error(conn->ssl, rc)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                break;
            default:
                log_warn("worker %zu(%u): connection torn down due to "
                         "SSL write error %d", conn->w->idx, conn->wl->port,
                         rcx);
                diagnose_ssl_io_error(conn->ssl, /*is_write=*/1, 0);
                ERR_print_errors_fp(stderr);
                conn_teardown(conn);
                return;
            }

        connp_try_flush_net_write(conn);
    }

    connp_try_flush_app_read(conn);
}

/*
 * Update whether we are trying to read from the network based on our current
 * state.
 */
static void connp_update_net_read_state(CONN *conn)
{
    if (conn->read_stashed_buf != NULL)
        uv_read_stop((uv_stream_t *)&conn->tcp);
    else
        uv_read_start((uv_stream_t *)&conn->tcp,
                      connp_on_net_read_alloc,
                      connp_on_net_read_done);
}

/*
 * Worker Management
 * =================
 */

static void worker_remove_conn(WORKER *w, CONN *conn);

static void conn_delete(CONN *conn)
{
    APP_WRITE_OP *op, *op_next;

    if (conn == NULL)
        return;

    assert(!conn->tcp_valid);

    if (conn->on_list)
        worker_remove_conn(conn->w, conn);

    for (op = conn->app_write_op_head; op != NULL; op = op_next) {
        op_next = op->next;
        if (op->cb != NULL)
            op->cb(conn, -1, op->cb_arg);

        free(op);
    }

    SSL_free(conn->ssl);
    conn->ssl = NULL;

    BIO_free_all(conn->net_bio);
    conn->net_bio = NULL;
    conn->ssl_bio = NULL;

    free(conn);
}

/* Add connection to end of list. */
static void worker_add_conn(WORKER *w, CONN *conn)
{
    assert(conn->w == w && conn->wl->w == w && !conn->on_list);

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
    assert(conn->w == w && conn->wl->w == w
           && w->conn_head != NULL && conn->on_list);

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

static void wlistener_on_conn(uv_stream_t *h, int status);

static void wlistener_on_close(uv_handle_t *h)
{
    WLISTENER *wl = h->data;

    assert(wl->w->num_to_close > 0);
    --wl->w->num_to_close;
}

static void wlistener_cleanup(WLISTENER *wl)
{
    if (wl->active) {
        ++wl->w->num_to_close;
        uv_close((uv_handle_t *)&wl->tcp, wlistener_on_close);

        wl->active = 0;
    }

    if (wl->fd >= 0)
        closesocket(wl->fd);
}

static int wlistener_init(WLISTENER *wl)
{
    int ret = 0, rc;
    WORKER *w = wl->w;
    uint16_t port = wl->port;
    int reuseport = 1;

#ifndef SO_REUSEPORT
    /* Windows does not support SO_REUSEPORT. */
    reuseport = 0;
#endif

    if ((wl->fd = create_socket(port, SOCK_STREAM, reuseport)) < 0)
        goto err;

    wl->tcp.data = wl;
    if ((rc = uv_tcp_init(&w->loop, &wl->tcp)) < 0) {
        log_warn_uv(rc, "uv_tcp_init failed");
        goto err;
    }

    wl->active = 1;

    if ((rc = uv_tcp_open(&wl->tcp, wl->fd)) < 0) {
        log_warn_uv(rc, "uv_tcp_open failed");
        goto err;
    }

    if ((rc = uv_listen((uv_stream_t *)&wl->tcp, 50, wlistener_on_conn)) < 0) {
        log_warn_uv(rc, "uv_stream_listen failed");
        goto err;
    }

    log_warn("worker %zu: created socket %d for port %u", wl->w->idx, wl->fd, port);
    ret = 1;

err:
    if (!ret)
        wlistener_cleanup(wl);

    return ret;
}

static void app_on_conn(CONN *conn);

static void wlistener_on_conn(uv_stream_t *h, int status)
{
    int rc;
    WLISTENER *wl = h->data;
    CONN *conn;
    BIO *net_bio_ssl = NULL;

    if ((conn = calloc(1, sizeof(CONN))) == NULL) {
        log_warn_errno("worker %zu(%u): failed to allocate connection",
                       wl->w->idx, wl->port);
        return;
    }

    if ((conn->ssl = SSL_new(g_ssl_ctx)) == NULL) {
        log_warn("worker %zu(%u): failed to create SSL object",
                 wl->w->idx, wl->port);
        free(conn);
        goto err;
    }

    SSL_set_accept_state(conn->ssl);

    conn->w         = wl->w;
    conn->wl        = wl;
    conn->tcp.data  = conn;
    if ((rc = uv_tcp_init(&wl->w->loop, &conn->tcp)) < 0) {
        log_warn_uv(rc, "uv_tcp_init(conn) failed");
        goto err;
    }

    conn->tcp_valid = 1;

    if ((rc = uv_accept(h, (uv_stream_t *)&conn->tcp)) < 0) {
        log_warn_uv(rc, "uv_accept failed");
        goto err;
    }

    if ((rc = uv_fileno((uv_handle_t *)&conn->tcp,
                        (uv_os_fd_t *)&conn->fd)) < 0) {
        log_warn_uv(rc, "uv_fileno failed");
        goto err;
    }

    assert(conn->fd >= 0);

    if (!BIO_new_bio_pair(&net_bio_ssl, 0, &conn->net_bio, 0)) {
        log_warn("worker %zu(%u): failed to create BIO pair",
                 wl->w->idx, wl->port);
        goto err;
    }

    conn->ssl_bio = net_bio_ssl;
    SSL_set_bio(conn->ssl, net_bio_ssl, net_bio_ssl);

    worker_add_conn(wl->w, conn);
    log_warn("worker %zu(%u): accepted connection",
             wl->w->idx, wl->port);

    connp_update_net_read_state(conn);
    app_on_conn(conn);
    return;

err:
    conn_teardown(conn);
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

    log_warn("stopping worker %zu", w->idx);
    uv_stop(&w->loop);
}

static int worker_main(WORKER *w)
{
    int ret = 0, rc;
    size_t i;
    CONN *conn, *cnext;

    w->loop.data = w;
    if ((rc = uv_loop_init(&w->loop)) < 0) {
        log_warn_uv(rc, "uv_loop_init failed");
        goto err;
    }

    w->wakeup.data = w;
    if ((rc = uv_async_init(&w->loop, &w->wakeup, worker_on_wakeup)) < 0) {
        log_warn_uv(rc, "uv_async_init failed");
        goto err;
    }

    for (i = 0; i < NUM_LISTENERS; ++i)
        if (!wlistener_init(&w->listeners[i])) {
            log_warn_uv(rc, "wlistener init failed");
            goto err;
        }

    log_warn("worker %zu: running", w->idx);
    if ((rc = uv_run(&w->loop, UV_RUN_DEFAULT)) < 0) {
        log_warn_uv(rc, "uv_run failed");
        goto err;
    }

    log_warn("worker %zu: done", w->idx);
    ret = 1;
err:
    ++w->num_to_close;
    uv_close((uv_handle_t *)&w->wakeup, worker_on_close_wakeup);

    for (i = 0; i < NUM_LISTENERS; ++i)
        wlistener_cleanup(&w->listeners[i]);

    for (conn = w->conn_head; conn != NULL; conn = cnext) {
        cnext = conn->next;
        conn_teardown(conn);
    }

    while (w->num_to_close > 0)
        uv_run(&w->loop, UV_RUN_ONCE);

    if ((rc = uv_loop_close(&w->loop)) < 0)
        log_warn_uv(rc, "uv_loop_close failed");

    return ret;
}

static void worker_main_p(void *arg)
{
    WORKER *w = arg;

    w->rc = worker_main(w);
}

static int worker_start(WORKER *w)
{
    int rc;

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

/*
 * Main
 * ====
 */
int main(int argc, char **argv)
{
    int exit_code = EXIT_FAILURE;
    WORKER *workers = NULL;
    LISTENER *listeners = NULL;
    size_t i, j;

    /* Setup signal handlers. */
    setup_signals();

    /* Parse command line arguments. */
    if (!parse_args(argc, argv, NUM_LISTENERS))
        goto err;

    /* Configure SSL context and set as g_ssl_ctx. */
    if (!create_ssl_ctx())
        goto err;

    /* Create bookkeeping structures. */
    if ((workers = calloc(NUM_WORKERS, sizeof(WORKER))) == NULL)
        goto err;

    /* Create listener structures. */
    if ((listeners = calloc(NUM_LISTENERS, sizeof(LISTENER))) == NULL)
        goto err;

    for (i = 0; i < NUM_LISTENERS; ++i) {
        listeners[i].idx    = i;
        listeners[i].port   = g_port + i;
    }

    /* Create worker-listener structures. */
    for (i = 0; i < NUM_WORKERS; ++i) {
        WORKER *w = &workers[i];

        w->idx = i;
        if ((w->listeners = calloc(NUM_LISTENERS, sizeof(WLISTENER))) == NULL)
            goto err;

        for (j = 0; j < NUM_LISTENERS; ++j) {
            w->listeners[j].w           = w;
            w->listeners[j].l           = &listeners[j];
#ifdef _WIN32
            /*
             * Workaround: Win32 does not support SO_REUSEPORT, so just remap to
             * a different port for each worker.
             */
            w->listeners[j].port        = listeners[j].port + i * NUM_WORKERS;
#else
            w->listeners[j].port        = listeners[j].port;
#endif
            w->listeners[j].fd          = -1;
            w->listeners[j].tcp.data    = &w->listeners[j];
        }
    }

    /* Spawn workers. */
    for (i = 0; i < NUM_WORKERS; ++i)
        if (!worker_start(&workers[i])) {
            log_warn("failed to start worker %zu", i);
            goto err;
        }

    log_warn("process %lu listening on [::]:%u..%u (addressed=%d)",
             (unsigned long)getpid(),
             (unsigned int)g_port, (unsigned int)(g_port + NUM_LISTENERS - 1),
             ADDRESSED);

    while (!g_int)
        uv_sleep(1000);

    for (i = 0; i < NUM_WORKERS; ++i)
        uv_async_send(&workers[i].wakeup);

    exit_code = EXIT_SUCCESS;
err:
    if (workers != NULL) {
        for (i = 0; i < NUM_WORKERS; ++i)
            worker_wait(&workers[i]);

        for (i = 0; i < NUM_WORKERS; ++i)
            assert(workers[i].conn_head == NULL);

        for (i = 0; i < NUM_WORKERS; ++i)
            free(workers[i].listeners);

        free(workers);
    }

    free(listeners);
    cleanup_ssl_ctx();
    return exit_code;
}

/*
 * Application Connection Handler
 * ==============================
 */

static void app_on_write_done(CONN *conn, int status, void *arg)
{
    free(arg);
}

static void app_on_read(CONN *conn, void *buf, size_t buf_len,
                        void *arg)
{
    conn_write(conn, buf, buf_len, app_on_write_done, buf);
}

static void app_on_conn(CONN *conn)
{
    conn_read_start(conn, app_on_read, NULL);
}
