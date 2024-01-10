#define USE_LIBUV
#include "ddd-server-common.h"
#include <uv.h>
#include <stdarg.h>
#include <assert.h>

/*
 * ddd-server-async-pollable
 * =========================
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
 * that infrastructure. The application invokes the CONN_* methods to read and
 * write data from the network, which provide a libuv-like interface. conn_*
 * functions are internal to the CONN infrastructure. Functions which are
 * provided by the application and called into by the infrastructure are named
 * app_*.
 *
 * libssl communication with the network is based around directly passing it
 * a network socket file descriptor and determining readiness using a uv_poll_t
 * instance:
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
 */

#ifdef USE_QUIC
# define USE_LISTENER
#endif

 /* Number of worker threads. */
#define NUM_WORKERS     3

/* Number of ports to listen on. */
#define NUM_LISTENERS   3

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

/* Application I/O readiness callback. */
typedef void (app_poll_cb)(CONN *conn, SSL *ssl, int events, void *arg);

struct worker_st {
    uv_thread_t         t;              /* worker thread */
    uv_loop_t           loop;           /* thread-specific event loop */
    uv_async_t          wakeup;         /* inter-thread wakeup for shutdown */
    size_t              idx;            /* worker idx [0..p) */
    size_t              num_to_close;   /* number of libuv handles to close */
    WLISTENER           *listeners;     /* array of WLISTENERs, size q */
    CONN                *conn_head;     /* list of owned CONNs */
    CONN                *conn_tail;
    int                 rc;             /* thread return code */
    unsigned int        active  : 1;    /* thread running? */
};

struct listener_st {
    size_t              idx;            /* listener idx [0..q) */
    uint16_t            port;           /* port (host byte order) */
#ifdef USE_LISTENER
    int                 fd;             /* listening socket */
    uv_poll_t           poll;           /* poller for fd */
    SSL                 *listen_ssl;    /* QLSO */
#endif
};

struct wlistener_st {
    WORKER              *w;             /* owning worker */
    LISTENER            *l;             /* overall listener information */
    uint16_t            port;           /* port (host byte order) */
#ifdef USE_LISTENER
    OSSL_POLL_GROUP     *poll_group;
#else
    int                 fd;             /* listening socket */
    uv_tcp_t            tcp;            /* listening socket, owns FD */
#endif
    unsigned int        active  : 1;
};

struct conn_st {
    CONN                *prev, *next;   /* for WORKER conn list */

    WORKER              *w;             /* owning worker */
    WLISTENER           *wl;            /* WLISTENER which accepted the conn */
#ifndef USE_LISTENER
    int                 fd;             /* socket FD */
    uv_tcp_t            tcp;            /* owns FD */
    uv_poll_t           poll;           /* polls FD */

    /* Weakref to BIO given to SSL object (SSL object holds only ref) */
    BIO                 *ssl_bio;
#endif

    SSL                 *ssl;           /* TLS object for established conn */

    /* Callback for application when we are potentially ready to do I/O. */
    app_poll_cb         *app_poll_cb;
    void                *app_poll_cb_arg;
    int                 app_poll_events;  /* libuv events app wants */

    unsigned int        teardown    : 1; /* teardown started? */
    unsigned int        on_list     : 1; /* on worker list? */
#ifndef USE_LISTENER
    unsigned int        tcp_valid   : 1; /* ->tcp is initialised? */
    unsigned int        poll_valid  : 1; /* ->poll is initialized? */
#endif

    /*
     * The following track whether the TLS engine is internally blocked on
     * network-side read or writes.
     */
    unsigned int        want_read   : 1; /* TLS engine blocked on net-side read */
    unsigned int        want_write  : 1; /* TLS engine blocked on net-side write */

    /* Fields for application use. */
    uint8_t             *app_buf;
    size_t              app_buf_len, app_buf_written;
};

static void app_on_conn(CONN *conn, SSL *ssl);

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
    assert(!conn->tcp_valid);
#endif

    if (conn->on_list)
        worker_remove_conn(conn->w, conn);

    SSL_free(conn->ssl);
    conn->ssl = NULL;
    free(conn->app_buf);
    free(conn);
}

#ifndef USE_LISTENER
static int conn_try_delete(CONN *conn)
{
    if (conn->tcp_valid || conn->poll_valid)
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

static void conn_poll_on_close(uv_handle_t *h)
{
    CONN *conn = h->data;

    assert(conn->w->num_to_close > 0);
    --conn->w->num_to_close;

    conn->poll_valid = 0;
    if (conn_try_delete(conn))
        return;

    assert(conn->tcp_valid);
    ++conn->w->num_to_close;
    uv_close((uv_handle_t*)&conn->tcp, conn_tcp_on_close);
}
#endif

/*
 * Start to teardown the connection. Subsequent calls are ignored.
 * The application may also use this.
 */
static void CONN_teardown(CONN *conn)
{
    if (conn->teardown)
        return;

    conn->teardown = 1;

#ifdef USE_LISTENER
    conn_delete(conn);
#else
    if (conn->poll_valid)
        uv_poll_stop(&conn->poll);

    if (conn_try_delete(conn))
        return;

    log_warn("worker %zu(%u): tearing down connection", conn->w->idx, conn->wl->port);

    /* Close the poller. */
    if (conn->poll_valid) {
        ++conn->w->num_to_close;
        uv_close((uv_handle_t *)&conn->poll, conn_poll_on_close);
        return;
    }

    /* Close the TCP connection. */
    if (conn->tcp_valid) {
        ++conn->w->num_to_close;
        uv_close((uv_handle_t *)&conn->tcp, conn_tcp_on_close);
    }
#endif
}

/*
 * Called in the event of a permanent network error; places the connection in a
 * terminal closed state.
 */
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

    if ((events & UV_DISCONNECT) != 0)
        /*
         * Handle DISCONNECT as READABLE so libssl can handle it and generate a
         * clean EOF (SSL_ERROR_ZERO_RETURN) if appropriate.
         */
        events = (events & ~UV_DISCONNECT) | UV_READABLE;

    if (conn->app_poll_cb != NULL)
        conn->app_poll_cb(conn, conn->ssl, events, conn->app_poll_cb_arg);
}

static int conn_determine_desired_events(CONN *conn)
{
    /* Always listen for TCP connection termination/errors. */
#ifdef USE_LISTENER
    int events_mask = OSSL_POLL_EVENT_E;
#else
    int events_mask = UV_DISCONNECT;
#endif

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
    if (!OSSL_POLL_GROUP_change(conn->wl->poll_group, chg, 1, 0)) {
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
 * i.e. above TLS) I/O readiness events. Set events to 0 to disable callback.
 */
static int CONN_poll_start(CONN *conn, app_poll_cb cb, void *cb_arg, int events)
{
    conn->app_poll_cb       = (events != 0 ? cb : NULL);
    conn->app_poll_cb_arg   = cb_arg;
    conn->app_poll_events   = (cb != NULL ? events : 0);
    return conn_update_poll(conn);
}

/*
 * Request by application to try to read application data. Semantics are the
 * same as SSL_read_ex(3), but we automatically track cases where the TLS stack
 * is blocked on network I/O in the opposite direction so we can update our own
 * internal readiness event mask accordingly.
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
 * As for CONN_read. Semantics are the same as SSL_write_ex(3), but we
 * automatically track cases where the TLS stack is blocked on network I/O in
 * the opposite direction.
 */
static int CONN_write(CONN *conn, const void *buf, size_t buf_len,
                      size_t *bytes_written)
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
 * Worker Management
 * =================
 */
#ifdef USE_LISTENER
static void wlistener_on_conn(uv_poll_t *h, int status, SSL *conn_ssl);
#else
static void wlistener_on_conn(uv_stream_t *h, int status);
#endif

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

static void wlistener_on_close(uv_handle_t *h)
{
    WLISTENER *wl = h->data;

    assert(wl->w->num_to_close > 0);
    --wl->w->num_to_close;
#ifdef USE_LISTENER
    closesocket(wl->fd);
#endif
}

static void wlistener_cleanup(WLISTENER *wl)
{
#ifdef USE_LISTENER
    OSSL_POLL_GROUP_free(wl->poll_group);
    wl->poll_group = NULL;

    SSL_free(wl->listen_ssl);
    wl->listen_ssl = NULL;
#endif

    if (wl->active) {
        ++wl->w->num_to_close;
#ifdef USE_LISTENER
        uv_close((uv_handle_t *)&wl->poll, wlistener_on_close);
#else
        uv_close((uv_handle_t *)&wl->tcp, wlistener_on_close);
#endif

        wl->active = 0;
    } else if (wl->fd >= 0) {
        closesocket(wl->fd);
    }
}

#ifdef USE_LISTENER
static void wlistener_on_ready(uv_poll_t *h, int status, int events)
{
    static const struct timeval now = {0}; /* non-blocking */
    WLISTENER *wl = h->data;
#define EVENTS_PER_CALL 8
    OSSL_POLL_EVENT ev_info[EVENTS_PER_CALL];
    size_t i, result_count = 0;
    SSL *conn_ssl;

    if (!OSSL_POLL_GROUP_poll(wl->poll_group, ev_info, EVENTS_PER_CALL,
                              &now, 0, &result_count)) {
        log_warn_ssl("OSSL_POLL_GROUP_poll failed");
        return;
    }

    for (i = 0; i < result_count; ++i) {
        if (ev_info[i].desc.type != BIO_POLL_DESCRIPTOR_TYPE_SSL)
            continue;

        if (SSL_is_listener(ev_info[i].desc.value.ssl)) {
            while ((conn_ssl = SSL_accept_connection(wl->listen_ssl, 0)) != NULL)
                wlistener_on_conn(h, 0, conn_ssl);
        } else if (SSL_is_connection(ev_info[i].desc.value.ssl)) {
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

static int wlistener_update_poll(WLISTENER *wl)
{
    int rc, events = 0;

    if (SSL_net_read_desired(wl->listen_ssl))
        events |= UV_READABLE;
    if (SSL_net_write_desired(wl->listen_ssl))
        events |= UV_WRITABLE;

    if ((rc = uv_poll_start(&wl->poll, events, wlistener_on_ready)) < 0) {
        log_warn_uv(rc, "uv_poll_start/stop failed");
        return 0;
    }

    return 1;
}
#endif

static int wlistener_init(WLISTENER *wl)
{
    int ret = 0, rc;
    WORKER *w = wl->w;
    uint16_t port = wl->port;
    int reuseport = 1;
    int sock_type = SOCK_STREAM;
#ifdef USE_LISTENER
    OSSL_POLL_CHANGE chg[1];
#endif

#ifdef USE_QUIC
    sock_type = SOCK_DGRAM;
#endif

#ifndef SO_REUSEPORT
    /* Windows does not support SO_REUSEPORT. */
    reuseport = 0;
#endif

    if ((wl->fd = create_socket(port, sock_type, reuseport)) < 0)
        goto err;

#ifdef USE_LISTENER
    if ((wl->poll_group = OSSL_POLL_GROUP_new(NULL, 0, 0)) == NULL) {
        log_warn_ssl("cannot create poll group");
        goto err;
    }

    if ((wl->listen_ssl = SSL_new_listener(g_ssl_ctx, 0)) == NULL) {
        log_warn_ssl("cannot create SSL listener");
        goto err;
    }

    SSL_set_fd(wl->listen_ssl, wl->fd);

    wl->poll.data = wl;
    if ((rc = uv_poll_init_socket(&w->loop, &wl->poll, wl->fd)) < 0) {
        log_warn_uv(rc, "uv_poll_init_socket failed");
        goto err;
    }

    wl->active = 1;
    if (!SSL_listen(wl->listen_ssl))
        goto err;

    OSSL_POLL_CHANGE_set(&chg[0], SSL_as_poll_descriptor(wl->listen_ssl), 0,
                         wl, OSSL_POLL_EVENT_IC, 0);
    if (!OSSL_POLL_GROUP_change(wl->poll_group, chg, 1, 0)) {
        log_warn_ssl("poll group change failed");
        goto err;
    }

    if (!wlistener_update_poll(wl))
        goto err;
#else
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
#endif

    log_warn("worker %zu: created socket %d for port %u", wl->w->idx, wl->fd, port);
    ret = 1;

err:
    if (!ret)
        wlistener_cleanup(wl);

    return ret;
}

#ifdef USE_LISTENER
static void wlistener_on_conn(uv_poll_t *h, int status, SSL *conn_ssl)
#else
static void wlistener_on_conn(uv_stream_t *h, int status)
#endif
{
#ifndef USE_LISTENER
    int rc;
    BIO *net_bio_ssl = NULL;
#endif
    WLISTENER *wl = h->data;
    CONN *conn;

    if ((conn = calloc(1, sizeof(CONN))) == NULL) {
        log_warn_errno("worker %zu(%u): failed to allocate connection",
                       wl->w->idx, wl->port);
        return;
    }

#ifdef USE_LISTENER
    conn->ssl = conn_ssl;
#else
    if ((conn->ssl = SSL_new(g_ssl_ctx)) == NULL) {
        log_warn("worker %zu(%u): failed to create SSL object",
                 wl->w->idx, wl->port);
        free(conn);
        goto err;
    }
#endif

    SSL_set_accept_state(conn->ssl);

    conn->w         = wl->w;
    conn->wl        = wl;

#ifndef USE_LISTENER
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
                        (uv_os_fd_t*)&conn->fd)) < 0) {
        log_warn_uv(rc, "uv_fileno failed");
        goto err;
    }

    assert(conn->fd >= 0);

    conn->poll.data = conn;
    if ((rc = uv_poll_init_socket(&wl->w->loop, &conn->poll, conn->fd)) < 0) {
        log_warn_uv(rc, "uv_poll_init(conn) failed");
        goto err;
    }

    conn->poll_valid = 1;
#endif

    if (!conn_update_poll(conn))
        goto err;

#ifndef USE_LISTENER
    if ((net_bio_ssl = BIO_new_socket(conn->fd, BIO_NOCLOSE)) == NULL) {
        log_warn("BIO_new_socket failed");
        goto err;
    }

    conn->ssl_bio = net_bio_ssl;
    SSL_set_bio(conn->ssl, net_bio_ssl, net_bio_ssl);
#endif

    worker_add_conn(wl->w, conn);
    log_warn("worker %zu(%u): accepted connection",
             wl->w->idx, wl->port);

    app_on_conn(conn, conn->ssl);
    return;

err:
    CONN_teardown(conn);
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
        CONN_teardown(conn);
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

    /* Create bookkeeping structures for workers. */
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
#ifdef USE_LISTENER
            w->listeners[j].poll.data   = &w->listeners[j];
#else
            w->listeners[j].tcp.data    = &w->listeners[j];
#endif
        }
    }


    /* Spawn workers. */
    for (i = 0; i < NUM_WORKERS; ++i)
        if (!worker_start(&workers[i])) {
            log_warn("failed to start worker %zu", i);
            goto err;
        }

    log_warn("process %lu listening on [::]:%u..%u",
             (unsigned long)getpid(),
             (unsigned int)g_port, (unsigned int)(g_port + NUM_LISTENERS - 1));

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
 * Application
 * ===========
 */
#define APP_BUF_LEN     4096

static void app_on_io_ready(CONN *conn, SSL *ssl, int events, void *arg)
{
    size_t bytes_read, bytes_written;

    for (;;) {
        while (conn->app_buf_len > 0) {
            bytes_written = 0;
            if (!CONN_write(conn, conn->app_buf + conn->app_buf_written,
                            conn->app_buf_len - conn->app_buf_written,
                            &bytes_written)) {
                /*
                 * If we have not managed to flush the entire write buffer, stop
                 * listening for more incoming data and now listen only for
                 * write readiness.
                 */
                if (SSL_get_error(ssl, 0) == SSL_ERROR_WANT_WRITE)
                    CONN_poll_start(conn, app_on_io_ready, NULL, UV_WRITABLE);
                else
                    diagnose_ssl_io_error(ssl, /*is_write=*/1, 0);

                return;
            }

            conn->app_buf_written += bytes_written;
            if (conn->app_buf_written >= conn->app_buf_len)
                conn->app_buf_len = 0;
        }

        /*
         * If we are not currently trying to flush a write buffer, we always
         * listen for more incoming data.
         */
        CONN_poll_start(conn, app_on_io_ready, NULL, UV_READABLE);

        bytes_read = 0;
        if (!CONN_read(conn, conn->app_buf, APP_BUF_LEN, &bytes_read)
            || bytes_read == 0) {
            if (SSL_get_error(ssl, 0) != SSL_ERROR_WANT_READ)
                diagnose_ssl_io_error(ssl, /*is_write=*/0, 0);

            return;
        }

        conn->app_buf_len       = bytes_read;
        conn->app_buf_written   = 0;
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
