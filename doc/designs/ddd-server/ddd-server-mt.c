#define USE_LIBUV
#define CUSTOM_HANDLER
#include "ddd-server-common.h"

/*
 * ddd-server-mt
 * =============
 *
 * Trivial multithreaded TCP-TLS echo server example. A single process spawns a
 * set of worker threads to handle accepted connections. While we could have
 * each thread call accept(), instead, to get some diversity of approach, we
 * have accept() serviced only by the main thread and distribute accepted
 * sockets to the worker threads via a mailbox.
 *
 * Because a finite number of worker processes are created up front, there is a
 * limit to the number of concurrent connections which can be processed. In a
 * real design this would be ramped up and down dynamically or otherwise
 * addressed. Since such issues do not pertain to I/O and concurrency issues and
 * their interaction with QUIC API design, such aspects are not modelled here.
 *
 * To further explore the design space, this demo, unlike the fork and prefork
 * designs, uses a multiple listener model where three different ports are
 * listened on. This creates the need to service three different sockets and
 * their accept queues.
 *
 * For use with UNIX/POSIX systems only. This approach is a reasonably modern
 * way to handle concurrent connection processing in a UNIX daemon. It can be
 * combined with a prefork model to create a multi-process, multiple threads per
 * process model if desired; we do not do this here as the relevant design
 * issues for multi-process approaches are explored in the fork and prefork
 * demos, and the relevant design issues for multi-thread approaches are
 * explored here, and the composition of the two is straightforward. An example
 * of such an approach is found in Apache httpd's mpm_worker processing module.
 *
 * Note that this involves a single socket on which accept() is being called
 * concurrently in different processes, and not, for example, multiple sockets
 * bound to the same network endpoint using SO_REUSEPORT. If this implementation
 * were changed to create threads dynamically, the latter approach would be
 * viable, as accept() would then be continuously serviced for each socket (see
 * comment in ddd-server-prefork).
 */

/*
 * A key part of supporting QUIC on the server side is abstracting FD handling,
 * etc. into a generic listener API so that accept operations can be implemented
 * in userspace instead of by an OS's built-in API such as accept(). However, we
 * can also support this unified API for conventional TLS over TCP usage. Thus,
 * the code in this file guarded by USE_QUIC represents QUIC-specific code;
 * whereas the code in this file guarded by USE_LISTENER represents code which
 * is not specific to QUIC but represents necessary application refactoring,
 * which could (after such a refactor is complete) be used to enable both TLS
 * and QUIC cases, assuming that it is acceptable for an application to drop
 * support for OpenSSL versions before 3.3.
 */
#ifdef USE_QUIC
# define USE_LISTENER
#endif

struct worker_info {
    size_t      idx;    /* g_workers[idx].idx == idx */
    uv_thread_t thread;
    int         active; /* thread created? */
};

#define NUM_WORKERS     5

static struct worker_info *g_workers;
static size_t g_num_workers;

static uv_mutex_t      g_mutex;
/* The following globals are protected by g_mutex */
static uv_cond_t       g_cond;
static uv_cond_t       g_cond_taken;
#ifdef USE_LISTENER
static SSL             *g_new_child_ssl;
#else
static int             g_new_fd = -1;
#endif

struct listener_info {
#ifdef USE_LISTENER
    SSL *listen_ssl;
#endif
    int listen_fd;
};

#define NUM_LISTENERS   3

static struct listener_info g_listeners[NUM_LISTENERS];

#ifndef _WIN32
static void on_int(int s)
{
    g_int = 1;
    uv_cond_broadcast(&g_cond);
    uv_cond_broadcast(&g_cond_taken);
}
#endif

/*
 * Simple echo server. Each child process has this function as its main loop,
 * where fd is the socket of a single established TCP connection.
 */
#ifdef USE_LISTENER
static int handle_conn(SSL *ssl, SSL_CTX *ssl_ctx)
#else
static int handle_conn(int fd, SSL_CTX *ssl_ctx)
#endif
{
    int rc = 0, ret;
    size_t bytes_read, bytes_written;
    char buf[128], *p = buf;
#ifndef USE_LISTENER
    SSL *ssl = NULL;

    /* Create an SSL object to use for our TLS connection. */
    if ((ssl = SSL_new(ssl_ctx)) == NULL) {
        log_warn("cannot create SSL object to handle socket FD %d", fd);
        goto err;
    }

    /*
     * Does not take ownership of fd; closed by child's main() after we return.
     */
    SSL_set_fd(ssl, fd);
#endif

    /* Perform the SSL handshake in the server role. */
    if (SSL_accept(ssl) <= 0) {
        log_warn("failed to complete SSL handshake");
        goto err;
    }

    /* Echo server loop. */
    for (;;) {
        if ((ret = SSL_read_ex(ssl, buf, sizeof(buf), &bytes_read)) == 0) {
            rc = diagnose_ssl_io_error(ssl, /*is_write=*/0, ret);
            goto err;
        }

        p = buf;
        while (bytes_read > 0) {
            if ((ret = SSL_write_ex(ssl, p, bytes_read, &bytes_written)) == 0) {
                rc = diagnose_ssl_io_error(ssl, /*is_write=*/1, ret);
                goto err;
            }

            p           += bytes_written;
            bytes_read  -= bytes_written;
        }
    }

err:
    /*
     * If we got a clean application EOF from the peer, perform a clean shutdown
     * in turn. This is a synchronous demo so SSL_shutdown() will block and we
     * shouldn't need to call it again.
     */
    if (rc != 0 && SSL_shutdown(ssl) != 1)
        log_warn("warning: got clean EOF but our own TLS shutdown was not clean");

    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    return rc;
}

#define NUM_WORKERS     5

#ifdef USE_LISTENER
static SSL *get_new_socket(void)
{
    SSL *r;

    uv_mutex_lock(&g_mutex);
    for (;;) {
        if (g_int) {
            uv_mutex_unlock(&g_mutex);
            return NULL;
        }

        if (g_new_child_ssl != NULL) {
            r = g_new_child_ssl;
            g_new_child_ssl = NULL;
            uv_cond_signal(&g_cond_taken);
            uv_mutex_unlock(&g_mutex);
            return r;
        }

        uv_cond_wait(&g_cond, &g_mutex);
    }
}
#else
static int get_new_socket(void)
{
    int fd;

    uv_mutex_lock(&g_mutex);
    for (;;) {
        if (g_int) {
            uv_mutex_unlock(&g_mutex);
            return -1;
        }

        if (g_new_fd >= 0) {
            fd = g_new_fd;
            g_new_fd = -1;
            uv_cond_signal(&g_cond_taken);
            uv_mutex_unlock(&g_mutex);
            return fd;
        }

        uv_cond_wait(&g_cond, &g_mutex);
    }
}
#endif

#ifdef USE_LISTENER
static void put_new_socket(SSL *child_ssl)
{
    uv_mutex_lock(&g_mutex);

    while (g_new_child_ssl != NULL) {
        if (g_int) {
            SSL_free(g_new_child_ssl);
            goto out;
        }

        uv_cond_wait(&g_cond_taken, &g_mutex);
    }

    g_new_child_ssl = child_ssl;
    uv_cond_signal(&g_cond);
out:
    uv_mutex_unlock(&g_mutex);
}
#else
static void put_new_socket(int fd)
{
    uv_mutex_lock(&g_mutex);

    while (g_new_fd >= 0) {
        if (g_int) {
            closesocket(fd);
            goto out;
        }

        uv_cond_wait(&g_cond_taken, &g_mutex);
    }

    g_new_fd = fd;
    uv_cond_signal(&g_cond);
out:
    uv_mutex_unlock(&g_mutex);
}
#endif

/*
 * Worker thread main loop.
 */
static void worker_main(void *arg)
{
    struct worker_info *worker = arg;
    size_t idx = worker->idx;
#ifdef USE_LISTENER
    SSL *child_ssl;
#else
    int child_fd;
#endif

    while (!g_int) {
#ifdef USE_LISTENER
        child_ssl = get_new_socket();
        if (child_ssl == NULL)
            break;

        log_warn("worker thread %zu: handling child SSL object", idx);
        handle_conn(child_ssl, g_ssl_ctx);
        SSL_free(child_ssl);
#else
        child_fd = get_new_socket();
        if (child_fd < 0)
            break;

        log_warn("worker thread %zu: handling child FD %d", idx, child_fd);
        handle_conn(child_fd, g_ssl_ctx);
        closesocket(child_fd);
#endif
    }

    log_warn("worker thread %zu: shutting down", idx);
}

int main(int argc, char **argv)
{
    int rc, exit_code = EXIT_FAILURE;
#ifdef USE_LISTENER
    SSL *child_ssl;
#else
    int child_fd;
#endif
    pid_t parent_pid;
    size_t i;

    for (i = 0; i < NUM_LISTENERS; ++i)
        g_listeners[i].listen_fd = -1;

    /* Setup signal handlers. */
    setup_signals();

    /* Condition variables for our incoming connection FD mailbox. */
    if ((rc = uv_mutex_init(&g_mutex)) < 0
        || (rc = uv_cond_init(&g_cond)) < 0
        || (rc = uv_cond_init(&g_cond_taken)) < 0) {
        log_warn_uv(rc, "uv sync init");
        goto err;
    }

    /* Parse command line arguments. */
    if (!parse_args(argc, argv, NUM_LISTENERS))
        goto err;

    /* Configure SSL context and set as g_ssl_ctx. */
    if (!create_ssl_ctx())
        goto err;

    /* Create bookkeeping structures. */
    if ((g_workers = calloc(NUM_WORKERS, sizeof(struct worker_info))) == NULL)
        goto err;

    g_num_workers = NUM_WORKERS;

    /* Create listening sockets. */
    for (i = 0; i < NUM_LISTENERS; ++i) {
        int sock_type;

#ifdef USE_QUIC
        sock_type = SOCK_DGRAM;
#else
        sock_type = SOCK_STREAM;
#endif

        if ((g_listeners[i].listen_fd = create_socket(g_port + i, sock_type,
                                                      /*reuseport=*/0)) < 0)
            goto err;

        /* Begin listening. */
#ifdef USE_LISTENER
        if ((g_listeners[i].listen_ssl = SSL_new_listener(g_ssl_ctx, 0)) == NULL) {
            log_warn_ssl("could not create listener");
            goto err;
        }

        SSL_set_fd(g_listeners[i].listen_ssl, g_listeners[i].listen_fd);

        if (!SSL_listen(g_listeners[i].listen_ssl)) {
            log_warn_ssl("could not listen");
            goto err;
        }
#else
        if (listen(g_listeners[i].listen_fd, 50) < 0) {
            log_warn_errno("listen failed");
            goto err;
        }
#endif
    }

    parent_pid = getpid();
    log_warn("process %lu listening on [::]:%lu..%lu",
             (unsigned long)parent_pid,
             (unsigned long)g_port,
             (unsigned long)g_port + NUM_LISTENERS - 1);

    /* Spawn worker threads. */
    g_num_workers = NUM_WORKERS;
    for (i = 0; i < g_num_workers; ++i) {
        g_workers[i].idx = i;
        if ((rc = uv_thread_create(&g_workers[i].thread, worker_main, &g_workers[i])) < 0) {
            log_warn_uv(rc, "failed to create worker thread %zu", i);
            goto err;
        }

        g_workers[i].active = 1;
    }

    /*
     * Use the main thread to service all of the listener accept queues. Poll
     * all of the listening sockets to see if we have any connections waiting.
     */
    while (!g_int) {
        size_t listener_idx = SIZE_MAX;
#ifdef USE_LISTENER
        OSSL_POLL_ITEM poll_items[NUM_LISTENERS];

        for (i = 0; i < NUM_LISTENERS; ++i) {
            /* listen for incoming connections only */
            poll_items[i].events = OSSL_POLL_EVENT_IC;
            poll_items[i].desc
                = SSL_as_poll_descriptor(g_listeners[i].listen_ssl);
        }

        if (!SSL_poll(poll_items, NUM_LISTENERS, sizeof(OSSL_POLL_ITEM),
                      NULL, 0, NULL)) {
            log_warn_ssl("failed to poll");
            goto err;
        }

        for (i = 0; i < NUM_LISTENERS; ++i)
            if ((poll_items[i].revents & OSSL_POLL_EVENT_IC) != 0) {
                listener_idx = i;
                break;
            }
#else
        fd_set rfd;

        FD_ZERO(&rfd);

        for (i = 0; i < NUM_LISTENERS; ++i)
            FD_SET(g_listeners[i].listen_fd, &rfd);

        errno = 0;
        if (select(1, &rfd, NULL, NULL, NULL) <= 0) {
            if (errno == EINTR)
                continue;

            log_warn_errno("failed to poll");
            goto err;
        }

        for (i = 0; i < NUM_LISTENERS; ++i)
            if (FD_ISSET(g_listeners[i].listen_fd, &rfd)) {
                listener_idx = i;
                break;
            }
#endif

        if (listener_idx == SIZE_MAX)
            continue;

        /* A listening socket has one or more connections ready. */
#ifdef USE_LISTENER
        child_ssl
            = SSL_accept_connection(g_listeners[listener_idx].listen_ssl, 0);
        if (child_ssl == NULL) {
            log_warn_ssl("SSL_accept_connection failed");
            goto err;
        }
#else
        child_fd = accept(g_listeners[listener_idx].listen_fd, NULL, NULL);
        if (child_fd < 0) {
            if (errno == EINTR)
                continue;

            log_warn_errno("accept failed");
            goto err;
        }
#endif

        /* Put new connection in mailbox for a worker thread to get it. */
#ifdef USE_LISTENER
        put_new_socket(child_ssl);
#else
        put_new_socket(child_fd);
#endif
    }

    log_warn("server shutting down");
    exit_code = EXIT_SUCCESS;
err:
    /*
     * If we shut down due to an error rather than a signal, inform every thread
     * and make sure it will start teardown.
     */
    g_int = 1;
    uv_cond_broadcast(&g_cond);

    if (exit_code != 0)
        ERR_print_errors_fp(stderr);

    for (i = 0; i < NUM_LISTENERS; ++i) {
#ifdef USE_LISTENER
        SSL_free(g_listeners[i].listen_ssl);
#endif
        if (g_listeners[i].listen_fd >= 0)
            closesocket(g_listeners[i].listen_fd);
    }

#ifdef USE_LISTENER
    if (g_new_child_ssl != NULL)
        SSL_free(g_new_child_ssl);
#else
    if (g_new_fd >= 0)
        closesocket(g_new_fd);
#endif

    cleanup_ssl_ctx();

    /* Wait for all threads to terminate. */
    if (g_workers != NULL) {
        for (i = 0; i < g_num_workers; ++i)
            if (g_workers[i].active)
                uv_thread_join(&g_workers[i].thread);

        free(g_workers);
        g_workers = NULL;
    }

    return exit_code;
}
