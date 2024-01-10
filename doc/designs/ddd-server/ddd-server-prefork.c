#include "ddd-server-common.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/*
 * ddd-server-prefork
 * ==================
 *
 * Trivial prefork-type TCP-TLS echo server example. A master process uses
 * fork() to create a fixed number of worker processes, each of which endlessly
 * accept connections from the same listening TCP socket and process them.
 *
 * Unlike ddd-server-fork, because a finite number of worker processes are
 * created up front, there is a limit to the number of concurrent connections
 * which can be processed. In a real design this would be ramped up and down
 * dynamically or otherwise addressed. Since such issues do not pertain to I/O
 * and concurrency issues and their interaction with QUIC API design, such
 * aspects are not modelled here.
 *
 * For use with UNIX/POSIX systems only. This approach is the evolved way to
 * construct a multi-process UNIX daemon, and is used (for example) by Apache's
 * mpm_prefork processing model. Typically, a child process might be thrown away
 * after processing a certain number of connections.
 *
 * Note that this involves a single socket on which accept() is being called
 * conrurrently in different processes, and not, for example, multiple sockets
 * bound to the same network endpoint using SO_REUSEPORT. SO_REUSEPORT is not
 * suitable for use here because while the aim is to evenly distribute incoming
 * connections to the different sockets all bound to the same endpoint, there is
 * no particular guarantee of the exact distribution and multiple incoming
 * connections could end up in the queue for one specific (currently busy)
 * worker and thus unavailable to be accept()ed by other idle workers. This is
 * as opposed to the single socket case where all accept() queues are popping
 * from the same single queue. SO_REUSEPORT is thus more suitable for use where
 * an implementation can guarantee minimal delay between successive accept()
 * calls on a single socket (i.e., event-based implementations). We will exhibit
 * SO_REUSEPORT in subsequent event-based examples.
 */
#ifdef USE_QUIC
# error This demo does not currently support QUIC
#endif

/*
 * Simple echo server. Each child process has this function as its main loop,
 * where fd is the socket of a single established TCP connection.
 */
static int handle_conn(int fd, SSL_CTX *ssl_ctx)
{
    int rc = 0, ret;
    size_t bytes_read, bytes_written;
    char buf[128], *p = buf;
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

/*
 * Child process main loop. This keeps accepting connections and processes a
 * connection one at a time.
 */
static int child_main(int listen_fd)
{
    int exit_code = EXIT_FAILURE;
    int child_fd;

    while (!g_int) {
        child_fd = accept(listen_fd, NULL, 0);
        if (child_fd < 0) {
            if (errno == EINTR)
                continue;

            log_warn_errno("accept failure");
            goto err;
        }

        handle_conn(child_fd, g_ssl_ctx);
        close(child_fd);
    }

    log_warn("child shutting down");
    exit_code = EXIT_SUCCESS;
err:
    cleanup_ssl_ctx(); /* free SSL_CTX copy in child process */
    return exit_code;
}

#define NUM_WORKERS     5


int main(int argc, char **argv)
{
    int exit_code = EXIT_FAILURE;
    int listen_fd = -1;
    pid_t parent_pid, fork_pid;
    size_t i, num_workers = NUM_WORKERS;

    /* Setup signal handlers. */
    setup_signals();

    /* Parse command line arguments. */
    if (!parse_args(argc, argv, /*num_ports=*/1))
        goto err;

    /* Configure SSL context and set as g_ssl_ctx. */
    if (!create_ssl_ctx())
        goto err;

    /* Create listening socket. */
    if ((listen_fd = create_socket(g_port, SOCK_STREAM, /*reuseport=*/0)) < 0) {
        log_warn_errno("cannot create socket");
        goto err;
    }

    /* Begin listening. */
    if (listen(listen_fd, 50) < 0) {
        log_warn_errno("listen failed");
        goto err;
    }

    parent_pid = getpid();
    log_warn("process %lu listening on [::]:%lu",
             (unsigned long)parent_pid,
             (unsigned long)g_port);

    /* Spawn worker processes. */
    for (i = 0; i < num_workers; ++i) {
        fork_pid = fork();
        if (fork_pid < 0) {
            log_warn_errno("fork failed, worker %zu", i);
            goto err;
        } else if (fork_pid == 0) {
            /* Child process. */
            exit(child_main(listen_fd));
        }
    }

    /* Wait until we are requested to exit. */
    while (!g_int)
        sleep(10000);

    log_warn("server shutting down");
    exit_code = EXIT_SUCCESS;
err:
    if (exit_code != 0)
        ERR_print_errors_fp(stderr);

    if (listen_fd >= 0)
        close(listen_fd);

    cleanup_ssl_ctx();
    return exit_code;
}
