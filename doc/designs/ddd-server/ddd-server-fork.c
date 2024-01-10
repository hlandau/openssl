#include "ddd-server-common.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/*
 * ddd-server-fork
 * ===============
 *
 * Trivial post-fork() TCP-TLS echo server example. A master process calls
 * accept() repeatedly and then forks for each accepted connection, then
 * performs the SSL handshake on that connection and runs an echo server.
 *
 * For use with UNIX/POSIX systems only. This approach is the most "traditional"
 * (and inefficient) way to construct a UNIX daemon. Since fork() is called
 * after calling accept(), each child process services only a single connection.
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

int main(int argc, char **argv)
{
    int exit_code = EXIT_FAILURE, rc;
    int listen_fd = -1, child_fd;
    pid_t parent_pid, fork_pid;

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

    /* Main loop. */
    while (!g_int) {
        child_fd = accept(listen_fd, NULL, NULL);
        if (child_fd < 0) {
            if (errno == EINTR)
                continue;

            log_warn_errno("accept failed");
            goto err;
        }

        fork_pid = fork();
        if (fork_pid < 0) {
            log_warn_errno("fork failed");
            goto err;
        } else if (fork_pid != 0) {
            /*
             * We are the parent, close our copy of the FD and let the child
             * process handle it now.
             */
            close(child_fd);
        } else {
            /* We are the child process. */
            log_warn("forked from %lu to %lu to handle new connection",
                     (unsigned long)parent_pid, (unsigned long)getpid());
            rc = handle_conn(child_fd, g_ssl_ctx);
            if (rc != 1)
                log_warn("child handler failed");

            close(child_fd);
            cleanup_ssl_ctx(); /* free the child's SSL_CTX copy */
            exit(0);
        }
    }

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
