#ifndef DDD_SERVER_COMMON_H
# define DDD_SERVER_COMMON_H

# include <stdint.h>
# include <stddef.h>
# include <stdlib.h>
# include <errno.h>
# include <signal.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
# ifndef _WIN32
#  include <unistd.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <sys/select.h>
# else
#  include <winsock2.h>
#  include <ws2ipdef.h>
# endif
# ifdef USE_LIBUV
#  include <uv.h>
# endif

/*
 * Common Support Utilities for the DDD Server Demos
 * =================================================
 *
 * This file is included into each of the DDD Server demos and provides common
 * functionality such as:
 *
 *   - Argument parsing
 *   - Signal handling
 *   - SSL_CTX creation
 *   - logging SSL object I/O errors
 *
 * This functionality is placed in a separate file for two reasons:
 *
 *   - firstly, to factor common code;
 *
 *   - secondly, because this code is not really core to what we are trying to
 *     exhibit and provide exposition for with these demos, therefore keeping it
 *     in a second file enhances the pedagogical purpose of the demos and
 *     focuses attention at the matters at hand in the DDD demo process (which
 *     largely focuses on how I/O and concurrency questions are addressed).
 */

/* argv[0] */
static const char *g_prog_name;

/* Have we been requested to shut down the entire server? */
static int g_int;

/* The port (or first port in a contiguous range) we are going to listen on. */
static unsigned long g_port;

/* Paths to the certificate chain and private key files (PEM). */
static const char *g_chain_fn, *g_privkey_fn;

/* SSL_CTX used for establishing connections. */
static SSL_CTX *g_ssl_ctx;

/* SIGINT signal handler */
# ifndef _WIN32
static void on_int(int s)
#  ifndef CUSTOM_HANDLER
{
    g_int = 1;
}
#  else
;
#  endif
# endif

# ifndef _WIN32
#  define closesocket close
# endif

/* Setup common signal handling for the demos. */
static void setup_signals(void)
{
# ifndef _WIN32
    struct sigaction sig = {0};

    /* Use sigaction(2) and not signal(2) to avoid SA_RESTART and use EINTR. */
    sig.sa_handler = on_int;
    sigaction(SIGINT, &sig, NULL);
    signal(SIGPIPE, SIG_IGN);
# endif
}

static void log_vwarn(const char *fmt, va_list args, int use_errno, int use_ssl)
{
    fprintf(stderr, "%s: ", g_prog_name);
    vfprintf(stderr, fmt, args);
    if (use_errno) {
        fprintf(stderr, ": ");
#ifdef _WIN32
        if (use_errno > 1)
            fprintf(stderr, "socket error %d\n", WSAGetLastError());
        else
#endif
            perror(NULL);
    } else {
        fprintf(stderr, "\n");
    }

    if (use_ssl)
        ERR_print_errors_fp(stderr);
}

static void log_warn(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_vwarn(fmt, args, /*use_errno=*/0, /*use_ssl=*/0);
    va_end(args);
}

static void log_warn_errno(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_vwarn(fmt, args, /*use_errno=*/1, /*use_ssl=*/0);
    va_end(args);
}

static void log_warn_sock(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_vwarn(fmt, args, /*use_errno=*/2, /*use_ssl=*/0);
    va_end(args);
}

static void log_warn_ssl(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_vwarn(fmt, args, /*use_errno=*/0, /*use_ssl=*/1);
    va_end(args);
}

# ifdef USE_LIBUV

static void log_warn_uv(int rc, const char *fmt, ...)
{
    va_list args;
    char name[64], *name_p, msg[1024], *msg_p;

    va_start(args, fmt);
    log_vwarn(fmt, args, 0, 0);
    va_end(args);

    msg_p   = uv_strerror_r(rc, msg, sizeof(msg));
    name_p  = uv_err_name_r(rc, name, sizeof(name));

    log_warn("  due to libuv error %s(%d): %s", name_p, rc, msg_p);
}

# endif

/*
 * Parse arguments (chain, privkey, port). Allows a range of ports to be
 * requested for multiple listener demos.
 */
static int parse_args(int argc, char **argv, size_t num_ports)
{
    g_prog_name = argv[0];

    if (argc < 4) {
        log_warn("usage: %s <chain.pem> <privkey.pem> <listen-port>",
                 g_prog_name);
        return 0;
    }

    g_chain_fn      = argv[1];
    g_privkey_fn    = argv[2];

    errno = 0;
    g_port = strtoul(argv[3], NULL, 0);
    if (g_port == 0 || g_port > UINT16_MAX - (num_ports - 1) || errno != 0) {
        log_warn("port must be an integer in [1..%u]",
                 (unsigned int)(UINT16_MAX - (num_ports - 1)));
        return 0;
    }

    return 1;
}

static void cleanup_ssl_ctx(void)
{
    SSL_CTX_free(g_ssl_ctx);
    g_ssl_ctx = NULL;
}

static int create_ssl_ctx(void)
{
    int rc = 0;
    const SSL_METHOD *method;

#if defined(USE_QUIC)
    method = OSSL_QUIC_server_method();
#elif defined(USE_DTLS)
    method = DTLS_server_method();
#else
    method = TLS_server_method();
#endif

    if ((g_ssl_ctx = SSL_CTX_new(method)) == NULL) {
        log_warn("cannot allocate SSL context");
        goto err;
    }

    if (SSL_CTX_use_certificate_chain_file(g_ssl_ctx, g_chain_fn) <= 0) {
        log_warn("cannot load certificate chain file \"%s\"", g_chain_fn);
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx,
                                    g_privkey_fn, SSL_FILETYPE_PEM) <= 0) {
        log_warn("cannot load private key file \"%s\"", g_privkey_fn);
        goto err;
    }

    if (!SSL_CTX_check_private_key(g_ssl_ctx)) {
        log_warn("check of private key failed");
        goto err;
    }

    rc = 1;
err:
    if (rc == 0) {
        ERR_print_errors_fp(stderr);
        cleanup_ssl_ctx();
    }
    return rc;
}

/*
 * Print a useful diagnostic about an SSL I/O error where ret is the return
 * value of an SSL I/O function such as SSL_read or SSL_write.
 * Returns 1 if a clean EOF occurred, 0 for any other error.
 */
static int diagnose_ssl_io_error(SSL *s, int is_write, int ret)
{
    int err;
    const char *verb = is_write ? "write to" : "read from";

    switch (err = SSL_get_error(s, ret)) {
    case SSL_ERROR_ZERO_RETURN:
        if (is_write) {
            log_warn("unexpected EOF during write");
            break;
        }

        log_warn("EOF");
        return 1;
    case SSL_ERROR_SYSCALL:
        log_warn_errno("failed to %s SSL object due to system call failure (%d)",
                       verb, ret);
        break;
    default:
    case SSL_ERROR_SSL:
        log_warn("failed to %s SSL object due to SSL error (%d:%d)",
                 verb, ret, err);
        break;
    }

    return 0;
}

/*
 * Create an OS socket.
 */
static int create_socket(uint16_t port, int type, int reuseport)
{
    int ok = 0, fd = -1, rc;
    struct sockaddr_in6 sa = {0};
    static const int on = 1;

    if (port == 0) {
        log_warn("invalid port");
        goto err;
    }

#ifdef _WIN32
    /* Ensure Winsock is initialised. */
    uv_default_loop();
#endif

    if ((fd = socket(AF_INET6, type,
                     (type == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP)) < 0) {
        log_warn_sock("cannot create socket");
        goto err;
    }

    sa.sin6_family  = AF_INET6;
    sa.sin6_port    = htons(port);

    /* Casts here are for Win32 compat. */
    if ((rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                         (const void *)&on, sizeof(on))) < 0) {
        log_warn_sock("port %u: setsockopt[SO_REUSEADDR] failed", port);
        goto err;
    }

    if (reuseport) {
#ifdef SO_REUSEPORT
        if ((rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                             (const void *)&on, sizeof(on))) < 0) {
            log_warn_sock("port %u: setsockopt[SO_REUSEPORT] failed", port);
            goto err;
        }
#else
        log_warn_sock("port %u: setsockopt[SO_REUSEPORT] not supported", port);
        goto err;
#endif
    }

    if ((rc = bind(fd, (const struct sockaddr *)&sa, sizeof(sa))) < 0) {
        log_warn_sock("port %u: bind to [::]:%u failed", port, port);
        goto err;
    }

    ok = 1;
err:
    if (!ok && fd >= 0) {
        closesocket(fd);
        fd = -1;
    }

    return fd;
}

#endif
