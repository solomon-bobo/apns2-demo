#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <sys/epoll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <nghttp2/nghttp2.h>


enum {
    IO_NONE,
    WANT_READ,
    WANT_WRITE
};

struct connection_t {
    int steam_id;
    int fd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    nghttp2_session *session;
};

struct uri_t {
    const char *url;
    const char *prefix;
    const char *token;
    uint16_t port;
    const char *cert;
};

struct request_t {
    struct uri_t uri;
    uint8_t *data;
    size_t data_len;
};

struct loop_t {
    int epfd;
};

static void
die(const char *msg)
{
    fprintf(stderr, "FATAL: %s\n", msg);
    exit(EXIT_FAILURE);
}

static bool
file_exsit(const char *f)
{
    return 0 == access(f, 0) ? true : (printf("file not exsit:%s\n",f),false);
}

static bool
string_eq(const char *s1, const char *s2)
{
    return strcmp(s1,s2) == 0 ? true : false;
}

static bool
option_is_test(int argc, const char *arg1)
{
    if (argc == 2 && string_eq(arg1, "test")) {
        return true;
    } else {
        return false;
    }
}

static bool
option_is_regular(int argc, const char *token, const char *cert, const char *msg)
{
    if (argc == 4 && file_exsit(cert) && (msg!=NULL)) {
        return true;
    } else {
        return false;
    }
}

struct uri_t
make_uri(const char *url, uint16_t port, const char *prefix, const char *token ,const char *cert)
{
    struct uri_t uri;
    uri.url = url;
    uri.port = port;
    uri.prefix = prefix;
    uri.token = token;
    uri.cert = cert;
    return uri;
}

static void
init_global_library()
{
    SSL_library_init();
    SSL_load_error_strings();
}

static int
connect_to_url(const char *url, uint16_t port)
{
    int sockfd;
    int rv;
    struct addrinfo hints, *res, *ressave;
    char port_str[6];

    bzero(&hints, sizeof(struct addrinfo));
    bzero(port_str, sizeof(port_str));
    snprintf(port_str, 6, "%d", port);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    rv = getaddrinfo(url, port_str, &hints, &res);
    if (rv != 0) {
        freeaddrinfo(res);
        return -1;
    }

    ressave = res;
    do {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if(sockfd < 0) {
            continue;
        }
        while ((rv = connect(sockfd, res->ai_addr, res->ai_addrlen)) == -1 &&
                errno == EINTR)
            ;
        if (0 == rv) {
            freeaddrinfo(ressave);
            return sockfd;
        } else {
            close(sockfd);
        }
    } while ((res = res->ai_next) != NULL);

    freeaddrinfo(ressave);
    return -1; 
}

static bool
socket_connect(const struct uri_t *uri, struct connection_t *conn)
{
    int fd;
    fd = connect_to_url(uri->url,uri->port);
    if (fd > 0) {
        conn->fd = fd;
        printf("socket connect ok: fd=%d, host: %s:%d\n", conn->fd, uri->url, uri->port);
        return true;
    }
    die("socket connect fail.");
    return false;
}

static X509*
read_x509_certificate(const char* path)
{
    BIO  *bio = NULL;
    X509 *x509 = NULL;
    if (NULL == (bio = BIO_new_file(path, "r"))) {
        return NULL;
    }
    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return x509;
}

/*
 * Callback function for TLS NPN. Since this program only supports
 * HTTP/2 protocol, if server does not offer HTTP/2 the nghttp2
 * library supports, we terminate program.
 */
static int
select_next_proto_cb(SSL *ssl, unsigned char **out,
                     unsigned char *outlen, const unsigned char *in,
                     unsigned int inlen, void *arg)
{
    int rv;
  /* nghttp2_select_next_protocol() selects HTTP/2 protocol the
     nghttp2 library supports. */
    rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
    if (rv <= 0) {
        die("Server did not advertise HTTP/2 protocol");
    }
    return SSL_TLSEXT_ERR_OK;
}

static void
init_ssl_ctx(SSL_CTX *ssl_ctx)
{
  /* Disable SSLv2 and enable all workarounds for buggy servers */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  /* Set NPN callback */
    SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
}

static bool
ssl_allocate(struct connection_t *conn, const char *cert)
{
    int rv;
    X509 *x509 = NULL;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    if (NULL == (x509 = read_x509_certificate(cert))) {
        return false;
    }

    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL) {
        X509_free(x509);
    }
    init_ssl_ctx(ssl_ctx);
    
    rv = SSL_CTX_use_certificate(ssl_ctx, x509);
    X509_free(x509);
    if (rv != 1) {
        SSL_CTX_free(ssl_ctx);
        return false;
    }

    rv = SSL_CTX_use_PrivateKey_file(ssl_ctx, cert, SSL_FILETYPE_PEM);
    if (rv != 1) {
        SSL_CTX_free(ssl_ctx);
        return false;
    }  

    rv = SSL_CTX_check_private_key(ssl_ctx);
    if (rv != 1) {
        SSL_CTX_free(ssl_ctx);
        return false;
    }  

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ssl_ctx);
        return false;
    }    
    
    conn->ssl_ctx = ssl_ctx;
    conn->ssl = ssl;
    return true;
}

static bool
ssl_handshake(SSL *ssl, int fd)
{
    int rv;
    if (SSL_set_fd(ssl, fd) == 0) {
        return false;
    }
    ERR_clear_error();
    rv = SSL_connect(ssl);
    if (rv <= 0) {
        fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
        return false;
    }
    return true;
}

static bool
ssl_connect(const struct uri_t *uri, struct connection_t *conn)
{
    if (ssl_allocate(conn,uri->cert)) {
        fprintf(stdout, "ssl allocation ok\n");
    } else {
        fprintf(stderr, "ssl allocation error\n");
        return false;
    }

    if (ssl_handshake(conn->ssl, conn->fd)) {
        fprintf(stderr, "ssl handshake ok\n");
    } else {
        fprintf(stderr, "ssl handshake error\n");
        return false;
    }
    
    printf("tls/ssl connect ok: protocol= \n");
    return true;
}

// callback impelement
#define _U_
/*
 * The implementation of nghttp2_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * nghttp2_send_callback for the details.
 */
static ssize_t send_callback(nghttp2_session *session _U_, const uint8_t *data,
                             size_t length, int flags _U_, void *user_data) {
  int rv;
  return rv;
}

/*
 * The implementation of nghttp2_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of nghttp2_recv_callback for the details.
 */
static ssize_t recv_callback(nghttp2_session *session _U_, uint8_t *buf,
                             size_t length, int flags _U_, void *user_data) {
  int rv;
  return rv;
}

static int on_frame_send_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *user_data _U_) {
  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *user_data _U_) {
  return 0;
}

/*
 * The implementation of nghttp2_on_stream_close_callback type. We use
 * this function to know the response is fully received. Since we just
 * fetch 1 resource in this program, after reception of the response,
 * we submit GOAWAY and close the session.
 */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code _U_,
                                    void *user_data _U_) {
  return 0;
}

/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static int on_data_chunk_recv_callback(nghttp2_session *session,
                                       uint8_t flags _U_, int32_t stream_id,
                                       const uint8_t *data, size_t len,
                                       void *user_data _U_) {
  return 0;
}

/*
 * Setup callback functions. nghttp2 API offers many callback
 * functions, but most of them are optional. The send_callback is
 * always required. Since we use nghttp2_session_recv(), the
 * recv_callback is also required.
 */
static void
setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks)
{
  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
  nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
  nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);

}

static bool
set_nghttp2_session_info(struct connection_t *conn)
{
    int rv;
    nghttp2_session_callbacks *callbacks;

    rv = nghttp2_session_callbacks_new(&callbacks);
    if (rv != 0) {
        fprintf(stderr, "nghttp2_session_callbacks_new");
    }
    setup_nghttp2_callbacks(callbacks);
    rv = nghttp2_session_client_new(&conn->session, callbacks, conn);
    if (rv != 0) {
        fprintf(stderr, "nghttp2_session_client_new");
    }
    nghttp2_session_callbacks_del(callbacks);

    return true;
}

static struct request_t
make_request(struct uri_t uri, const char *msg)
{
    struct request_t req;
    req.uri = uri;
    req.data_len = strlen(msg);
    req.data = malloc(req.data_len);
    memcpy(req.data, msg, req.data_len);
    return req;
}

int set_nonblocking(int fd)
{
    int flags, rv;
    while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
        ;
    if (flags == -1) {
        return -1;
    }
    while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
        ;
    if (rv == -1) {
        return -1;
    }
    return 0;
}

int set_tcp_nodelay(int fd)
{
    int val = 1;
    if(-1 == setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val))) {
        return -1;
    }
    return 0;
}

static bool
blocking_post(struct loop_t *loop, struct connection_t *conn, struct request_t req)
{
    set_nonblocking(conn->fd);
    set_tcp_nodelay(conn->fd);

    return false;
}

static void
connection_cleanup(struct connection_t *conn)
{
    nghttp2_session_del(conn->session);
    SSL_shutdown(conn->ssl);
    SSL_free(conn->ssl);
    SSL_CTX_free(conn->ssl_ctx);
    shutdown(conn->fd, SHUT_WR);
    close(conn->fd); 
}

void
usage()
{
    printf("usage: apns2demo token cert message \n");
}

static void
test()
{
    printf("nghttp2 version: %s\n", NGHTTP2_VERSION);
    printf("tls/ssl version: %s\n", SSL_TXT_TLSV1_2);
}

int
main(int argc, const char *argv[])
{
    struct connection_t conn;
    struct uri_t uri;
    struct loop_t loop;

    if (option_is_test(argc,argv[1])) {
        test();
    } else if (option_is_regular(argc, argv[1], argv[2], argv[3])) {
        /* production */
        uri = make_uri("api.push.apple.com", 2197, "/3/device/", argv[1], argv[2]);
    } else {
        usage();
        exit(0);
    }

    init_global_library();
    
    socket_connect(&uri, &conn);
    ssl_connect(&uri, &conn);
    set_nghttp2_session_info(&conn);

    blocking_post(&loop, &conn, make_request(uri,argv[3]));

    //connection_cleanup(&conn);
    
    return 0;
}
