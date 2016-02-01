#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <nghttp2/nghttp2.h>

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
    //"https://api.push.apple.com", 2197, "/3/device/", argv[1], argv[2]);
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

static bool
socket_connect(const struct uri_t *uri, struct connection_t *conn)
{
    return false;
}

static bool
ssl_connect(const struct uri_t *uri, struct connection_t *conn)
{
    return false;
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

static bool
sync_post(struct loop_t *loop, struct connection_t *conn, struct request_t req)
{
    return false;
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
        /* using product interface */
        uri = make_uri("https://api.push.apple.com", 2197, "/3/device/", argv[1], argv[2]);
    } else {
        usage();
        exit(0);
    }

    init_global_library();
    socket_connect(&uri, &conn);
    ssl_connect(&uri, &conn);
    sync_post(&loop, &conn, make_request(uri,argv[3]));

    return 0;
}
