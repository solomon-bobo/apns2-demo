#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>


#include <nghttp2/nghttp2.h>

int main(int argc, char *argv[])
{
    printf("%s\n",NGHTTP2_VERSION);

    return 0;
}
