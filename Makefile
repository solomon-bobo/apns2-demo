# I use lastest nghttp2 dev-version for feature testing
# , you may change this location
INC=../nghttp2/lib/includes
LIB=../nghttp2/lib/.libs

.PHONY: all clean

all: apns2-demo.c
	gcc -o apns2-demo apns2-demo.c -Wall -Wextra -Wno-unused-parameter \
	-I$(INC) -L$(LIB) -lnghttp2 -lssl -lcrypto

clean:
	rm apns2-demo
