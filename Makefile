INC=../nghttp2/lib/includes
LIB=../nghttp2/lib/.libs

.PHONY: all clean

all: apns2-demo.c
	gcc -o apns2-demo -Wall apns2-demo.c -I$(INC) -L$(LIB)

clean:
	rm apns2-demo
