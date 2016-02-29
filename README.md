# apns2-demo

* using APNs http2 new provider api

    [see more document](https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/APNsProviderAPI.html)



* requirements:

 nghttp2 (https://github.com/tatsuhiro-t/nghttp2)
 

* usage:
```
    make
    ./apns2-demo token certfile.pem msg
```    
    
* log:
```
[19:37:34] liym:apns2-demo git:(master*) $ make
gcc -o apns2-demo apns2-demo.c -Wall -I../nghttp2/lib/includes -L../nghttp2/lib/.libs -lnghttp2 -lssl -lcrypto

[19:40:33] liym:apns2-demo git:(master*) $ ./apns2-demo 

nghttp2 version: 1.9.0-DEV
tls/ssl version: TLSv1.2
ns looking up ...
connecting to : 17.172.234.15
socket connect ok: fd=3, host: api.push.apple.com:2197
ssl allocation ok
ssl handshaking ...
ssl handshake ok
tls/ssl connect ok: protocol= 
[INFO] Stream ID = 1
[INFO] C ----------------------------> S (HEADERS)
:method: POST
:path: /3/device/73f98e1833fa744403fb4447e0f3a054d43f433b80e48c5bcaa62b501fd0f956
apns-id: e77a3d12-bc9f-f410-a127-43f212597a9c
[INFO] C ----------------------------> S (DATA post body)
{"aps":{"alert":"nghttp2 test.","sound":"default"}}
[INFO] C <---------------------------- S (HEADERS begin)
:status: 200
apns-id: e77a3d12-bc9f-f410-a127-43f212597a9c
[INFO] C <---------------------------- S (HEADERS end)
[INFO] C ----------------------------> S (GOAWAY)
```