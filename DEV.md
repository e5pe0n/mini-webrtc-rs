create client secret key and X.509 certificate for local client

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes -keyout client.key -out client.crt -subj /CN=interop-client -days 365
```

encode X.509 certificate to DER

```sh
openssl x509 -in client.crt -outform DER -out client.der
```

connect dtls to local server running port 4433

```sh
openssl s_client -dtls1_2 -connect 127.0.0.1:4433 -cert client.crt -key client.key -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -use_srtp SRTP_AEAD_AES_128_GCM -timeout -brief -msg -state
```
