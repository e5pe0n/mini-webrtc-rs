run local dtls server

```sh
watchexec -r -e rs,toml -- cargo run -p dtls
```

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

view decrypted SRTP as live video with GStreamer (VP8/PT=96)

```sh
brew install gstreamer gst-plugins-base gst-plugins-good gst-plugins-bad gst-libav
```

run viewer first (listens on UDP 5004)

```sh
gst-launch-1.0 -v udpsrc port=5004 caps="application/x-rtp,media=video,encoding-name=VP8,payload=96,clock-rate=90000" ! rtpjitterbuffer latency=50 drop-on-latency=true ! rtpvp8depay ! vp8dec ! videoconvert ! autovideosink sync=false
```

then run the Rust server and start media from browser app; decrypted RTP packets are forwarded to 127.0.0.1:5004 in SRTP manager.

disable forwarding toggle (optional)

```sh
MINI_WEBRTC_LIVE_RTP_FORWARD=0 cargo run -p mini-webrtc-rs
```
