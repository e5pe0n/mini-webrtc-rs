use std::env;

use anyhow::Result;
use mini_webrtc_rs::{
    media_stream_track::MediaStreamTrack,
    peer_connection::PeerConnection,
    rtc_event::{RtcEvent, RtcTrackEvent},
};
use tokio::{net::UdpSocket, select};
use tracing::{info, warn};

// GStreamer viewer listens for VP8/PT=96 RTP on this address (see DEV.md).
const GSTREAMER_RTP_ADDR: &str = "127.0.0.1:5004";
const LIVE_RTP_FORWARD_ENABLED_ENV: &str = "MINI_WEBRTC_LIVE_RTP_FORWARD";

#[tokio::main]
async fn main() -> Result<()> {
    let mut pc = PeerConnection::new().await?;
    let mut dc = pc.create_data_channel().await?;

    loop {
        select! {
            rtc_event = pc.recv() => {
                match rtc_event {
                    Some(RtcEvent::RtcTrack(RtcTrackEvent { track })) => {
                        tokio::spawn(pipe_media_to_gstreamer(track));
                    }
                    None => break,
                }
            }
            dc_event = dc.recv() => {
                if let Some(event) = dc_event {
                    info!("data channel event: {event:?}");
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    pc.close();
    Ok(())
}

/// Forwards decrypted RTP packets from a media track to a local GStreamer
/// viewer over UDP (see DEV.md for the matching `gst-launch-1.0` pipeline).
async fn pipe_media_to_gstreamer(mut track: MediaStreamTrack) {
    if !is_live_rtp_forward_enabled() {
        info!("live RTP forwarding to GStreamer disabled by env {LIVE_RTP_FORWARD_ENABLED_ENV}");
        // Drain the track so decrypted packets are not buffered indefinitely.
        while track.recv().await.is_some() {}
        return;
    }

    let socket = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(socket) => socket,
        Err(err) => {
            warn!("failed to bind local RTP forwarding socket for GStreamer: {err}");
            return;
        }
    };
    info!(
        "forwarding decrypted RTP packets for track {} to GStreamer at {GSTREAMER_RTP_ADDR}",
        track.id
    );

    let mut forwarded: u64 = 0;
    while let Some(packet) = track.recv().await {
        // `packet.raw` is still the encrypted bytes; `to_bytes()` rebuilds the
        // plaintext RTP (header + decrypted payload) for the media sink.
        if let Err(err) = socket.send_to(&packet.to_bytes(), GSTREAMER_RTP_ADDR).await {
            warn!("failed to forward RTP packet to GStreamer: {err}");
            continue;
        }

        forwarded += 1;
        if forwarded == 1 {
            info!(
                "forwarded first RTP packet to GStreamer (pt={:?}, ssrc=0x{:08x})",
                packet.header.payload_type, packet.header.ssrc
            );
        }
    }
}

fn is_live_rtp_forward_enabled() -> bool {
    match env::var(LIVE_RTP_FORWARD_ENABLED_ENV) {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}
