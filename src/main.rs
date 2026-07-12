use std::env;

use anyhow::Result;
use mini_webrtc_rs::{media_track::MediaTrackStream, peer_connection::PeerConnection};
use tokio::net::UdpSocket;
use tracing::{info, warn};

// GStreamer viewer listens for VP8/PT=96 RTP on this address (see DEV.md).
const GSTREAMER_RTP_ADDR: &str = "127.0.0.1:5004";
const LIVE_RTP_FORWARD_ENABLED_ENV: &str = "MINI_WEBRTC_LIVE_RTP_FORWARD";

#[tokio::main]
async fn main() -> Result<()> {
    let pc = PeerConnection::new().await?;
    let mut dc = pc.create_data_channel().await?;
    let media_track = pc.create_media_track_stream().await?;

    tokio::spawn(async move {
        loop {
            if let Some(event) = dc.recv().await {
                info!("data channel event: {event:?}");
            }
        }
    });

    tokio::spawn(pipe_media_to_gstreamer(media_track));

    tokio::signal::ctrl_c().await?;
    pc.close();
    Ok(())
}

/// Forwards decrypted RTP packets from the media track to a local GStreamer
/// viewer over UDP (see DEV.md for the matching `gst-launch-1.0` pipeline).
async fn pipe_media_to_gstreamer(mut media_track: MediaTrackStream) {
    if !is_live_rtp_forward_enabled() {
        info!("live RTP forwarding to GStreamer disabled by env {LIVE_RTP_FORWARD_ENABLED_ENV}");
        // Drain the track so decrypted packets are not buffered indefinitely.
        while media_track.recv().await.is_some() {}
        return;
    }

    let socket = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(socket) => socket,
        Err(err) => {
            warn!("failed to bind local RTP forwarding socket for GStreamer: {err}");
            return;
        }
    };
    info!("forwarding decrypted RTP packets to GStreamer at {GSTREAMER_RTP_ADDR}");

    let mut forwarded: u64 = 0;
    while let Some(packet) = media_track.recv().await {
        if let Err(err) = socket.send_to(&packet.rtp, GSTREAMER_RTP_ADDR).await {
            warn!("failed to forward RTP packet to GStreamer: {err}");
            continue;
        }

        forwarded += 1;
        if forwarded == 1 {
            info!(
                "forwarded first RTP packet to GStreamer (pt={}, ssrc=0x{:08x})",
                packet.payload_type, packet.ssrc
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
