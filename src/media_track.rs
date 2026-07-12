use tokio::sync::mpsc;

/// A single decrypted RTP media packet delivered to the application layer.
#[derive(Debug, Clone)]
pub struct MediaPacket {
    pub ssrc: u32,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub marker: bool,
    /// Decrypted RTP bytes (header + payload, padding stripped), ready to be
    /// forwarded to a media sink such as GStreamer.
    pub rtp: Vec<u8>,
}

/// Receiving end of an inbound media track. Decrypted RTP packets produced by
/// the SRTP manager are delivered here so the application can consume them
/// (e.g. forward them to GStreamer for playback).
pub struct MediaTrackStream {
    inbound_rtp_rx: mpsc::UnboundedReceiver<MediaPacket>,
}

impl MediaTrackStream {
    pub fn new(inbound_rtp_rx: mpsc::UnboundedReceiver<MediaPacket>) -> Self {
        Self { inbound_rtp_rx }
    }

    /// Awaits the next decrypted media packet. Returns `None` once the sending
    /// side (the SRTP manager) has been dropped.
    pub async fn recv(&mut self) -> Option<MediaPacket> {
        self.inbound_rtp_rx.recv().await
    }
}
