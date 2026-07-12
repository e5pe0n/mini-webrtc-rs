use tokio::sync::mpsc;

use crate::{common::error::MiniWebrtcRsError, sdp::MediaType, srtp::packet::RtpPacket};

#[derive(Debug, Clone)]
pub enum MediaStreamTrackKind {
    Audio,
    Video,
}

impl TryFrom<MediaType> for MediaStreamTrackKind {
    type Error = MiniWebrtcRsError;

    fn try_from(value: MediaType) -> Result<Self, MiniWebrtcRsError> {
        match value {
            MediaType::Audio => Ok(MediaStreamTrackKind::Audio),
            MediaType::Video => Ok(MediaStreamTrackKind::Video),
            _ => Err(MiniWebrtcRsError::InvalidEnumVariantError {
                enum_name: "MediaStreamTrackKind".to_string(),
                value: format!("{value:?}"),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MediaStreamTrackReadyState {
    Live,
    Ended,
}

#[derive(Debug)]
pub struct MediaStreamTrack {
    pub id: String,
    pub kind: MediaStreamTrackKind,
    pub label: String,
    pub ready_state: MediaStreamTrackReadyState,
    pub inbound_rtp_rx: mpsc::UnboundedReceiver<RtpPacket>,
}

impl MediaStreamTrack {
    pub async fn recv(&mut self) -> Option<RtpPacket> {
        self.inbound_rtp_rx.recv().await
    }
}
