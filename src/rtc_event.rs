use crate::media_stream_track::MediaStreamTrack;

pub enum RtcEvent {
    RtcTrack(RtcTrackEvent),
}

pub struct RtcTrackEvent {
    pub track: MediaStreamTrack,
}
