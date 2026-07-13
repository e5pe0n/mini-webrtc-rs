pub enum RtcSctpTransportState {
    Connecting,
    Connected,
    Closed,
}

pub struct RtcSctpTransport {
    pub state: RtcSctpTransportState,
}

impl RtcSctpTransport {
    pub fn new() -> Self {
        Self {
            state: RtcSctpTransportState::Connecting,
        }
    }
}
