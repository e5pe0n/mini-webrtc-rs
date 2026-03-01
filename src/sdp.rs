pub struct SdpMessage {
    pub session_id: String,
    pub media_items: Vec<SdpMedia>,
}

pub struct SdpMedia {
    pub media_id: u64,
    pub media_type: MediaType,
    pub ufrag: String,
    pub pwd: String,
    pub fingerprint_type: FingerprintType,
    pub fingerprint_hash: String,
    pub candidates: Vec<SdpMediaCandidate>,
    pub payloads: String,
    pub rtp_codec: String,
}

pub enum MediaType {
    Video,
    Audio,
}

pub enum FingerprintType {
    Sha256,
}

pub struct SdpMediaCandidate {
    pub ip: String,
    pub port: u64,
    pub candidate_type: CandidateType,
    pub transport_type: TransportType,
}

pub enum CandidateType {
    Host,
}

pub enum TransportType {
    Udp,
    Tcp,
}
