pub struct SdpMessage {
    pub session_id: String,
    pub media_items: Vec<SdpMedia>,
}

pub struct SdpMedia {
    pub media_id: i64,
    pub media_type: MediaType,
    pub u_frag: String,
    pub pwd: String,
    fingerprint_type: FingerprintType,
    candidates: Vec<SdpMediaCandidate>,
    payloads: String,
    prt_codec: String,
}

enum MediaType {
    Video,
    Audio,
}

enum FingerprintType {
    Sha256,
}

struct SdpMediaCandidate {
    pub ip: String,
    pub port: i64,
    pub candidate_type: CandidateType,
    pub transport_type: TransportType,
}

enum CandidateType {
    Host,
}

enum TransportType {
    Udp,
    Tcp,
}
