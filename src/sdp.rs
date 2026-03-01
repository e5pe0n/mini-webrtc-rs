use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct SdpMessage {
    pub session_id: String,
    pub media_items: Vec<SdpMedia>,
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
pub enum MediaType {
    Video,
    Audio,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum FingerprintType {
    Sha256,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SdpMediaCandidate {
    pub ip: IpAddr,
    pub port: u64,
    pub candidate_type: CandidateType,
    pub transport_type: TransportType,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CandidateType {
    Host,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum TransportType {
    Udp,
    Tcp,
}
