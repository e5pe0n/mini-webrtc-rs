use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SdpMessage {
    pub session_id: String,
    pub medias: Vec<SdpMedia>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SdpMedia {
    pub media_id: String,
    pub media_type: MediaType,
    pub direction: MediaDirection,
    pub ufrag: String,
    pub pwd: String,
    pub fingerprint_type: FingerprintType,
    pub fingerprint_hash: String,
    pub candidates: Vec<SdpMediaCandidate>,
    pub payloads: String,
    pub rtp: Vec<Rtp>,

    pub rtcp_mux: Option<String>,
    pub protocol: String,

    pub sctp_port: Option<u64>,
    pub max_message_size: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaType {
    Video,
    Audio,
    Application,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaDirection {
    Sendrecv,
    Sendonly,
    Recvonly,
    Inactive,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FingerprintType {
    #[serde(rename = "sha-256")]
    Sha256,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SdpMediaCandidate {
    pub ip: IpAddr,
    pub port: u64,
    pub candidate_type: CandidateType,
    pub transport_type: TransportType,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CandidateType {
    Host,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Udp,
    Tcp,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub struct Rtp {
    pub payload: u32,
    pub codec: String,
    pub rate: u32,
}
