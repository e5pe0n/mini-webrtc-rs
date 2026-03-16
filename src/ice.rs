use std::net::IpAddr;

use rand::Rng;

use crate::{
    dtls::common::Fingerprint,
    sdp::{
        CandidateType, FingerprintType, MediaType, SdpMedia, SdpMediaCandidate, SdpMessage,
        TransportType,
    },
};

pub fn generate_ice_ufrag() -> String {
    let mut rng = rand::rng();
    let u_frag: String = (0..13)
        .map(|_| rng.sample(rand::distr::Alphabetic).to_string())
        .collect();
    u_frag + "mini"
}

pub fn generate_ice_pwd() -> String {
    let mut rng = rand::rng();
    (0..32)
        .map(|_| rng.sample(rand::distr::Alphabetic).to_string())
        .collect()
}

#[derive(Debug, Clone, Copy)]
pub struct IceCandidate {
    pub ip: IpAddr,
    pub port: u64,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub ufrag: String,
    pub pwd: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct IceAgent {
    pub ice_candidates: Vec<IceCandidate>,
    pub local_peer: Peer,
    pub remote_peer: Option<Peer>,
}

impl IceAgent {
    pub fn new(ice_candidates: Vec<IceCandidate>, fingerprint: Fingerprint) -> Self {
        Self {
            ice_candidates,
            local_peer: Peer {
                ufrag: generate_ice_ufrag(),
                pwd: generate_ice_pwd(),
                fingerprint: fingerprint.to_string(),
            },
            remote_peer: None,
        }
    }

    pub fn generate_sdp_offer(&self) -> SdpMessage {
        SdpMessage {
            session_id: "123456789".to_string(),
            medias: vec![SdpMedia {
                media_id: "0".to_string(),
                media_type: MediaType::Video,
                payloads: "96".to_string(), // VP8
                rtp_codec: "VP8/90000".to_string(),
                ufrag: self.local_peer.ufrag.clone(),
                pwd: self.local_peer.pwd.clone(),
                fingerprint_type: FingerprintType::Sha256,
                fingerprint_hash: self.local_peer.fingerprint.clone(),
                candidates: self
                    .ice_candidates
                    .iter()
                    .map(|c| SdpMediaCandidate {
                        ip: c.ip.clone(),
                        port: c.port,
                        candidate_type: CandidateType::Host,
                        transport_type: TransportType::Udp,
                    })
                    .collect(),
            }],
        }
    }
}
