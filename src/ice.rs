use crate::{dtls::Fingerprint, sdp::Rtp};
use rand::RngExt;
use std::net::IpAddr;

use crate::sdp::{
    CandidateType, FingerprintType, MediaDirection, MediaType, SdpMedia, SdpMediaCandidate,
    SdpMessage, TransportType,
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
    pub remote_peers: Vec<Peer>,
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
            remote_peers: vec![],
        }
    }

    pub fn generate_sdp_offer(&self) -> SdpMessage {
        SdpMessage {
            session_id: "123456789".to_string(),
            medias: vec![
                SdpMedia {
                    media_id: "0".to_string(),
                    media_type: MediaType::Video,
                    direction: MediaDirection::Recvonly,
                    payloads: "96".to_string(), // VP8
                    rtp: vec![Rtp {
                        payload: 96,
                        codec: "VP8".to_string(),
                        rate: 90000,
                    }],
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
                    rtcp_mux: Some("rtcp-mux".to_string()),
                    protocol: "UDP/TLS/RTP/SAVPF".to_string(),
                    sctp_port: None,
                    max_message_size: None,
                },
                SdpMedia {
                    media_id: "1".to_string(),
                    media_type: MediaType::Application,
                    direction: MediaDirection::Recvonly,
                    payloads: "webrtc-datachannel".to_string(),
                    rtp: vec![],
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
                    rtcp_mux: None,
                    protocol: "UDP/DTLS/SCTP".to_string(),
                    sctp_port: Some(4433),
                    max_message_size: None,
                },
            ],
        }
    }
}
