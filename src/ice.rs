use std::net::IpAddr;

use rand::Rng;

use crate::{
    dtls::common::Fingerprint,
    sdp::{
        CandidateType, FingerprintType, MediaType, SdpMedia, SdpMediaCandidate, SdpMessage,
        TransportType,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct IceCandidate {
    pub ip: IpAddr,
    pub port: u64,
}

#[derive(Debug, Clone)]
pub struct RemotePeer {
    pub ufrag: String,
    pub pwd: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct IceAgent {
    pub ice_candidates: Vec<IceCandidate>,
    pub local_ufrag: String,
    pub local_pwd: String,
    pub remote_ufrag: Option<String>,
    pub remote_pwd: Option<String>,
    pub fingerprint: Fingerprint,
    pub remote_peers: Vec<RemotePeer>,
}

impl IceAgent {
    pub fn new(ice_candidates: Vec<IceCandidate>, fingerprint: Fingerprint) -> Self {
        let mut rng = rand::rng();
        let local_ufrag: String = {
            let u_frag: String = (0..13)
                .map(|_| rng.sample(rand::distr::Alphabetic).to_string())
                .collect();
            u_frag + "mini"
        };

        Self {
            ice_candidates,
            local_ufrag,
            local_pwd: (0..32)
                .map(|_| rng.sample(rand::distr::Alphabetic).to_string())
                .collect(),
            remote_ufrag: None,
            remote_pwd: None,
            fingerprint,
            remote_peers: vec![],
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
                ufrag: self.local_ufrag.clone(),
                pwd: self.local_pwd.clone(),
                fingerprint_type: FingerprintType::Sha256,
                fingerprint_hash: self.fingerprint.to_string(),
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

    pub fn add_remote_peers(&mut self, remote_peers: Vec<RemotePeer>) {
        self.remote_peers.extend_from_slice(&remote_peers);
    }
}
