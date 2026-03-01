use rand::Rng;

use crate::sdp::{
    CandidateType, FingerprintType, MediaType, SdpMedia, SdpMediaCandidate, SdpMessage,
    TransportType,
};

pub struct IceCandidate {
    pub ip: String,
    pub port: u64,
}

pub struct IceAgent {
    pub ice_candidates: Vec<IceCandidate>,
    pub ufrag: String,
    pub pwd: String,
    pub fingerprint_hash: String,
}

impl IceAgent {
    pub fn new(ice_candidates: Vec<IceCandidate>, fingerprint_hash: &str) -> Self {
        let mut rng = rand::rng();
        let ufrag: String = {
            let u_frag: String = (0..13)
                .map(|_| rng.sample(rand::distr::Alphabetic).to_string())
                .collect();
            u_frag + "mini"
        };

        Self {
            ice_candidates,
            ufrag,
            pwd: (0..32)
                .map(|_| rng.sample(rand::distr::Alphabetic).to_string())
                .collect(),
            fingerprint_hash: fingerprint_hash.to_string(),
        }
    }

    pub fn generate_sdp_offer(&self) -> SdpMessage {
        SdpMessage {
            session_id: "123456789".to_string(),
            media_items: vec![SdpMedia {
                media_id: 0,
                media_type: MediaType::Video,
                payloads: "96".to_string(), // VP8
                rtp_codec: "VP8/90000".to_string(),
                ufrag: self.ufrag.clone(),
                pwd: self.pwd.clone(),
                fingerprint_type: FingerprintType::Sha256,
                fingerprint_hash: self.fingerprint_hash.clone(),
                candidates: self
                    .ice_candidates
                    .iter()
                    .map(
                        (|c| SdpMediaCandidate {
                            ip: c.ip.clone(),
                            port: c.port,
                            candidate_type: CandidateType::Host,
                            transport_type: TransportType::Udp,
                        }),
                    )
                    .collect(),
            }],
        }
    }
}
