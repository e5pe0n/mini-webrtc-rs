use rand::Rng;

use crate::sdp::SdpMessage;

pub struct IceCandidate {
    pub ip: String,
    pub port: u64,
}

pub struct IceAgent {
    pub ice_candidates: Vec<IceCandidate>,
    pub u_frag: String,
    pub pwd: String,
    pub fingerprint_hash: String,
}

impl IceAgent {
    pub fn new(ice_candidates: Vec<IceCandidate>, fingerprint_hash: &str) -> Self {
        let mut rng = rand::rng();
        let u_frag: String = {
            let u_frag: String = (0..13)
                .map(|_| rng.sample(rand::distr::Alphabetic).to_string())
                .collect();
            u_frag + "mwr"
        };

        Self {
            ice_candidates,
            u_frag,
            pwd: (0..32)
                .map(|_| rng.sample(rand::distr::Alphabetic).to_string())
                .collect(),
            fingerprint_hash: fingerprint_hash.to_string(),
        }
    }

    pub fn generate_sdp_offer() -> SdpMessage {
        // TODO
    }
}
