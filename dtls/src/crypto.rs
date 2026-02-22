use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::SharedSecret;

use crate::handshake::random::Random;

type HmacSha256 = Hmac<Sha256>;

const PRF_MASTER_SECRET_LABEL: &str = "master secret";

fn hmac_sha(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// prf (pseudorandom function)
fn prf_p_hash(secret: &[u8], seed: &[u8], requested_bytes: usize) -> Vec<u8> {
    let mut last_round = seed.to_vec();
    let mut out: Vec<u8> = vec![];

    // key stretching
    let iterations = (requested_bytes as f64 / (256 / 8) as f64).ceil() as usize;
    for _ in 0..iterations {
        last_round = hmac_sha(secret, &last_round);
        let mut last_round_with_seed = last_round.clone();
        last_round_with_seed.extend_from_slice(seed);
        let with_secret = hmac_sha(secret, &last_round_with_seed);
        out.extend_from_slice(&with_secret);
    }

    out[..requested_bytes].to_vec()
}

// https://datatracker.ietf.org/doc/html/rfc5246#section-8.1
pub fn generate_master_secret(
    pre_master_secret: SharedSecret,
    client_random: &Random,
    server_random: &Random,
) -> Vec<u8> {
    let mut seed = PRF_MASTER_SECRET_LABEL.as_bytes().to_vec();
    seed.extend_from_slice(&client_random.to_bytes());
    seed.extend_from_slice(&server_random.to_bytes());
    prf_p_hash(pre_master_secret.as_bytes(), &seed, 48)
}
