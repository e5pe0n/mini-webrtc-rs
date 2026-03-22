use aes_gcm::{Aes128Gcm, Key, KeyInit};
use hmac::{
    Hmac, Mac,
    digest::{consts::U32, generic_array::GenericArray},
};
use sha2::Sha256;
use x25519_dalek::SharedSecret;

use crate::dtls::handshake::random::Random;

type HmacSha256 = Hmac<Sha256>;

const PRF_EXTENDED_MASTER_SECRET_LABEL: &str = "extended master secret";
const PRF_MASTER_SECRET_LABEL: &str = "master secret";
const PRF_KEY_EXPANSION_LABEL: &str = "key expansion";

pub fn hmac_sha(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
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

// https://datatracker.ietf.org/doc/html/rfc7627#autoid-4
pub fn generate_extended_master_secret(
    pre_master_secret: SharedSecret,
    handshake_hash: GenericArray<u8, U32>,
) -> Vec<u8> {
    let seed = vec![
        PRF_EXTENDED_MASTER_SECRET_LABEL.as_bytes().to_vec(),
        handshake_hash.to_vec(),
    ]
    .concat();
    prf_p_hash(pre_master_secret.as_bytes(), &seed, 48)
}

// https://datatracker.ietf.org/doc/html/rfc5246#section-8.1
pub fn generate_master_secret(
    pre_master_secret: SharedSecret,
    client_random: &Random,
    server_random: &Random,
) -> Vec<u8> {
    let seed = vec![
        PRF_MASTER_SECRET_LABEL.as_bytes().to_vec(),
        client_random.to_bytes().to_vec(),
        server_random.to_bytes().to_vec(),
    ]
    .concat();
    prf_p_hash(pre_master_secret.as_bytes(), &seed, 48)
}

pub struct EncryptionKes {
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

// https://datatracker.ietf.org/doc/html/rfc5289#section-3.2
// https://datatracker.ietf.org/doc/html/rfc5288#section-3
// https://datatracker.ietf.org/doc/html/rfc5116
pub fn generate_encryption_keys(
    master_secret: &[u8],
    client_random: &Random,
    server_random: &Random,
) -> EncryptionKes {
    let mut seed = PRF_KEY_EXPANSION_LABEL.as_bytes().to_vec();
    seed.extend_from_slice(&server_random.to_bytes());
    seed.extend_from_slice(&client_random.to_bytes());

    let prf_key_len = 16;
    let prf_iv_len = 4;

    let key_material = prf_p_hash(master_secret, &seed, 2 * prf_key_len + 2 * prf_iv_len);

    EncryptionKes {
        client_write_key: key_material[..prf_key_len].to_vec(),
        server_write_key: key_material[prf_key_len..prf_key_len * 2].to_vec(),
        client_write_iv: key_material[prf_key_len * 2..prf_key_len * 3].to_vec(),
        server_write_iv: key_material[prf_key_len * 3..prf_key_len * 4].to_vec(),
    }
}

pub struct Gcm {
    local_gcm: Aes128Gcm,
    remote_gcm: Aes128Gcm,
    local_write_iv: Vec<u8>,
    remote_write_iv: Vec<u8>,
}

impl Gcm {
    pub fn new(
        local_key: &[u8],
        local_write_iv: &[u8],
        remote_key: &[u8],
        remote_write_iv: &[u8],
    ) -> Self {
        Self {
            local_gcm: Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(local_key)),
            remote_gcm: Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(remote_key)),
            local_write_iv: local_write_iv.to_vec(),
            remote_write_iv: remote_write_iv.to_vec(),
        }
    }
}
