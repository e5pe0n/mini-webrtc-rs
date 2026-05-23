use aes_gcm::{AeadInPlace, Aes128Gcm, Key, KeyInit, Nonce};
use anyhow::{Result, anyhow};
use hmac::digest::array::Array;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac, digest::consts::U32};
use sha2::Sha256;
use x25519_dalek::SharedSecret;

use crate::dtls::handshake::random::Random;
use crate::dtls::record_header::RecordHeader;
use rand::Rng;

type HmacSha256 = Hmac<Sha256>;

const PRF_EXTENDED_MASTER_SECRET_LABEL: &str = "extended master secret";
const PRF_MASTER_SECRET_LABEL: &str = "master secret";
const PRF_KEY_EXPANSION_LABEL: &str = "key expansion";
const PRF_CLIENT_FINISHED_LABEL: &str = "client finished";

pub fn hmac_sha(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// prf (pseudorandom function)
pub fn prf_p_hash(secret: &[u8], seed: &[u8], requested_bytes: usize) -> Vec<u8> {
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
    handshake_hash: Array<u8, U32>,
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

pub struct Aes128GcmEncryptionKeys {
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

// https://datatracker.ietf.org/doc/html/rfc5289#section-3.2
// https://datatracker.ietf.org/doc/html/rfc5288#section-3
// https://datatracker.ietf.org/doc/html/rfc5116
impl Aes128GcmEncryptionKeys {
    pub fn new(master_secret: &[u8], client_random: &Random, server_random: &Random) -> Self {
        let mut seed = PRF_KEY_EXPANSION_LABEL.as_bytes().to_vec();
        seed.extend_from_slice(&server_random.to_bytes());
        seed.extend_from_slice(&client_random.to_bytes());

        let prf_key_len = 16;
        let prf_iv_len = 4;

        let key_material = prf_p_hash(master_secret, &seed, 2 * prf_key_len + 2 * prf_iv_len);

        Aes128GcmEncryptionKeys {
            client_write_key: key_material[..prf_key_len].to_vec(),
            server_write_key: key_material[prf_key_len..prf_key_len * 2].to_vec(),
            client_write_iv: key_material[prf_key_len * 2..prf_key_len * 2 + prf_iv_len].to_vec(),
            server_write_iv: key_material
                [prf_key_len * 2 + prf_iv_len..prf_key_len * 2 + prf_iv_len * 2]
                .to_vec(),
        }
    }
}

const GCM_NONCE_LENGTH: usize = 12;
const GCM_EXPLICIT_NONCE_LENGTH: usize = 8;
const GCM_TAG_LENGTH: usize = 16;

#[derive(Clone)]
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

    pub fn encrypt(&self, record_header: RecordHeader, payload: Vec<u8>) -> Result<Vec<u8>> {
        // https://datatracker.ietf.org/doc/html/rfc5288#section-3
        let implicit_nonce = self.local_write_iv[..4].to_vec();
        let explicit_nonce = {
            let mut explicit_nonce = vec![0u8; GCM_NONCE_LENGTH - implicit_nonce.len()];
            let mut rng = rand::rng();
            rng.fill_bytes(&mut explicit_nonce);
            explicit_nonce
        };
        let nonce = vec![implicit_nonce, explicit_nonce.clone()].concat();

        let additional_data = {
            // https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.3
            let mut additional_data = vec![0u8; 13];

            additional_data[..8].copy_from_slice(&record_header.sequence_number.to_be_bytes()); // 48bit
            additional_data[..2].copy_from_slice(&record_header.epoch.to_be_bytes());

            additional_data[8] = record_header.content_type as u8;
            let version: u16 = record_header.version.into();
            additional_data[9..11].copy_from_slice(&version.to_be_bytes());
            additional_data[11..].copy_from_slice(&(record_header.length).to_be_bytes());

            additional_data
        };

        let mut encrypted_payload = payload;
        self.local_gcm
            .encrypt_in_place(
                Nonce::from_slice(&nonce),
                &additional_data,
                &mut encrypted_payload,
            )
            .map_err(|err| anyhow!("failed to encrypt payload: {err:?}"))?;
        // https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.3
        let encrypted_record = vec![explicit_nonce, encrypted_payload].concat();

        Ok(encrypted_record)
    }

    pub fn decrypt(&self, record_header: RecordHeader, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < GCM_EXPLICIT_NONCE_LENGTH + GCM_TAG_LENGTH {
            anyhow::bail!(
                "encrypted payload too short; expected at least {} bytes, got {}",
                GCM_EXPLICIT_NONCE_LENGTH + GCM_TAG_LENGTH,
                payload.len()
            );
        }

        let implicit_nonce = self.remote_write_iv[..4].to_vec();
        let explicit_nonce = payload[..GCM_EXPLICIT_NONCE_LENGTH].to_vec();
        let nonce = vec![implicit_nonce, explicit_nonce].concat();
        let plaintext_len = payload.len() - GCM_EXPLICIT_NONCE_LENGTH - GCM_TAG_LENGTH;

        let additional_data = {
            // https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.3
            let mut additional_data = vec![0u8; 13];

            additional_data[..8].copy_from_slice(&record_header.sequence_number.to_be_bytes()); // 48bit
            additional_data[..2].copy_from_slice(&record_header.epoch.to_be_bytes());

            additional_data[8] = record_header.content_type as u8;
            let version: u16 = record_header.version.into();
            additional_data[9..11].copy_from_slice(&version.to_be_bytes());
            additional_data[11..].copy_from_slice(&(plaintext_len as u16).to_be_bytes());

            additional_data
        };

        let mut decrypted_payload = payload[GCM_EXPLICIT_NONCE_LENGTH..].to_vec();
        self.remote_gcm
            .decrypt_in_place(
                Nonce::from_slice(&nonce),
                &additional_data,
                &mut decrypted_payload,
            )
            .map_err(|err| anyhow!("failed to decrypt dtls message; {err:?}"))?;

        Ok(decrypted_payload)
    }
}

// https://datatracker.ietf.org/doc/html/rfc5246#autoid-49
pub fn generate_verify_data(master_secret: &[u8], handshake_messages_hash: &[u8]) -> Vec<u8> {
    prf_p_hash(
        master_secret,
        &vec![
            PRF_CLIENT_FINISHED_LABEL.as_bytes().to_vec(),
            handshake_messages_hash.to_vec(),
        ]
        .concat(),
        12,
    )
}
