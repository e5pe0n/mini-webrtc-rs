use aes::Aes128;
use aes::cipher::BlockCipherEncrypt;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use anyhow::{Result, anyhow};
use common::decode_hex;

use crate::header::RtpHeader;
use crate::packet::RtpPacket;
use common::buffer::BufWriter;
use dtls::crypto::prf_p_hash;

pub struct SrtpEncryptionKeys {
    pub server_master_key: Vec<u8>,
    pub server_master_salt: Vec<u8>,
    pub client_master_key: Vec<u8>,
    pub client_master_salt: Vec<u8>,
}

pub struct SrtpGcm {
    srtp_gcm: Aes128Gcm,
    srtcp_gcm: Aes128Gcm,
    srtp_salt: Vec<u8>,
    srtcp_salt: Vec<u8>,
}

impl SrtpGcm {
    pub fn new(master_key: &[u8], master_salt: &[u8]) -> Self {
        let srtp_key = aes_cm_key_derivation(
            KeyDerivationLabel::SrtpEncryptionKey,
            master_key,
            master_salt,
        );
        let srtp_salt =
            aes_cm_key_derivation(KeyDerivationLabel::SrtpSaltingKey, master_key, master_salt);
        let srtcp_key = aes_cm_key_derivation(
            KeyDerivationLabel::SrtcpEncryptionKey,
            master_key,
            master_salt,
        );
        let srtcp_salt =
            aes_cm_key_derivation(KeyDerivationLabel::SrtcpSaltingKey, master_key, master_salt);

        Self {
            srtp_gcm: Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&srtp_key)),
            srtcp_gcm: Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&srtcp_key)),
            srtp_salt,
            srtcp_salt,
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc7714#section-8.1
    fn iv(&self, header: &RtpHeader, roc: u32) -> Vec<u8> {
        let mut writer = BufWriter::new();
        writer.write_u16(0);
        writer.write_u32(header.ssrc);
        writer.write_u32(roc);
        writer.write_u16(header.sequence_number);

        let mut iv = writer.buf();

        for (i, v) in iv.iter_mut().enumerate() {
            *v ^= self.srtp_salt[i];
        }

        iv
    }

    pub fn decrypt(&self, packet: RtpPacket, roc: u32) -> Result<RtpPacket> {
        // https://datatracker.ietf.org/doc/html/rfc3711#section-4.1.1
        let nonce = self.iv(&packet.header, roc);
        let decrypted_msg = self
            .srtp_gcm
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &packet.raw[packet.header_size..],
                    aad: &packet.raw[..packet.header_size],
                },
            )
            .map_err(|err| anyhow!("failed to decrypt srtp; {err}"))?;
        Ok(RtpPacket {
            header: packet.header,
            header_size: packet.header_size,
            payload: decrypted_msg,
            raw: packet.raw,
        })
    }
}

// https://datatracker.ietf.org/doc/html/rfc3711#section-4.3.1
enum KeyDerivationLabel {
    SrtpEncryptionKey = 0x00,
    SrtpSaltingKey = 0x02,
    SrtcpEncryptionKey = 0x03,
    SrtcpSaltingKey = 0x05,
}

fn aes_cm_key_derivation(
    label: KeyDerivationLabel,
    master_key: &[u8],
    master_salt: &[u8],
) -> Vec<u8> {
    // https://datatracker.ietf.org/doc/html/rfc3711#section-5.3
    // https://datatracker.ietf.org/doc/html/rfc3711#autoid-26
    // https://datatracker.ietf.org/doc/html/rfc3711#autoid-17
    // index DIV kdr:                 000000000000
    // label:                       00
    // master salt:   0EC675AD498AFEEBB6960B3AABE6
    // -----------------------------------------------
    // xor:           0EC675AD498AFEEBB6960B3AABE6     (x, PRF input)
    // x*2^16:        0EC675AD498AFEEBB6960B3AABE60000 (AES-CM input)
    let key_length = match label {
        KeyDerivationLabel::SrtpEncryptionKey => master_key.len(),
        KeyDerivationLabel::SrtpSaltingKey => master_salt.len(),
        KeyDerivationLabel::SrtcpEncryptionKey => master_key.len(),
        KeyDerivationLabel::SrtcpSaltingKey => master_salt.len(),
    };
    let mut x = vec![0u8; master_key.len()];
    x[0..master_salt.len()].copy_from_slice(master_salt);
    x[7] ^= label as u8;

    let block = <Aes128 as aes::cipher::KeyInit>::new_from_slice(master_key)
        .expect("AES-128 master key must be 16 bytes");

    let num_iters = key_length.div_ceil(master_key.len());
    let mut key = vec![0u8; num_iters * master_key.len()];
    for i in 0..num_iters {
        x[master_key.len() - 2..].copy_from_slice(&(i as u16).to_be_bytes());
        let ki: &mut aes::cipher::Block<Aes128> = (&mut key
            [i * master_key.len()..(i + 1) * master_key.len()])
            .try_into()
            .expect("derived AES block must be 16 bytes");
        ki.copy_from_slice(&x);
        block.encrypt_block(ki);
    }
    key.truncate(key_length);
    key
}

#[cfg(test)]
mod aes_cm_key_derivation_tests {
    use super::*;

    #[test]
    fn test_cipher_key() -> Result<()> {
        // https://datatracker.ietf.org/doc/html/rfc3711#appendix-B.3
        let master_key = decode_hex("E1F97A0D3E018BE0D64FA32C06DE4139")?;
        let master_salt = decode_hex("0EC675AD498AFEEBB6960B3AABE6")?;
        let expected_cipher_key = decode_hex("C61E7A93744F39EE10734AFE3FF7A087")?;
        let cipher_key = aes_cm_key_derivation(
            KeyDerivationLabel::SrtpEncryptionKey,
            &master_key,
            &master_salt,
        );
        assert_eq!(cipher_key, expected_cipher_key);
        Ok(())
    }

    #[test]
    fn test_salt() -> Result<()> {
        // https://datatracker.ietf.org/doc/html/rfc3711#appendix-B.3
        let master_key = decode_hex("E1F97A0D3E018BE0D64FA32C06DE4139")?;
        let master_salt = decode_hex("0EC675AD498AFEEBB6960B3AABE6")?;
        let expected_salt = decode_hex("30CBBC08863D8C85D49DB34A9AE1")?;
        let cipher_key = aes_cm_key_derivation(
            KeyDerivationLabel::SrtpSaltingKey,
            &master_key,
            &master_salt,
        );
        assert_eq!(cipher_key, expected_salt);
        Ok(())
    }
}

const PRF_DTLS_SRTP_EXPORTER_LABEL: &str = "EXTRACTOR-dtls_srtp";

// https://datatracker.ietf.org/doc/html/rfc5764#section-4.2
// https://datatracker.ietf.org/doc/html/rfc5705
pub fn generate_keying_material(
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    requested_bytes: usize,
) -> Vec<u8> {
    let seed = vec![
        PRF_DTLS_SRTP_EXPORTER_LABEL.as_bytes().to_vec(),
        client_random.to_vec(),
        server_random.to_vec(),
    ]
    .concat();
    prf_p_hash(master_secret, &seed, requested_bytes)
}
