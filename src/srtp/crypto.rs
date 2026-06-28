use aes::Aes128;
use aes::cipher::BlockCipherEncrypt;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use anyhow::{Result, anyhow};

use crate::common::buffer::BufWriter;
use crate::dtls::crypto::prf_p_hash;
use crate::srtp::header::RtpHeader;
use crate::srtp::packet::RtpPacket;

pub struct SrtpEncryptionKeys {
    pub server_master_key: Vec<u8>,
    pub server_master_salt: Vec<u8>,
    pub client_master_key: Vec<u8>,
    pub client_master_salt: Vec<u8>,
}

#[derive(Clone)]
#[allow(dead_code)]
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
    use crate::common::buffer::BufReader;
    use crate::common::decode_hex;
    use crate::srtp::is_rtp_packet;
    use etherparse::{PacketHeaders, TransportHeader};
    use pcap_file::DataLink;
    use pcap_file::pcap::PcapReader;
    use std::io::Cursor;

    const SRTP_MASTER_KEY_LEN: usize = 16;
    const LAB_PLAIN_CAPTURE_PCAP: &[u8] =
        include_bytes!("../../lab/captured_srtp_gcm128_plain.pcap");
    const LAB_ENCRYPTED_CAPTURE_PCAP: &[u8] =
        include_bytes!("../../lab/captured_srtp_gcm128_encrypted.pcap");
    const LAB_SRTP_EXPORTER_HEX: &str = include_str!("../../lab/srtp_test_keys.txt");

    fn parse_udp_payloads_from_raw_ipv4_pcap(pcap: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut reader = PcapReader::new(Cursor::new(pcap))
            .map_err(|err| anyhow!("failed to parse pcap header; {err}"))?;
        if reader.header().datalink != DataLink::RAW && reader.header().datalink != DataLink::IPV4 {
            anyhow::bail!(
                "expected DLT_RAW(228) or DLT_IPV4(228), found {:?}",
                reader.header().datalink
            )
        }

        let mut payloads = vec![];
        while let Some(packet) = reader.next_packet() {
            let packet = packet.map_err(|err| anyhow!("failed to read pcap packet; {err}"))?;
            let headers = match PacketHeaders::from_ip_slice(&packet.data) {
                Ok(h) => h,
                Err(_) => continue,
            };

            if headers.net.is_none() {
                continue;
            }

            let Some(TransportHeader::Udp(_)) = headers.transport else {
                continue;
            };

            payloads.push(headers.payload.slice().to_vec());
        }

        Ok(payloads)
    }

    fn split_lab_exporter_material() -> Result<SrtpEncryptionKeys> {
        let keying_material = decode_hex(LAB_SRTP_EXPORTER_HEX.trim())?;
        if keying_material.len() % 2 != 0 {
            anyhow::bail!("keying material length must be even")
        }

        let per_side_len = keying_material.len() / 2;
        if per_side_len <= SRTP_MASTER_KEY_LEN {
            anyhow::bail!("keying material per side too small: {per_side_len}")
        }

        let salt_len = per_side_len - SRTP_MASTER_KEY_LEN;
        let client_master_key = keying_material[0..SRTP_MASTER_KEY_LEN].to_vec();
        let server_master_key =
            keying_material[SRTP_MASTER_KEY_LEN..2 * SRTP_MASTER_KEY_LEN].to_vec();
        let salts_start = 2 * SRTP_MASTER_KEY_LEN;
        let client_master_salt = keying_material[salts_start..salts_start + salt_len].to_vec();
        let server_master_salt =
            keying_material[salts_start + salt_len..salts_start + 2 * salt_len].to_vec();

        Ok(SrtpEncryptionKeys {
            server_master_key,
            server_master_salt,
            client_master_key,
            client_master_salt,
        })
    }

    fn first_rtp_payload_from_pcap(pcap: &[u8]) -> Result<Vec<u8>> {
        let payloads = parse_udp_payloads_from_raw_ipv4_pcap(pcap)?;
        payloads
            .into_iter()
            .find(|p| p.len() >= 12 && is_rtp_packet(p))
            .ok_or_else(|| anyhow!("pcap contains no RTP packets"))
    }

    fn decode_rtp_packet(raw_payload: &[u8]) -> Result<RtpPacket> {
        let mut reader = BufReader::new(raw_payload);
        RtpPacket::decode(&mut reader)
    }

    fn decrypt_with_direction(
        encrypted_raw_payload: &[u8],
        master_key: &[u8],
        master_salt: &[u8],
        roc: u32,
    ) -> Result<RtpPacket> {
        let encrypted_packet = decode_rtp_packet(encrypted_raw_payload)?;
        let gcm = SrtpGcm::new(master_key, master_salt);
        gcm.decrypt(encrypted_packet, roc)
    }

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

    #[test]
    fn test_srtp_gcm_decrypt_with_lab_capture() -> Result<()> {
        let keys = split_lab_exporter_material()?;
        let plain_raw = first_rtp_payload_from_pcap(LAB_PLAIN_CAPTURE_PCAP)?;
        let encrypted_raw = first_rtp_payload_from_pcap(LAB_ENCRYPTED_CAPTURE_PCAP)?;
        let plain_packet = decode_rtp_packet(&plain_raw)?;

        let decrypted_packet = decrypt_with_direction(
            &encrypted_raw,
            &keys.client_master_key,
            &keys.client_master_salt,
            0,
        )
        .or_else(|_| {
            decrypt_with_direction(
                &encrypted_raw,
                &keys.server_master_key,
                &keys.server_master_salt,
                0,
            )
        })?;

        assert_eq!(
            decrypted_packet.header.sequence_number,
            plain_packet.header.sequence_number
        );
        assert_eq!(
            decrypted_packet.header.timestamp,
            plain_packet.header.timestamp
        );
        assert_eq!(decrypted_packet.header.ssrc, plain_packet.header.ssrc);
        assert_eq!(decrypted_packet.payload, plain_packet.payload);
        Ok(())
    }

    #[test]
    fn test_srtp_gcm_decrypt_fails_with_wrong_roc() -> Result<()> {
        let keys = split_lab_exporter_material()?;
        let encrypted_raw = first_rtp_payload_from_pcap(LAB_ENCRYPTED_CAPTURE_PCAP)?;

        let client_err = decrypt_with_direction(
            &encrypted_raw,
            &keys.client_master_key,
            &keys.client_master_salt,
            1,
        )
        .is_err();
        let server_err = decrypt_with_direction(
            &encrypted_raw,
            &keys.server_master_key,
            &keys.server_master_salt,
            1,
        )
        .is_err();

        assert!(client_err && server_err);
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
