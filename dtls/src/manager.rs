use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::{Result, anyhow};
use common::buffer::{BufReader, BufWriter};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rcgen::{CertifiedKey, KeyPair};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    Cookie, DtlsMessage, DtlsState, ECCurve, Fingerprint, HashAlgorithm, SignatureAlgorithm,
    change_cipher_sec::ChangeCipherSpec,
    cipher_suite::CipherSuiteId,
    crypto::{
        Aes128GcmEncryptionKeys, Gcm, generate_extended_master_secret, generate_master_secret,
        generate_verify_data,
    },
    extensions::{Extension, use_srtp::SrtpProtectionProfile},
    generate_curve_key_pair,
    handshake::{
        certificate::Certificate,
        certificate_request::CertificateRequest,
        certificate_verify::CertificateVerify,
        client_hello::ClientHello,
        client_key_exchange::ClientKeyExchange,
        context::HandshakeFlight,
        finished::Finished,
        header::{HandshakeHeader, HandshakeType},
        hello_verify_request::HelloVerifyRequest,
        random::Random,
        server_hello::ServerHello,
        server_hello_done::ServerHelloDone,
        server_key_exchange::ServerKeyExchange,
    },
    record_header::{ContentType, DtlsVersion, RecordHeader},
};

pub struct DtlsManager {
    socket: Arc<UdpSocket>,
    certified_key: CertifiedKey<KeyPair>,
    fingerprint: Fingerprint,
    state: DtlsState,
    handshake_flight: HandshakeFlight,
    message_seq: u16,
    sequence_number: u64,
    epoch: u16,
    received_handshake_messages: HashMap<HandshakeType, Vec<u8>>,
    sent_handshake_messages: HashMap<HandshakeType, Vec<u8>>,
    cookie: Option<Cookie>,
    cipher_suite_id: Option<CipherSuiteId>,
    curve: Option<ECCurve>,
    srtp_protection_profile: Option<SrtpProtectionProfile>,
    use_extended_master_secret: bool,
    ephemeral_secret: Option<EphemeralSecret>,
    master_secret: Option<Vec<u8>>,
    client_random: Option<Random>,
    server_random: Option<Random>,
    client_certificate: Option<Vec<u8>>,
    gcm: Option<Gcm>,
}

impl DtlsManager {
    pub fn new(
        socket: Arc<UdpSocket>,
        certified_key: CertifiedKey<KeyPair>,
        fingerprint: Fingerprint,
    ) -> Self {
        Self {
            socket,
            certified_key,
            fingerprint,
            state: DtlsState::New,
            handshake_flight: HandshakeFlight::Flight0,
            message_seq: 0,
            sequence_number: 0,
            epoch: 0,
            cookie: None,
            received_handshake_messages: HashMap::new(),
            sent_handshake_messages: HashMap::new(),
            cipher_suite_id: None,
            curve: None,
            srtp_protection_profile: None,
            use_extended_master_secret: false,
            ephemeral_secret: None,
            master_secret: None,
            client_random: None,
            server_random: None,
            client_certificate: None,
            gcm: None,
        }
    }

    pub async fn handle_dtls_packet(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        let mut reader = BufReader::new(data);
        let record_header = RecordHeader::decode(&mut reader)?;
        debug!("{:?}", record_header);

        match record_header.content_type {
            ContentType::ChangeCipherSpec => {
                // TODO: handle ChangeCipherSpec
                debug!("Received ChangeCipherSpec from {}", peer_addr);
                Ok(())
            }
            ContentType::Alert => {
                // TODO: handle Alert
                debug!("Received Alert from {}", peer_addr);
                Ok(())
            }
            ContentType::Handshake => {
                debug!("Received Handshake from {}", peer_addr);
                self.handle_handshake_message(&mut reader, peer_addr)
                    .await?;
                match self.state {
                    DtlsState::Connected => {
                        // on dtls connected handler
                        // // export key material
                        // let profile = match *&self
                        //     .srtp_protection_profile
                        //     .ok_or(anyhow!("srtp protection profile is none."))?
                        // {
                        //     SrtpProtectionProfile::SrtpAeadAes128Gcm(profile) => Ok(profile),
                        //     _ => Err(anyhow!("unsupported srtp protection profile.")),
                        // }?;
                        // let keying_material = generate_keying_material(
                        //     &self
                        //         .master_secret
                        //         .clone()
                        //         .ok_or(anyhow!("master secret is none."))?,
                        //     &self
                        //         .client_random
                        //         .ok_or(anyhow!("client random is none."))?
                        //         .to_bytes(),
                        //     &self
                        //         .server_random
                        //         .ok_or(anyhow!("server random is none."))?
                        //         .to_bytes(),
                        //     profile.key_length * 2 + profile.salt_length * 2,
                        // );
                        // // init srtp cipher suite
                        // let encryption_keys = SrtpEncryptionKeys {
                        //     client_master_key: keying_material[..profile.key_length].to_vec(),
                        //     client_master_salt: keying_material
                        //         [profile.key_length..profile.key_length * 2]
                        //         .to_vec(),
                        //     server_master_key: keying_material[profile.key_length * 2..].to_vec(),
                        //     server_master_salt: keying_material
                        //         [profile.key_length * 2 + profile.salt_length..]
                        //         .to_vec(),
                        // };
                        // // use client key and salt to decrypt data from client
                        // let srtp_gcm = SrtpGcm::new(
                        //     &encryption_keys.client_master_key,
                        //     &encryption_keys.client_master_salt,
                        // );
                        // self.srtp_gcm = Some(srtp_gcm);
                    }
                    _ => {}
                }
                Ok(())
            }
            ContentType::ApplicationData => {
                // TODO: handle ApplicationData
                debug!("Received ApplicationData from {}", peer_addr);
                Ok(())
            }
        }
    }

    async fn handle_handshake_message(
        &mut self,
        reader: &'_ mut BufReader<'_>,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let handshake_header = HandshakeHeader::decode(reader)?;
        debug!("{:?}", handshake_header);

        // only handshake message part; exclude record header
        self.received_handshake_messages.insert(
            handshake_header.handshake_type,
            reader.buf[reader.pos..].to_vec(),
        );
        debug!("pos: {}, len: {}", reader.pos, reader.buf.len());

        match handshake_header.handshake_type {
            HandshakeType::ClientHello => {
                debug!("  -> ClientHello from {}", peer_addr);
                let message = ClientHello::decode(reader)?;
                debug!("{message:?}");
                match &self.handshake_flight {
                    HandshakeFlight::Flight0 => {
                        debug!("  <- Sending HelloVerifyRequest to {}", peer_addr);
                        // TODO: set CONNECTING to dtls state

                        // TODO: negotiate dtls version
                        let message = HelloVerifyRequest::new(DtlsVersion::V1_2);
                        let cookie = message.cookie.clone();

                        self.send_message(DtlsMessage::Handshake(Box::new(message)), peer_addr)
                            .await?;

                        self.handshake_flight = HandshakeFlight::Flight2;
                        self.cookie = Some(cookie);
                    }
                    HandshakeFlight::Flight2 => {
                        if message.cookie.is_none() {
                            // TODO: set FAILED to dtls state
                            anyhow::bail!(anyhow!("message.cookie is none."))
                        }
                        if self.cookie.clone().is_none() {
                            // TODO: set FAILED to dtls state
                            anyhow::bail!(anyhow!("self.cookie is none."))
                        }
                        if message.cookie.unwrap() != self.cookie.clone().unwrap() {
                            // TODO: set FAILED to dtls state
                        }
                        // TODO: negotiate cipher suite
                        if !message
                            .cipher_suite_ids
                            .contains(&CipherSuiteId::TlsEcdheEcdsaWithAes128GcmSha256)
                        {
                            // TODO: set FAILED to dtls state
                        }
                        self.cipher_suite_id =
                            Some(CipherSuiteId::TlsEcdheEcdsaWithAes128GcmSha256);

                        // TODO: handle extensions
                        for extension in message.extensions {
                            match extension {
                                Extension::SupportedGroups(value) => {
                                    let curve = value
                                        .curves
                                        .iter()
                                        // TODO: negotiate curve
                                        .find(|curve| **curve == ECCurve::X25519)
                                        .ok_or(anyhow!("ECCurve::X25519 not found."))?;
                                    self.curve = Some(*curve);
                                }
                                Extension::UseSrtp(value) => {
                                    let profile = value
                                        .srtp_protection_profiles
                                        .iter()
                                        .find(|profile| match **profile {
                                            SrtpProtectionProfile::SrtpAeadAes128Gcm(_) => true,
                                            _ => false,
                                        })
                                        .ok_or(anyhow!(
                                            "SrtpProtectionProfile::SrtpAeadAes128Gcm not found."
                                        ))?;
                                    self.srtp_protection_profile = Some(*profile);
                                }
                                Extension::UseExtendedMasterSecret(_) => {
                                    self.use_extended_master_secret = true;
                                }
                                _ => {
                                    info!("ignore unsupported extension; {extension:?}.");
                                }
                            }
                        }

                        let client_random = message.random;
                        let server_random = Random::new();

                        self.handshake_flight = HandshakeFlight::Flight4;
                        {
                            // ServerHello
                            // TODO: negotiate dtls version
                            let message =
                                ServerHello::new(DtlsVersion::V1_2, server_random.clone());
                            self.send_message(DtlsMessage::Handshake(Box::new(message)), peer_addr)
                                .await?;
                        }
                        {
                            // Server Certificate
                            let message =
                                Certificate::new(vec![self.certified_key.cert.der().to_vec()]);
                            self.send_message(DtlsMessage::Handshake(Box::new(message)), peer_addr)
                                .await?;
                        }
                        let ephemeral_secret = {
                            // ServerKeyExchange
                            let curve_key_pair = generate_curve_key_pair();
                            let message = ServerKeyExchange::new(
                                curve_key_pair.public_key,
                                &self.certified_key,
                                &client_random,
                                &server_random,
                            );
                            self.send_message(DtlsMessage::Handshake(Box::new(message)), peer_addr)
                                .await?;
                            curve_key_pair.secret
                        };
                        {
                            // Certificate Request
                            let message = CertificateRequest::new();
                            self.send_message(DtlsMessage::Handshake(Box::new(message)), peer_addr)
                                .await?;
                        }
                        {
                            // ServerHelloDone
                            let message = ServerHelloDone::new();
                            self.send_message(DtlsMessage::Handshake(Box::new(message)), peer_addr)
                                .await?;
                        }

                        self.ephemeral_secret = Some(ephemeral_secret);
                        self.client_random = Some(client_random);
                        self.server_random = Some(server_random);
                    }
                    _ => warn!(
                        "invalid flight for ClientHello; {:?}",
                        &self.handshake_flight
                    ),
                }
            }
            HandshakeType::Certificate => {
                let message = Certificate::decode(reader)?;
                let cert = &message.certificates[0];
                let fingerprint = Fingerprint::new(cert);
                if fingerprint.to_string() != self.fingerprint.to_string() {
                    // TODO: set FAILED to dtls state
                }
                self.client_certificate = Some(cert.clone());
            }
            HandshakeType::ClientKeyExchange => {
                debug!("  -> ClientKeyExchange from {}", peer_addr);
                let message = ClientKeyExchange::decode(reader)?;
                let client_public_key = message.public_key;

                let client_public_key: [u8; 32] = client_public_key
                    .try_into()
                    .or(Err(anyhow!("failed to convert vec into array.")))?;
                let pre_master_secret = self
                    .ephemeral_secret
                    .take()
                    .ok_or(anyhow!("ephemeral secret is none."))?
                    .diffie_hellman(&PublicKey::from(client_public_key));
                let client_random = self
                    .client_random
                    .ok_or(anyhow!("client random is none."))?;
                let server_random = self
                    .server_random
                    .ok_or(anyhow!("server random is none."))?;

                let master_secret = if self.use_extended_master_secret {
                    let handshake_messages = self.concat_handshake_messages(false, false)?;
                    let handshake_hash = Sha256::digest(handshake_messages);
                    generate_extended_master_secret(pre_master_secret, handshake_hash)
                } else {
                    generate_master_secret(pre_master_secret, &client_random, &server_random)
                };

                self.master_secret = Some(master_secret);

                let encryption_keys = Aes128GcmEncryptionKeys::new(
                    &self.master_secret.clone().unwrap(),
                    &client_random,
                    &server_random,
                );
                let gcm = Gcm::new(
                    &encryption_keys.server_write_key,
                    &encryption_keys.server_write_iv,
                    &encryption_keys.client_write_key,
                    &encryption_keys.client_write_iv,
                );
                self.gcm = Some(gcm);
            }
            HandshakeType::CertificateVerify => {
                let message = CertificateVerify::decode(reader)?;
                if message.algo_pair.hash != HashAlgorithm::Sha256 {
                    warn!("unsupported hash algo; {:?}", message.algo_pair.hash);
                    // set dtls state to FAILED
                }
                if message.algo_pair.signature != SignatureAlgorithm::Ecdsa {
                    warn!(
                        "unsupported signature algo; {:?}",
                        message.algo_pair.signature
                    );
                    // set dtls state to FAILED
                }
                let handshake_messages = self.concat_handshake_messages(false, false)?;
                let handshake_messages_hash = Sha256::digest(handshake_messages);
                let client_certificate = self
                    .client_certificate
                    .clone()
                    .ok_or(anyhow!("client certificate is none."))?;
                let (_, x509) = x509_parser::parse_x509_certificate(&client_certificate)?;
                let verifying_key = VerifyingKey::from_sec1_bytes(x509.public_key().raw)?;
                let signature = Signature::from_der(&message.signature)?;
                verifying_key.verify_prehash(&handshake_messages_hash, &signature)?;
            }
            HandshakeType::Finished => {
                let handshake_messages = self.concat_handshake_messages(true, true)?;
                let handshake_messages_hash = Sha256::digest(handshake_messages);
                let verify_data = generate_verify_data(
                    &self.master_secret.clone().unwrap(),
                    &handshake_messages_hash,
                );

                self.handshake_flight = HandshakeFlight::Flight6;

                {
                    // ChangeCipherSuite
                    let message = ChangeCipherSpec {};
                    self.send_message(DtlsMessage::ChangeCipherSpec(message), peer_addr)
                        .await?;
                }
                {
                    // Finished response
                    let message = Finished { verify_data };
                    self.send_message(DtlsMessage::Handshake(Box::new(message)), peer_addr)
                        .await?;
                }
                // TODO: set CONNECTED to dtls state
            }
            _ => warn!(
                "  -> Unknown handshake type {:?} from {}",
                handshake_header.handshake_type, peer_addr
            ),
        }

        Ok(())
    }

    async fn send_message(&mut self, message: DtlsMessage, peer_addr: SocketAddr) -> Result<()> {
        let encoded_message = match &message {
            DtlsMessage::Handshake(message) => {
                let mut payload_writer = BufWriter::new();
                message.encode(&mut payload_writer);
                let payload = payload_writer.buf();

                // Create Handshake Header
                let mut handshake_writer = BufWriter::new();
                let handshake_header = HandshakeHeader::new(
                    message.get_handshake_type(),
                    payload.len() as u32,
                    self.message_seq,
                    0,
                    payload.len() as u32,
                );
                handshake_header.encode(&mut handshake_writer);
                handshake_writer.write_bytes(&payload);
                let encoded_message = handshake_writer.buf();

                // only handshake message part; exclude record header
                self.received_handshake_messages
                    .insert(message.get_handshake_type(), encoded_message.clone());
                encoded_message
            }
            DtlsMessage::ChangeCipherSpec(message) => {
                let mut writer = BufWriter::new();
                message.encode(&mut writer);
                writer.buf()
            }
        };

        // Create Record Header
        let mut record_header = RecordHeader::new(
            message.get_content_type(),
            DtlsVersion::V1_2,
            0,
            self.sequence_number,
            encoded_message.len() as u16,
        );

        let encoded_message = if self.epoch > 0
            && let Some(gcm) = &self.gcm
        {
            let encrypted_message = gcm.encrypt(record_header.clone(), encoded_message)?;
            record_header.length = encrypted_message.len() as u16;
            encrypted_message
        } else {
            encoded_message
        };

        let mut writer = BufWriter::new();
        record_header.encode(&mut writer);
        writer.write_bytes(&encoded_message);

        self.socket.send_to(&writer.buf_ref(), peer_addr).await?;

        self.message_seq += 1;
        Ok(())
    }

    fn concat_handshake_messages(
        &self,
        include_received_certificate_verify: bool,
        include_received_finished: bool,
    ) -> Result<Vec<u8>> {
        Ok(vec![
            self.received_handshake_messages
                .get(&HandshakeType::ClientHello)
                .ok_or(anyhow!("client hello not found."))?
                .clone(),
            self.sent_handshake_messages
                .get(&HandshakeType::ServerHello)
                .ok_or(anyhow!("server hello not found."))?
                .clone(),
            self.sent_handshake_messages
                .get(&HandshakeType::Certificate)
                .ok_or(anyhow!("server certificate not found."))?
                .clone(),
            self.sent_handshake_messages
                .get(&HandshakeType::ServerKeyExchange)
                .ok_or(anyhow!("server key exchange not found."))?
                .clone(),
            self.sent_handshake_messages
                .get(&HandshakeType::CertificateRequest)
                .ok_or(anyhow!("certificate request not found."))?
                .clone(),
            self.sent_handshake_messages
                .get(&HandshakeType::ServerHelloDone)
                .ok_or(anyhow!("server hello done not found."))?
                .clone(),
            self.received_handshake_messages
                .get(&HandshakeType::Certificate)
                .ok_or(anyhow!("client certificate not found."))?
                .clone(),
            if include_received_certificate_verify {
                self.received_handshake_messages
                    .get(&HandshakeType::CertificateVerify)
                    .ok_or(anyhow!("certificate verify not found."))?
                    .clone()
            } else {
                vec![]
            },
            if include_received_finished {
                self.received_handshake_messages
                    .get(&HandshakeType::Finished)
                    .ok_or(anyhow!("finished not found."))?
                    .clone()
            } else {
                vec![]
            },
        ]
        .concat())
    }
}
