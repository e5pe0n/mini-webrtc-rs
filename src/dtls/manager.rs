use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::common::buffer::{BufReader, BufWriter};
use crate::srtp::crypto::{SrtpEncryptionKeys, generate_keying_material};
use anyhow::{Context, Result, anyhow};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use rcgen::{CertifiedKey, KeyPair};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::dtls::{
    Cookie, DtlsMessage, DtlsState, ECCurve, Fingerprint, HashAlgorithm, SignatureAlgorithm,
    change_cipher_sec::ChangeCipherSpec,
    cipher_suite::CipherSuiteId,
    crypto::{
        Aes128GcmEncryptionKeys, Gcm, generate_client_verify_data, generate_extended_master_secret,
        generate_master_secret, generate_server_verify_data,
    },
    extensions::{
        Extension, renegotiation_info::RenegotiationInfo,
        use_extended_master_secret::UseExtendedMasterSecret, use_srtp::SrtpProtectionProfile,
        use_srtp::UseSrtp,
    },
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

pub enum EncodedHandshakeMessage {
    PlainHandshakeMessage(PlainHandshakeMessage),
    EncryptedHandshakeMessage(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct PlainHandshakeMessage {
    pub handshake_header: HandshakeHeader,
    pub mask: Vec<bool>,
    pub payload: Vec<u8>,
}

impl PlainHandshakeMessage {
    pub fn new(handshake_header: HandshakeHeader) -> Self {
        let length = handshake_header.length as usize;
        Self {
            // Transcript hashes are computed over full handshake messages, not per-fragment headers.
            handshake_header: HandshakeHeader::new(
                handshake_header.handshake_type,
                handshake_header.length,
                handshake_header.message_seq,
                0,
                handshake_header.length,
            ),
            mask: vec![false; length],
            payload: vec![0u8; length],
        }
    }

    pub fn add(&mut self, offset: u32, payload: &[u8]) {
        let offset = offset as usize;
        if offset >= self.payload.len() {
            return;
        }
        let length = payload.len().min(self.payload.len() - offset);
        self.payload[offset..offset + length].copy_from_slice(&payload[..length]);
        self.mask[offset..offset + length].fill(true);
    }

    pub fn completed(&self) -> bool {
        self.mask.iter().all(|b| *b)
    }

    pub fn raw(&self) -> Vec<u8> {
        let mut writer = BufWriter::new();
        self.handshake_header.encode(&mut writer);
        writer.write_bytes(&self.payload);
        writer.buf()
    }
}

pub struct DtlsManager {
    pub socket: Arc<UdpSocket>,
    pub certified_key: CertifiedKey<KeyPair>,
    pub fingerprint: Fingerprint,
    pub state: DtlsState,
    pub handshake_flight: HandshakeFlight,
    pub epoch: u16, // increment per ChangeCipherSpec and reset sequence_number to 0
    pub sequence_number: u64, // increment per sending a record
    pub message_seq: u16, // increment per handshake message
    pub next_client_message_seq: u16,
    pub fragments: HashMap<u16, PlainHandshakeMessage>,
    pub received_handshake_messages: HashMap<HandshakeType, Vec<u8>>,
    pub sent_handshake_messages: HashMap<HandshakeType, Vec<u8>>,
    pub cookie: Option<Cookie>,
    pub cipher_suite_id: Option<CipherSuiteId>,
    pub curve: Option<ECCurve>,
    pub srtp_protection_profile: Option<SrtpProtectionProfile>,
    pub use_extended_master_secret: bool,
    pub secure_renegotiation: bool,
    pub ephemeral_secret: Option<EphemeralSecret>,
    pub master_secret: Option<Vec<u8>>,
    pub client_random: Option<Random>,
    pub server_random: Option<Random>,
    pub client_certificate: Option<Vec<u8>>,
    pub gcm: Option<Gcm>,
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
            epoch: 0,
            sequence_number: 0,
            message_seq: 0,
            next_client_message_seq: 0,
            fragments: HashMap::new(),
            cookie: None,
            received_handshake_messages: HashMap::new(),
            sent_handshake_messages: HashMap::new(),
            cipher_suite_id: None,
            curve: None,
            srtp_protection_profile: None,
            use_extended_master_secret: false,
            secure_renegotiation: false,
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

        while reader.rest_len() > 0 {
            let record_header =
                RecordHeader::decode(&mut reader).context("decode record header")?;
            debug!("{:?}", record_header);

            match record_header.content_type {
                // ChangeCipherSpec message might be sent with handshake messages
                ContentType::ChangeCipherSpec => {
                    debug!("Received ChangeCipherSpec from {}", peer_addr);
                    let mut buf = vec![0u8; record_header.length as usize];
                    reader
                        .read_exact(&mut buf)
                        .context("reading change cipher spec message")?;
                    continue;
                }
                ContentType::Alert => {
                    debug!("Received Alert from {}", peer_addr);
                    let mut buf = vec![0u8; record_header.length as usize];
                    reader
                        .read_exact(&mut buf)
                        .context("reading alert message")?;
                }
                ContentType::ApplicationData => {
                    debug!("Received ApplicationData from {}", peer_addr);
                    let mut buf = vec![0u8; record_header.length as usize];
                    reader
                        .read_exact(&mut buf)
                        .context("reading application data")?;
                }
                ContentType::Handshake => {
                    debug!("Received Handshake from {}", peer_addr);

                    let mut handshake_message = vec![0u8; record_header.length as usize];
                    reader
                        .read_exact(&mut handshake_message)
                        .context("read handshake message")?;

                    let handshake_message = if record_header.epoch > 0 {
                        let decrypted_handshake_message = match &self.gcm {
                            None => {
                                anyhow::bail!(anyhow!("gcm is none."))
                            }
                            Some(gcm) => gcm.decrypt(record_header.clone(), &handshake_message),
                        }?;
                        decrypted_handshake_message
                    } else {
                        handshake_message
                    };
                    let mut handshake_message_reader = BufReader::new(&handshake_message);
                    let handshake_header = HandshakeHeader::decode(&mut handshake_message_reader)?;
                    debug!("{:?}", handshake_header);

                    let mut payload = vec![0u8; handshake_header.fragment_length as usize];
                    handshake_message_reader
                        .read_exact(&mut payload)
                        .context(format!("reading payload; {:?}", handshake_header))?;

                    if let Some(message) = self.fragments.get_mut(&handshake_header.message_seq) {
                        message.add(handshake_header.fragment_offset, &payload);
                    } else {
                        let mut message = PlainHandshakeMessage::new(handshake_header.clone());
                        message.add(handshake_header.fragment_offset, &payload);
                        self.fragments.insert(handshake_header.message_seq, message);
                    };

                    if let Some(message) = self.fragments.get(&self.next_client_message_seq)
                        && message.completed()
                    {
                        let message = message.clone();
                        self.fragments.remove(&self.next_client_message_seq);
                        self.next_client_message_seq += 1;
                        self.handle_handshake_message(message, peer_addr).await?;
                    };

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
                }
            }
        }
        Ok(())
    }

    async fn handle_handshake_message(
        &mut self,
        message: PlainHandshakeMessage,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        // only handshake message part; exclude record header
        self.received_handshake_messages
            .insert(message.handshake_header.handshake_type, message.raw());

        let mut message_reader = BufReader::new(&message.payload);

        match message.handshake_header.handshake_type {
            HandshakeType::ClientHello => {
                debug!("  -> ClientHello from {}", peer_addr);
                let message = ClientHello::decode(&mut message_reader)?;
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
                        if message
                            .cipher_suite_ids
                            .contains(&CipherSuiteId::TlsEmptyRenegotiationInfoScsv)
                        {
                            self.secure_renegotiation = true;
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
                                Extension::RenegotiationInfo(_) => {
                                    self.secure_renegotiation = true;
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
                            let mut extensions = vec![];
                            if self.secure_renegotiation {
                                extensions.push(Extension::RenegotiationInfo(
                                    RenegotiationInfo::new(vec![]),
                                ));
                            }
                            if let Some(profile) = self.srtp_protection_profile {
                                extensions.push(Extension::UseSrtp(UseSrtp {
                                    srtp_protection_profiles: vec![profile],
                                    srtp_mki: vec![],
                                }));
                            }
                            if self.use_extended_master_secret {
                                extensions.push(Extension::UseExtendedMasterSecret(
                                    UseExtendedMasterSecret {},
                                ));
                            }

                            let message = ServerHello::new(
                                DtlsVersion::V1_2,
                                server_random.clone(),
                                extensions,
                            );
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
                let message = Certificate::decode(&mut message_reader)
                    .context("DtlsManager::handle_handshake_message: decode Certificate")?;
                let cert = &message.certificates[0];
                let fingerprint = Fingerprint::new(cert);
                if fingerprint.to_string() != self.fingerprint.to_string() {
                    // TODO: set FAILED to dtls state
                }
                self.client_certificate = Some(cert.clone());
            }
            HandshakeType::ClientKeyExchange => {
                debug!("  -> ClientKeyExchange from {}", peer_addr);
                let message = ClientKeyExchange::decode(&mut message_reader)
                    .context("DtlsManager::handle_handshake_message: decode ClientKeyExchange")?;
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
                self.gcm = Some(gcm.clone());
            }
            HandshakeType::CertificateVerify => {
                let message = CertificateVerify::decode(&mut message_reader)?;
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
                let pk = x509.public_key().raw;
                let verifying_key = VerifyingKey::from_public_key_der(pk)?;
                let signature = Signature::from_der(&message.signature)
                    .map_err(|e| anyhow!("CV_PARSE_FAIL: {e}"))?;
                verifying_key
                    .verify_prehash(&handshake_messages_hash, &signature)
                    .map_err(|e| anyhow!("CV_VERIFY_FAIL: {e}"))?;
            }
            HandshakeType::Finished => {
                let message = Finished::decode(&mut message_reader)
                    .context("DtlsManager::handle_handshake_message: decode Finished")?;

                // Verify client's Finished first; transcript excludes Finished itself.
                let client_finished_transcript = self.concat_handshake_messages(true, false)?;
                let client_finished_hash = Sha256::digest(client_finished_transcript);
                let expected_client_verify_data = generate_client_verify_data(
                    &self.master_secret.clone().unwrap(),
                    &client_finished_hash,
                );
                if message.verify_data != expected_client_verify_data {
                    anyhow::bail!(
                        "invalid client Finished verify_data; expected_len={}, actual_len={}",
                        expected_client_verify_data.len(),
                        message.verify_data.len()
                    );
                }

                // Generate server Finished; transcript includes received client Finished.
                let server_finished_transcript = self.concat_handshake_messages(true, true)?;
                let server_finished_hash = Sha256::digest(server_finished_transcript);
                let verify_data = generate_server_verify_data(
                    &self.master_secret.clone().unwrap(),
                    &server_finished_hash,
                );

                self.handshake_flight = HandshakeFlight::Flight6;
                {
                    // Send CCS in epoch 0 as required by DTLS 1.2.
                    let message = ChangeCipherSpec {};
                    self.send_message(DtlsMessage::ChangeCipherSpec(message), peer_addr)
                        .await?;
                }
                // Switch write keys for the following Finished record.
                self.epoch = self.epoch.saturating_add(1);
                self.sequence_number = 0;
                {
                    // Send Finished encrypted under the negotiated cipher state.
                    let message = Finished { verify_data };
                    self.send_message(DtlsMessage::Handshake(Box::new(message)), peer_addr)
                        .await?;
                }
                self.state = DtlsState::Connected;
                info!("dtls handshake completed; state=connected");
            }
            _ => warn!(
                "  -> Unknown handshake type {:?} from {}",
                message.handshake_header.handshake_type, peer_addr
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
                self.sent_handshake_messages
                    .insert(message.get_handshake_type(), encoded_message.clone());

                self.message_seq += 1;
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
            self.epoch,
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

        self.sequence_number += 1;
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
            self.received_handshake_messages
                .get(&HandshakeType::ClientKeyExchange)
                .ok_or(anyhow!("client key exchange not found."))?
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

    pub fn export_keying_material(&self) -> Result<SrtpEncryptionKeys> {
        // // export key material
        let profile = match *&self
            .srtp_protection_profile
            .ok_or(anyhow!("srtp protection profile is none."))?
        {
            SrtpProtectionProfile::SrtpAeadAes128Gcm(profile) => Ok(profile),
            _ => Err(anyhow!("unsupported srtp protection profile.")),
        }?;
        let keying_material = generate_keying_material(
            &self
                .master_secret
                .clone()
                .ok_or(anyhow!("master secret is none."))?,
            &self
                .client_random
                .ok_or(anyhow!("client random is none."))?
                .to_bytes(),
            &self
                .server_random
                .ok_or(anyhow!("server random is none."))?
                .to_bytes(),
            profile.key_length * 2 + profile.salt_length * 2,
        );
        // init srtp cipher suite
        let encryption_keys = SrtpEncryptionKeys {
            client_master_key: keying_material[..profile.key_length].to_vec(),
            client_master_salt: keying_material[profile.key_length..profile.key_length * 2]
                .to_vec(),
            server_master_key: keying_material[profile.key_length * 2..].to_vec(),
            server_master_salt: keying_material[profile.key_length * 2 + profile.salt_length..]
                .to_vec(),
        };
        Ok(encryption_keys)
    }
}
