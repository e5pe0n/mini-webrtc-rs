use crate::dtls::buffer::{BufReader, BufWriter};
use crate::dtls::change_cipher_sec::ChangeCipherSpec;
use crate::dtls::cipher_suite::CipherSuiteId;
use crate::dtls::common::{
    Cookie, ECCurve, Fingerprint, HashAlgorithm, SignatureAlgorithm, generate_curve_key_pair,
};
use crate::dtls::crypto::{
    Gcm, generate_encryption_keys, generate_extended_master_secret, generate_master_secret,
    generate_verify_data,
};
use crate::dtls::extensions::Extension;
use crate::dtls::extensions::use_srtp::SrtpProtectionProfile;
use crate::dtls::handshake::HandshakeMessage;
use crate::dtls::handshake::certificate::Certificate;
use crate::dtls::handshake::certificate_request::CertificateRequest;
use crate::dtls::handshake::certificate_verify::CertificateVerify;
use crate::dtls::handshake::client_hello::ClientHello;
use crate::dtls::handshake::client_key_exchange::ClientKeyExchange;
use crate::dtls::handshake::context::HandshakeFlight;
use crate::dtls::handshake::finished::Finished;
use crate::dtls::handshake::header::{HandshakeHeader, HandshakeType};
use crate::dtls::handshake::hello_verify_request::HelloVerifyRequest;
use crate::dtls::handshake::random::Random;
use crate::dtls::handshake::server_hello::ServerHello;
use crate::dtls::handshake::server_hello_done::ServerHelloDone;
use crate::dtls::handshake::server_key_exchange::ServerKeyExchange;
use crate::dtls::record_header::{ContentType, DtlsVersion, RecordHeader};
use crate::dtls::{DtlsMessage, is_dtls_packet};
use crate::ice::IceAgent;
use crate::stun::{
    Attribute, AttributeType, HEADER_BYTES, MAGIC_COOKIE, StunMessage, StunMessageBuilder,
    StunMessageClass, StunMessageMethod, StunMessageType,
};
use anyhow::{Result, anyhow};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rcgen::{CertifiedKey, KeyPair};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use x509_parser::parse_x509_certificate;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct UdpServer {
    certified_key: CertifiedKey<KeyPair>,
    ice_agent: IceAgent,
    socket: UdpSocket,
    pub handshake_flight: HandshakeFlight,
    message_seq: u16,
    sequence_number: u64,
    epoch: u16,
    cookie: Option<Cookie>,
    received_handshake_messages: HashMap<HandshakeType, Vec<u8>>,
    sent_handshake_messages: HashMap<HandshakeType, Vec<u8>>,
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

impl UdpServer {
    pub async fn new(
        addr: &str,
        certified_key: CertifiedKey<KeyPair>,
        ice_agent: IceAgent,
    ) -> Result<Self> {
        // Bind UDP socket
        let socket = UdpSocket::bind(addr).await?;
        info!("Udp Server listening on {}", addr);

        Ok(UdpServer {
            certified_key,
            ice_agent,
            socket,
            handshake_flight: HandshakeFlight::Flight2,
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
        })
    }

    fn increment_epoch(&mut self) {
        self.epoch += 1;
        self.sequence_number = 0;
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        loop {
            // Receive data from client
            let (len, peer_addr) = self.socket.recv_from(&mut buf).await?;
            debug!("Received {} bytes from {}", len, peer_addr);

            // Parse DTLS handshake message
            self.handle_message(&buf[..len], peer_addr).await?;
        }
    }

    async fn handle_message(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        if StunMessage::is_stun_message(data) {
            return self.handle_stun_message(data, peer_addr).await;
        }

        if is_dtls_packet(data) {
            return self.handle_dtls_packet(data, peer_addr).await;
        }

        info!("ignored unknown data.");
        Ok(())
    }

    async fn handle_dtls_packet(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        let mut reader = BufReader::new(data);
        let record_header = RecordHeader::decode(&mut reader)?;

        match record_header.content_type {
            ContentType::ChangeCipherSpec => {
                debug!("Received ChangeCipherSpec from {}", peer_addr)
            }
            ContentType::Alert => debug!("Received Alert from {}", peer_addr),
            ContentType::Handshake => {
                debug!("Received Handshake from {}", peer_addr);
                return self
                    .handle_handshake(&mut reader, record_header, peer_addr)
                    .await;
            }
            ContentType::ApplicationData => {
                debug!("Received ApplicationData from {}", peer_addr)
            }
        }
    }

    async fn handle_stun_message(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        // respond to stun binding request of ice
        // - decode stun message
        let mut reader = BufReader::new(data);
        let message = StunMessage::decode(&mut reader)?;
        // - extract server username and client username
        let username_attr = message
            .attributes
            .get(&AttributeType::Username)
            .ok_or(anyhow!("username attribute does not exists."))?;
        // https://datatracker.ietf.org/doc/html/rfc8445#section-7.2.2
        // - verify username in the message
        let username = unsafe { String::from_utf8_unchecked(username_attr.value.clone()) };
        let expected_username = self.ice_agent.local_peer.ufrag.clone()
            + ":"
            + &self.ice_agent.remote_peer.as_ref().unwrap().ufrag.clone();
        if username != expected_username {
            warn!(
                "username attribute mismatch: expected={expected_username}, actual={username}; ignore the message."
            );
            return Ok(()); // ignore message
        }
        // - verify message integrity
        if !message.verify_message_integrity(self.ice_agent.local_peer.pwd.clone())? {
            warn!("message integrity mismatch; ignore the message.");
            return Ok(()); // ignore message
        }

        // - send stun binding response
        let xor_mapped_address = {
            let mut value_buf = BufWriter::new();
            value_buf.write_u8(0);
            value_buf.write_u8(
                0x0a, // ip v4
            );
            let x_port = peer_addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            value_buf.write_u16(x_port);
            let ip_addr_bytes = match peer_addr.ip() {
                IpAddr::V4(addr) => addr.octets(),
                IpAddr::V6(addr) => {
                    return Err(anyhow!("ip address is not ipv4; {addr}"));
                }
            };
            for (i, octet) in ip_addr_bytes.iter().enumerate() {
                value_buf.write_u8(octet ^ (MAGIC_COOKIE >> (8 * (3 - i))) as u8);
            }
            value_buf.buf()
        };
        let response_message = StunMessageBuilder::new(
            StunMessageType {
                method: StunMessageMethod::Binding,
                class: StunMessageClass::SuccessResponse,
            },
            message.transaction_id,
        )
        .add_attr(AttributeType::XorMappedAddress, &xor_mapped_address)
        .add_attr(AttributeType::Username, &username_attr.value[..])
        .build(self.ice_agent.local_peer.pwd.clone());
        self.socket
            .send_to(&response_message.raw, peer_addr)
            .await?;
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
            DtlsVersion::new(1, 2),
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

    async fn handle_handshake(
        &mut self,
        reader: &'_ mut BufReader<'_>,
        record_header: RecordHeader,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let handshake_header = HandshakeHeader::decode(reader)?;

        // only handshake message part; exclude record header
        self.received_handshake_messages.insert(
            handshake_header.handshake_type,
            reader.buf[reader.pos..].to_vec(),
        );

        match handshake_header.handshake_type {
            HandshakeType::ClientHello => {
                let message = ClientHello::decode(reader)?;
                debug!("  -> ClientHello from {}", peer_addr);
                match &self.handshake_flight {
                    HandshakeFlight::Flight0 => {
                        debug!("  <- Sending HelloVerifyRequest to {}", peer_addr);
                        // TODO: set CONNECTING to dtls state

                        // TODO: negotiate dtls version
                        let message = HelloVerifyRequest::new(DtlsVersion::new(1, 2));
                        let cookie = message.cookie.clone();

                        self.send_message(DtlsMessage::Handshake(Box::new(message)), peer_addr)
                            .await?;

                        self.handshake_flight = HandshakeFlight::Flight2;
                        self.cookie = Some(cookie);
                    }
                    HandshakeFlight::Flight2 => {
                        if message.cookie
                            != self.cookie.clone().ok_or(anyhow!("cookie is none."))?
                        {
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
                                        .find(|profile| {
                                            **profile == SrtpProtectionProfile::SrtpAeadAes128Gcm
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
                                ServerHello::new(DtlsVersion::new(1, 2), server_random.clone());
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
                let remote_peer = self
                    .ice_agent
                    .remote_peer
                    .clone()
                    .ok_or(anyhow!("no remote peer."))?;
                if fingerprint.to_string() != remote_peer.fingerprint {
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

                let encryption_keys = generate_encryption_keys(
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
