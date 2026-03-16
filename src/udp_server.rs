use crate::dtls::buffer::{BufReader, BufWriter};
use crate::dtls::common::generate_curve_key_pair;
use crate::dtls::crypto::{Gcm, generate_encryption_keys, generate_master_secret};
use crate::dtls::handshake::HandshakeMessage;
use crate::dtls::handshake::certificate::Certificate;
use crate::dtls::handshake::certificate_request::CertificateRequest;
use crate::dtls::handshake::client_hello::ClientHello;
use crate::dtls::handshake::client_key_exchange::ClientKeyExchange;
use crate::dtls::handshake::context::{Flight4Context, Flight6Context, HandshakeFlightContext};
use crate::dtls::handshake::header::{HandshakeHeader, HandshakeType};
use crate::dtls::handshake::hello_verify_request::HelloVerifyRequest;
use crate::dtls::handshake::random::Random;
use crate::dtls::handshake::server_hello::ServerHello;
use crate::dtls::handshake::server_hello_done::ServerHelloDone;
use crate::dtls::handshake::server_key_exchange::ServerKeyExchange;
use crate::dtls::record_header::{ContentType, DtlsVersion, RecordHeader};
use crate::ice::IceAgent;
use crate::stun::{
    Attribute, AttributeType, HEADER_BYTES, MAGIC_COOKIE, StunMessage, StunMessageBuilder,
    StunMessageClass, StunMessageMethod, StunMessageType,
};
use anyhow::{Result, anyhow};
use rcgen::{CertifiedKey, KeyPair};
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use x25519_dalek::PublicKey;

pub struct UdpServer {
    certified_key: CertifiedKey<KeyPair>,
    ice_agent: IceAgent,
    socket: UdpSocket,
    pub handshake_flight_context: HandshakeFlightContext,
    message_seq: u16,
    sequence_number: u64,
    epoch: u16,
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
            handshake_flight_context: HandshakeFlightContext::Flight0,
            message_seq: 0,
            sequence_number: 0,
            epoch: 0,
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

    fn encode_handshake_message_record(
        &mut self,
        writer: &mut BufWriter,
        handshake_message: impl HandshakeMessage,
    ) {
        let mut payload_writer = BufWriter::new();
        handshake_message.encode(&mut payload_writer);
        let payload = payload_writer.buf();

        // Create Handshake Header
        let mut handshake_writer = BufWriter::new();
        let handshake_header = HandshakeHeader::new(
            handshake_message.get_handshake_type(),
            payload.len() as u32,
            self.message_seq,
            0,
            payload.len() as u32,
        );
        self.message_seq += 1;
        handshake_header.encode(&mut handshake_writer);
        handshake_writer.write_bytes(&payload);
        let handshake_message = handshake_writer.buf();

        // Create Record Header
        let record_header = RecordHeader::new(
            ContentType::Handshake,
            DtlsVersion::new(1, 2),
            0,
            self.sequence_number,
            handshake_message.len() as u16,
        );
        record_header.encode(writer);
        writer.write_bytes(&handshake_message);
    }

    async fn handle_message(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        if StunMessage::is_stun_message(data) {
            return self.handle_stun_message(data, peer_addr).await;
        }

        let mut reader = BufReader::new(data);
        let record_header = RecordHeader::decode(&mut reader)?;

        match record_header.content_type {
            ContentType::ChangeCipherSpec => {
                debug!("Received ChangeCipherSpec from {}", peer_addr)
            }
            ContentType::Alert => debug!("Received Alert from {}", peer_addr),
            ContentType::Handshake => {
                debug!("Received Handshake from {}", peer_addr);
                self.handle_handshake(&mut reader, record_header, peer_addr)
                    .await?;
            }
            ContentType::ApplicationData => {
                debug!("Received ApplicationData from {}", peer_addr)
            }
        }

        Ok(())
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

    async fn handle_handshake(
        &mut self,
        reader: &'_ mut BufReader<'_>,
        record_header: RecordHeader,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let handshake_header = HandshakeHeader::decode(reader)?;

        match handshake_header.handshake_type {
            HandshakeType::ClientHello => {
                let client_hello = ClientHello::decode(reader)?;
                debug!("  -> ClientHello from {}", peer_addr);
                match &self.handshake_flight_context {
                    HandshakeFlightContext::Flight0 => {
                        debug!("  <- Sending HelloVerifyRequest to {}", peer_addr);

                        // TODO: negotiate dtls version
                        let hello_verify_request = HelloVerifyRequest::new(DtlsVersion::new(1, 2));
                        let cookie = hello_verify_request.cookie.clone();

                        let mut record_writer = BufWriter::new();
                        self.encode_handshake_message_record(
                            &mut record_writer,
                            hello_verify_request,
                        );

                        self.socket.send_to(&record_writer.buf(), peer_addr).await?;

                        self.handshake_flight_context =
                            HandshakeFlightContext::Flight4(Flight4Context::new(cookie));
                    }
                    HandshakeFlightContext::Flight4(context) => {
                        let client_random = client_hello.random;
                        let server_random = Random::new();
                        {
                            // ServerHello
                            let mut writer = BufWriter::new();
                            // TODO: negotiate dtls version
                            let server_hello =
                                ServerHello::new(DtlsVersion::new(1, 2), server_random.clone());
                            self.encode_handshake_message_record(&mut writer, server_hello);
                            self.socket.send_to(&writer.buf(), peer_addr).await?;
                        }
                        {
                            // Server Certificate
                            let mut writer = BufWriter::new();
                            let certificate =
                                Certificate::new(vec![self.certified_key.cert.der().to_vec()]);
                            self.encode_handshake_message_record(&mut writer, certificate);
                            self.socket.send_to(&writer.buf(), peer_addr).await?;
                        }
                        let ephemeral_secret = {
                            // ServerKeyExchange
                            let mut writer = BufWriter::new();
                            let curve_key_pair = generate_curve_key_pair();
                            let server_key_exchange = ServerKeyExchange::new(
                                curve_key_pair.public_key,
                                &self.certified_key,
                                &client_random,
                                &server_random,
                            );
                            self.encode_handshake_message_record(&mut writer, server_key_exchange);
                            self.socket.send_to(&writer.buf(), peer_addr).await?;
                            curve_key_pair.secret
                        };
                        {
                            // Certificate Request
                            let mut writer = BufWriter::new();
                            let certificate_request = CertificateRequest::new();
                            self.encode_handshake_message_record(&mut writer, certificate_request);
                            self.socket.send_to(&writer.buf(), peer_addr).await?;
                        }
                        {
                            // ServerHelloDone
                            let mut writer = BufWriter::new();
                            let server_hello_done = ServerHelloDone::new();
                            self.encode_handshake_message_record(&mut writer, server_hello_done);
                            self.socket.send_to(writer.buf_ref(), peer_addr).await?;
                        }
                        let context = Flight6Context {
                            ephemeral_secret,
                            client_random,
                            server_random,
                        };
                    }
                    _ => warn!(
                        "invalid flight for ClientHello; {:?}",
                        &self.handshake_flight_context
                    ),
                }
            }
            HandshakeType::Certificate => {
                let client_certificate = Certificate::decode(reader)?;
                // TODO: get fingerprint of client certificate
                // TODO: confirm the fingerprint hash matches the one in sdp
            }
            HandshakeType::ClientKeyExchange => {
                debug!("  -> ClientKeyExchange from {}", peer_addr);
                let client_key_exchange = ClientKeyExchange::decode(reader)?;
                let client_public_key = client_key_exchange.public_key;

                // EphemeralSecret doesn't implement Copy and Clone
                // so we need to take the ownership.
                match std::mem::replace(
                    &mut self.handshake_flight_context,
                    HandshakeFlightContext::Flight0,
                ) {
                    HandshakeFlightContext::Flight6(context) => {
                        let client_public_key: [u8; 32] = client_public_key.try_into().unwrap();
                        let pre_master_secret = context
                            .ephemeral_secret
                            .diffie_hellman(&PublicKey::from(client_public_key));
                        let master_secret = generate_master_secret(
                            pre_master_secret,
                            &context.client_random,
                            &context.server_random,
                        );
                        let encryption_keys = generate_encryption_keys(
                            &master_secret,
                            &context.client_random,
                            &context.server_random,
                        );
                        let gcm = Gcm::new(
                            &encryption_keys.server_write_key,
                            &encryption_keys.server_write_iv,
                            &encryption_keys.client_write_key,
                            &encryption_keys.client_write_iv,
                        );
                    }
                    _ => warn!(
                        "invalid flight for ClientKeyExchange ; {:?}",
                        &self.handshake_flight_context
                    ),
                }
            }
            HandshakeType::CertificateVerify => {
                // TODO
            }
            HandshakeType::Finished => {
                // TODO
            }
            _ => warn!(
                "  -> Unknown handshake type {:?} from {}",
                handshake_header.handshake_type, peer_addr
            ),
        }

        Ok(())
    }
}
