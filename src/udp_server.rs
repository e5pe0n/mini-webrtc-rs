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
use rcgen::{CertifiedKey, KeyPair, generate_simple_self_signed};
use sha2::{
    Digest, Sha256, digest::generic_array::GenericArray, digest::generic_array::typenum::U32,
};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use x25519_dalek::PublicKey;

pub struct UdpServer {
    certified_key: CertifiedKey<KeyPair>,
    fingerprint: GenericArray<u8, U32>,
    socket: UdpSocket,
    pub handshake_flight_context: HandshakeFlightContext,
    message_seq: u16,
    sequence_number: u64,
    epoch: u16,
}

impl UdpServer {
    pub async fn new(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Generate self-signed certificate
        let certified_key = generate_simple_self_signed(vec!["localhost".to_string()])?;
        let fingerprint = Sha256::digest(certified_key.cert.der());

        // Bind UDP socket
        let socket = UdpSocket::bind(addr).await?;
        println!("Udp Server listening on {}", addr);

        Ok(UdpServer {
            certified_key,
            fingerprint,
            socket,
            handshake_flight_context: HandshakeFlightContext::Flight0,
            message_seq: 0,
            sequence_number: 0,
            epoch: 0,
        })
    }

    pub fn get_fingerprint(&self) -> String {
        self.fingerprint
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    fn increment_epoch(&mut self) {
        self.epoch += 1;
        self.sequence_number = 0;
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "Certificate Fingerprint (SHA-256): {}",
            self.get_fingerprint()
        );

        let mut buf = vec![0u8; 65535];

        loop {
            // Receive data from client
            let (len, peer_addr) = self.socket.recv_from(&mut buf).await?;
            println!("Received {} bytes from {}", len, peer_addr);

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

    async fn handle_message(
        &mut self,
        data: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if data.is_empty() {
            return Ok(());
        }

        let mut reader = BufReader::new(data);
        let record_header = RecordHeader::decode(&mut reader)?;

        match record_header.content_type {
            ContentType::ChangeCipherSpec => {
                println!("Received ChangeCipherSpec from {}", peer_addr)
            }
            ContentType::Alert => println!("Received Alert from {}", peer_addr),
            ContentType::Handshake => {
                println!("Received Handshake from {}", peer_addr);
                self.handle_handshake(&mut reader, record_header, peer_addr)
                    .await?;
            }
            ContentType::ApplicationData => println!("Received ApplicationData from {}", peer_addr),
        }

        Ok(())
    }

    async fn handle_handshake(
        &mut self,
        reader: &'_ mut BufReader<'_>,
        record_header: RecordHeader,
        peer_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let handshake_header = HandshakeHeader::decode(reader)?;

        match handshake_header.handshake_type {
            HandshakeType::ClientHello => {
                let client_hello = ClientHello::decode(reader)?;
                println!("  -> ClientHello from {}", peer_addr);
                match &self.handshake_flight_context {
                    HandshakeFlightContext::Flight0 => {
                        println!("  <- Sending HelloVerifyRequest to {}", peer_addr);

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
                    _ => println!(
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
                println!("  -> ClientKeyExchange from {}", peer_addr);
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
                    _ => println!(
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
            _ => println!(
                "  -> Unknown handshake type {:?} from {}",
                handshake_header.handshake_type, peer_addr
            ),
        }

        Ok(())
    }
}
