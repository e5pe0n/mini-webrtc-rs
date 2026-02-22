mod buffer;
mod common;
mod crypto;
mod extension;
mod handshake;
mod record_header;

use crate::buffer::{BufReader, BufWriter};
use crate::common::generate_curve_key_pair;
use crate::crypto::{Gcm, generate_encryption_keys, generate_master_secret};
use crate::handshake::HandshakeMessage;
use crate::handshake::certificate::Certificate;
use crate::handshake::certificate_request::CertificateRequest;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::client_key_exchange::ClientKeyExchange;
use crate::handshake::context::{Flight4Context, Flight6Context, HandshakeFlightContext};
use crate::handshake::header::{HandshakeHeader, HandshakeType};
use crate::handshake::hello_verify_request::HelloVerifyRequest;
use crate::handshake::random::Random;
use crate::handshake::server_hello::ServerHello;
use crate::handshake::server_hello_done::ServerHelloDone;
use crate::handshake::server_key_exchange::ServerKeyExchange;
use crate::record_header::{ContentType, DtlsVersion, RecordHeader};
use rcgen::{CertifiedKey, KeyPair, generate_simple_self_signed};
use sha2::{
    Digest, Sha256, digest::generic_array::GenericArray, digest::generic_array::typenum::U32,
};
use std::io::Read;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey};

struct DtlsServer {
    certified_key: CertifiedKey<KeyPair>,
    fingerprint: GenericArray<u8, U32>,
    socket: UdpSocket,
    pub handshake_flight_context: HandshakeFlightContext,
    message_seq: u16,
    sequence_number: u64,
    epoch: u16,
}

impl DtlsServer {
    pub async fn new(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Generate self-signed certificate
        let certified_key = generate_simple_self_signed(vec!["localhost".to_string()])?;
        let fingerprint = Sha256::digest(certified_key.cert.der());

        // Bind UDP socket
        let socket = UdpSocket::bind(addr).await?;
        println!("DTLS Server listening on {}", addr);

        Ok(DtlsServer {
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
            record_header::ContentType::Handshake,
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
            HandshakeType::Finished {
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut server = DtlsServer::new("127.0.0.1:4433").await?;
    server.run().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_server_creation() {
        let server = DtlsServer::new("127.0.0.1:0").await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_fingerprint_format() {
        let server = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let fingerprint = server.get_fingerprint();

        // SHA-256 fingerprint should be 64 hex chars + 31 colons = 95 chars
        assert_eq!(fingerprint.len(), 95);

        // Should contain colons
        assert!(fingerprint.contains(':'));

        // Should be all uppercase hex with colons
        assert!(
            fingerprint
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':')
        );
    }

    #[tokio::test]
    async fn test_fingerprint_uniqueness() {
        let server1 = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let server2 = DtlsServer::new("127.0.0.1:0").await.unwrap();

        // Each server should have a unique certificate and fingerprint
        assert_ne!(server1.get_fingerprint(), server2.get_fingerprint());
    }

    #[tokio::test]
    async fn test_handle_empty_message() {
        let mut server = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        let result = server.handle_message(&[], peer_addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_change_cipher_spec() {
        let mut server = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        // ChangeCipherSpec message (content type 20)
        let message = vec![20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result = server.handle_message(&message, peer_addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_alert() {
        let mut server = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        // Alert message (content type 21)
        let message = vec![21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let result = server.handle_message(&message, peer_addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_handshake_short_message() {
        let mut server = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        // Handshake message too short (< 13 bytes)
        let message = vec![22, 0, 0, 0, 0];
        let result = server.handle_message(&message, peer_addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_client_hello() {
        let mut server = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        // Handshake message with ClientHello (type 1) at byte 13
        let message = vec![
            22, // content type: handshake
            254, 253, // version: DTLS 1.2
            0, 0, // epoch
            0, 0, 0, 0, 0, 0, // sequence number
            0, 10, // length
            1,  // handshake type: ClientHello
            0, 0, 0, // handshake length
        ];
        let result = server.handle_message(&message, peer_addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_application_data() {
        let mut server = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        // ApplicationData message (content type 23)
        let message = vec![23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        let result = server.handle_message(&message, peer_addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_unknown_content_type() {
        let mut server = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        // Unknown content type (99)
        let message = vec![99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let result = server.handle_message(&message, peer_addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_and_receive() {
        let server = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let server_addr = server.socket.local_addr().unwrap();

        // Create a client socket
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Send a message from client to server
        let test_message = b"test message";
        client.send_to(test_message, server_addr).await.unwrap();

        // Receive on server side
        let mut buf = vec![0u8; 1024];
        let (len, _addr) = server.socket.recv_from(&mut buf).await.unwrap();

        assert_eq!(&buf[..len], test_message);
    }

    #[tokio::test]
    async fn test_certificate_generation() {
        let server1 = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let server2 = DtlsServer::new("127.0.0.1:0").await.unwrap();

        // Each server should have a certificate
        assert_eq!(server1.fingerprint.len(), 32); // SHA-256 is 32 bytes
        assert_eq!(server2.fingerprint.len(), 32);

        // Fingerprints should be different
        assert_ne!(
            server1.fingerprint.as_slice(),
            server2.fingerprint.as_slice()
        );
    }

    #[tokio::test]
    async fn test_multiple_servers() {
        // Should be able to create multiple servers on different ports
        let server1 = DtlsServer::new("127.0.0.1:0").await;
        let server2 = DtlsServer::new("127.0.0.1:0").await;
        let server3 = DtlsServer::new("127.0.0.1:0").await;

        assert!(server1.is_ok());
        assert!(server2.is_ok());
        assert!(server3.is_ok());
    }

    #[tokio::test]
    async fn test_handshake_types() {
        let mut server = DtlsServer::new("127.0.0.1:0").await.unwrap();
        let peer_addr = "127.0.0.1:8080".parse().unwrap();

        // Test various handshake types
        let handshake_types = vec![
            1,  // ClientHello
            11, // Certificate
            12, // ServerKeyExchange
            13, // CertificateRequest
            14, // ServerHelloDone
            15, // CertificateVerify
            16, // ClientKeyExchange
            20, // Finished
        ];

        for handshake_type in handshake_types {
            let message = vec![
                22, // content type: handshake
                254,
                253, // version
                0,
                0, // epoch
                0,
                0,
                0,
                0,
                0,
                0, // sequence
                0,
                10,             // length
                handshake_type, // handshake type
                0,
                0,
                0, // handshake length
            ];
            let result = server.handle_message(&message, peer_addr).await;
            assert!(
                result.is_ok(),
                "Failed for handshake type {}",
                handshake_type
            );
        }
    }
}
