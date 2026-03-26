use crate::dtls::{
    buffer::BufWriter, change_cipher_sec::ChangeCipherSpec, handshake::HandshakeMessage,
    record_header::ContentType,
};

pub mod buffer;
pub mod change_cipher_sec;
pub mod cipher_suite;
pub mod common;
pub mod crypto;
pub mod extensions;
pub mod handshake;
pub mod record_header;

pub fn is_dtls_packet(data: &[u8]) -> bool {
    data.len() > 0 && data[0] >= 20 && data[0] <= 63
}

pub enum DtlsMessage {
    Handshake(Box<dyn HandshakeMessage>),
    ChangeCipherSpec(ChangeCipherSpec),
}

impl DtlsMessage {
    pub fn get_content_type(&self) -> ContentType {
        match &self {
            DtlsMessage::Handshake(_) => ContentType::Handshake,
            DtlsMessage::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
        }
    }
}
