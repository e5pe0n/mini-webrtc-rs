pub mod buffer;
pub mod common;
pub mod crypto;
pub mod extension;
pub mod handshake;
pub mod record_header;

pub fn is_dtls_packet(data: &[u8]) -> bool {
    data.len() > 0 && data[0] >= 20 && data[0] <= 63
}
