use crate::{buffer::BufWriter, handshake::header::HandshakeType};

pub mod certificate;
pub mod client_hello;
pub mod context;
pub mod header;
pub mod hello_verify_request;
pub mod random;
pub mod server_hello;

pub trait HandshakeMessage {
    fn get_handshake_type(&self) -> HandshakeType;
    fn encode(&self, writer: &mut BufWriter);
}
