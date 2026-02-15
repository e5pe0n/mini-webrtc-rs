use crate::{buffer::BufWriter, handshake::header::HandshakeType};

pub mod certificate;
pub mod certificate_request;
pub mod client_hello;
pub mod context;
pub mod header;
pub mod hello_verify_request;
pub mod random;
pub mod server_hello;
pub mod server_hello_done;
pub mod server_key_exchange;

pub trait HandshakeMessage {
    fn get_handshake_type(&self) -> HandshakeType;
    fn encode(&self, writer: &mut BufWriter);
}
