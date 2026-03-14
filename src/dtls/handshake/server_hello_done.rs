use crate::dtls::{
    buffer::BufWriter,
    handshake::{HandshakeMessage, header::HandshakeType},
};

#[derive(Debug)]
pub struct ServerHelloDone {}

impl ServerHelloDone {
    pub fn new() -> Self {
        Self {}
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        // TODO
    }
}

impl HandshakeMessage for ServerHelloDone {
    fn get_handshake_type(&self) -> super::header::HandshakeType {
        HandshakeType::ServerHelloDone
    }

    fn encode(&self, writer: &mut BufWriter) {
        self.encode(writer);
    }
}
