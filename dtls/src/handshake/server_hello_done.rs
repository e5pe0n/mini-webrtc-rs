use crate::{
    buffer::BufWriter,
    common::{CipherSuiteId, CompressionMethodId, SessionId},
    handshake::{HandshakeMessage, header::HandshakeType, random::Random},
    record_header::DtlsVersion,
};

#[derive(Debug)]
pub struct ServerHelloDone {}

impl ServerHelloDone {
    pub fn new() -> Self {
        Self {}
    }

    pub fn encode(&self, writer: &mut BufWriter) {}
}

impl HandshakeMessage for ServerHelloDone {
    fn get_handshake_type(&self) -> super::header::HandshakeType {
        HandshakeType::ServerHelloDone
    }

    fn encode(&self, writer: &mut BufWriter) {
        self.encode(writer);
    }
}
