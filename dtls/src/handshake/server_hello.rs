use crate::{
    buffer::BufWriter,
    common::{CipherSuiteId, CompressionMethodId, SessionId},
    handshake::{HandshakeMessage, header::HandshakeType, random::Random},
    record_header::DtlsVersion,
};

#[derive(Debug)]
pub struct ServerHello {
    version: DtlsVersion,
    random: Random,
    session_id: SessionId,
    cipher_suite_id: CipherSuiteId,
    compression_method_id: CompressionMethodId,
    // extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn new(version: DtlsVersion) -> Self {
        Self {
            version,
            random: Random::new(),
            session_id: vec![],
            cipher_suite_id: CipherSuiteId::TlsEcdheEcdheWithAes128GcmSha256,
            compression_method_id: CompressionMethodId::Null,
        }
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        self.version.encode(writer);
        self.random.encode(writer);
        writer.write_u8(self.session_id.len() as u8);
        writer.write_bytes(self.session_id.clone());
        writer.write_u16(self.cipher_suite_id.into());
        writer.write_u8(self.compression_method_id.into());
        // TODO: write extensions
    }
}

impl HandshakeMessage for ServerHello {
    fn get_handshake_type(&self) -> super::header::HandshakeType {
        HandshakeType::ServerHello
    }

    fn encode(&self, writer: &mut BufWriter) {
        self.encode(writer);
    }
}
