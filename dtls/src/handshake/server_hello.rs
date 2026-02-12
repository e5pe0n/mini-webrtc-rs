use crate::{
    buffer::BufWriter,
    common::{CipherSuiteId, CompressionMethodId, SessionId},
    handshake::{HandshakeMessage, header::HandshakeType, random::Random},
    record_header::DtlsVersion,
};

#[derive(Debug)]
pub struct ServerHello {
    pub version: DtlsVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suite_id: CipherSuiteId,
    pub compression_method_id: CompressionMethodId,
    // extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn new(version: DtlsVersion, random: Random) -> Self {
        Self {
            version,
            random,
            session_id: vec![],
            cipher_suite_id: CipherSuiteId::TlsEcdheEcdheWithAes128GcmSha256,
            compression_method_id: CompressionMethodId::Null,
        }
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        self.version.encode(writer);
        self.random.encode(writer);
        writer.write_u8(self.session_id.len() as u8);
        writer.write_bytes(&self.session_id);
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
