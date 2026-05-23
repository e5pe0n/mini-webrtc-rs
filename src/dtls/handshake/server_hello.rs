use crate::dtls::{
    cipher_suite::CipherSuiteId,
    extensions::Extension,
    handshake::{HandshakeMessage, header::HandshakeType, random::Random},
    record_header::DtlsVersion,
    {CompressionMethodId, SessionId},
};
use crate::common::buffer::BufWriter;

#[derive(Debug)]
pub struct ServerHello {
    pub version: DtlsVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suite_id: CipherSuiteId,
    pub compression_method_id: CompressionMethodId,
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn new(version: DtlsVersion, random: Random, extensions: Vec<Extension>) -> Self {
        Self {
            version,
            random,
            session_id: vec![],
            cipher_suite_id: CipherSuiteId::TlsEcdheEcdsaWithAes128GcmSha256,
            compression_method_id: CompressionMethodId::Null,
            extensions,
        }
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        writer.write_u16(self.version.into());
        self.random.encode(writer);
        writer.write_u8(self.session_id.len() as u8);
        writer.write_bytes(&self.session_id);
        writer.write_u16(self.cipher_suite_id.into());
        writer.write_u8(self.compression_method_id.into());

        let mut extensions_writer = BufWriter::new();
        for extension in &self.extensions {
            let mut extension_data_writer = BufWriter::new();
            match extension {
                Extension::RenegotiationInfo(value) => value.encode(&mut extension_data_writer),
                Extension::UseSrtp(value) => value.encode(&mut extension_data_writer),
                Extension::UseExtendedMasterSecret(value) => {
                    value.encode(&mut extension_data_writer)
                }
                _ => continue,
            }

            extensions_writer.write_u16(extension.get_extension_type() as u16);
            extensions_writer.write_u16(extension_data_writer.buf_ref().len() as u16);
            extensions_writer.write_bytes(extension_data_writer.buf_ref());
        }

        writer.write_u16(extensions_writer.buf_ref().len() as u16);
        writer.write_bytes(extensions_writer.buf_ref());
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
