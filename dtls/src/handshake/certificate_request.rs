use crate::{
    buffer::{BufReader, BufWriter},
    common::{AlgoPair, CertificateType, Cookie, HashAlgorithm, SignatureAlgorithm},
    handshake::{HandshakeMessage, header::HandshakeType},
    record_header::DtlsVersion,
};

#[derive(Debug)]
pub struct CertificateRequest {
    // https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.4
    // https://www.rfc-editor.org/rfc/rfc8422.html#section-5.5
    certificate_types: Vec<CertificateType>,
    supported_algo_pairs: Vec<AlgoPair>,
    certificate_authorities: Vec<String>,
}

impl CertificateRequest {
    pub fn new() -> Self {
        Self {
            // TODO: support others
            certificate_types: vec![CertificateType::Ecdsa],
            supported_algo_pairs: vec![AlgoPair {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Ecdsa,
            }],
            certificate_authorities: vec![],
        }
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        writer.write_u8(self.certificate_types.len() as u8);
        for t in &self.certificate_types {
            writer.write_u8((*t).into());
        }

        writer.write_u16(self.supported_algo_pairs.len() as u16);
        for p in &self.supported_algo_pairs {
            p.encode(writer);
        }

        writer.write_u16(self.certificate_authorities.len() as u16);
        // TODO: encode CA
        // for ca in &self.certificate_authorities {
        //     writer.write_bytes(ca);
        // }
    }
}

impl HandshakeMessage for CertificateRequest {
    fn get_handshake_type(&self) -> HandshakeType {
        HandshakeType::CertificateRequest
    }

    fn encode(&self, writer: &mut BufWriter) {
        self.encode(writer);
    }
}
