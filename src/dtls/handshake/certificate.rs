use crate::dtls::handshake::{HandshakeMessage, header::HandshakeType};
use anyhow::Context;
use crate::common::buffer::{BufReader, BufWriter};
use tracing::debug;

#[derive(Debug)]
pub struct Certificate {
    pub certificates: Vec<Vec<u8>>,
}

impl Certificate {
    pub fn new(certificates: Vec<Vec<u8>>) -> Self {
        Self { certificates }
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        let mut certs_writer = BufWriter::new();
        for cert in &self.certificates {
            certs_writer.write_u24(cert.len() as u32);
            certs_writer.write_bytes(cert);
        }

        let buf = certs_writer.buf_ref();
        writer.write_u24(buf.len() as u32);
        writer.write_bytes(buf);
    }

    pub fn decode(reader: &mut BufReader) -> anyhow::Result<Self> {
        let certificates_length = reader.read_u24().with_context(|| {
            format!(
                "Certificate::decode: read certificate_list_length at pos={}",
                reader.pos
            )
        })? as usize;
        let mut certificates: Vec<Vec<u8>> = vec![];
        while reader.pos < certificates_length {
            let cert_len = reader.read_u24().with_context(|| {
                format!(
                    "Certificate::decode: read certificate[{}] length at pos={}",
                    certificates.len(),
                    reader.pos
                )
            })?;
            let mut cert: Vec<u8> = vec![0u8; cert_len as usize];
            reader
                .read_exact(&mut cert)
                .with_context(|| format!("Certificate::decode: read certificate[{}] body (cert_len={cert_len}) at pos={}", certificates.len(), reader.pos))?;
            certificates.push(cert);
        }
        Ok(Self { certificates })
    }
}

impl HandshakeMessage for Certificate {
    fn get_handshake_type(&self) -> HandshakeType {
        HandshakeType::Certificate
    }

    fn encode(&self, writer: &mut BufWriter) {
        self.encode(writer);
    }
}
