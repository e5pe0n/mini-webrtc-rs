use crate::{
    buffer::{BufReader, BufWriter},
    handshake::{HandshakeMessage, header::HandshakeType},
};

#[derive(Debug)]
pub struct Certificate {
    certificates: Vec<Vec<u8>>,
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

    pub fn decode(reader: &mut BufReader) -> Result<Self, String> {
        let length = reader.read_u24()?;
        let mut certificates: Vec<Vec<u8>> = vec![];
        for _ in 0..length {
            let cert_len = reader.read_u24()?;
            let mut cert: Vec<u8> = vec![0u8; cert_len as usize];
            reader.read_exact(&mut cert);
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
