use crate::{
    buffer::BufWriter,
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
}

impl HandshakeMessage for Certificate {
    fn get_handshake_type(&self) -> HandshakeType {
        HandshakeType::Certificate
    }

    fn encode(&self, writer: &mut BufWriter) {
        self.encode(writer);
    }
}
