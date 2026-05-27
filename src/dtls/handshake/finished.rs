use crate::common::buffer::{BufReader, BufWriter};
use crate::dtls::handshake::{HandshakeMessage, header::HandshakeType};
use anyhow::Result;

pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let mut verify_data = vec![0u8; reader.rest_len()];
        reader.read_exact(&mut verify_data)?;
        Ok(Self { verify_data })
    }
}

impl HandshakeMessage for Finished {
    fn get_handshake_type(&self) -> HandshakeType {
        HandshakeType::Finished
    }

    fn encode(&self, writer: &mut BufWriter) {
        writer.write_bytes(&self.verify_data);
    }
}
