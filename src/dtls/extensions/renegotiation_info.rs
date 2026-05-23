use anyhow::Result;
use crate::common::buffer::{BufReader, BufWriter};

// https://datatracker.ietf.org/doc/html/rfc5746#section-3.2
#[derive(Debug)]
pub struct RenegotiationInfo {
    pub renegotiated_connection: Vec<u8>,
}

impl RenegotiationInfo {
    pub fn new(renegotiated_connection: Vec<u8>) -> Self {
        Self {
            renegotiated_connection,
        }
    }

    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let renegotiated_connection_length = reader.read_u8()? as usize;
        let mut renegotiated_connection = vec![0u8; renegotiated_connection_length];
        reader.read_exact(&mut renegotiated_connection)?;

        Ok(Self {
            renegotiated_connection,
        })
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        writer.write_u8(self.renegotiated_connection.len() as u8);
        writer.write_bytes(&self.renegotiated_connection);
    }
}
