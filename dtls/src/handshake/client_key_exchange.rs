use crate::{
    buffer::{BufReader, BufWriter},
    handshake::{HandshakeMessage, header::HandshakeType},
};

#[derive(Debug)]
pub struct ClientKeyExchange {
    // https://datatracker.ietf.org/doc/html/rfc8422#section-5.7
    pub public_key: Vec<u8>, // ephemeral public key
}

impl ClientKeyExchange {
    pub fn decode(reader: &mut BufReader) -> Result<Self, String> {
        let len = reader.read_u8()?;
        let mut public_key = vec![0u8; len as usize];
        reader.read_exact(&mut public_key);
        Ok(Self { public_key })
    }
}

impl HandshakeMessage for ClientKeyExchange {
    fn get_handshake_type(&self) -> super::header::HandshakeType {
        HandshakeType::ClientKeyExchange
    }

    fn encode(&self, writer: &mut BufWriter) {
        self.encode(writer);
    }
}
