use crate::buffer::{BufReader, BufWriter};

#[derive(Debug, Clone, Copy)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}

impl TryFrom<u8> for HandshakeType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(HandshakeType::HelloRequest),
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            3 => Ok(HandshakeType::HelloVerifyRequest),
            11 => Ok(HandshakeType::Certificate),
            12 => Ok(HandshakeType::ServerKeyExchange),
            13 => Ok(HandshakeType::CertificateRequest),
            14 => Ok(HandshakeType::ServerHelloDone),
            15 => Ok(HandshakeType::CertificateVerify),
            16 => Ok(HandshakeType::ClientKeyExchange),
            20 => Ok(HandshakeType::Finished),
            _ => Err(format!("invalid handshake type: {}", value)),
        }
    }
}

pub struct HandshakeHeader {
    pub handshake_type: HandshakeType,
    pub length: u32, // u24
    pub message_seq: u16,
    pub fragment_offset: u32, // u24
    pub fragment_length: u32, // u24
}

impl HandshakeHeader {
    pub fn new(
        handshake_type: HandshakeType,
        length: u32,
        message_seq: u16,
        fragment_offset: u32,
        fragment_length: u32,
    ) -> Self {
        Self {
            handshake_type,
            length,
            message_seq,
            fragment_offset,
            fragment_length,
        }
    }

    pub fn decode(reader: &mut BufReader) -> Result<Self, String> {
        let handshake_type_u8 = reader.read_u8()?;
        let handshake_type = HandshakeType::try_from(handshake_type_u8)?;

        let length = reader.read_u24()?;

        let message_seq = reader.read_u16()?;

        let fragment_offset = reader.read_u24()?;

        let fragment_length = reader.read_u24()?;

        Ok(Self {
            handshake_type,
            length,
            message_seq,
            fragment_offset,
            fragment_length,
        })
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        writer.write_u8(self.handshake_type as u8);
        writer.write_u24(self.length);
        writer.write_u16(self.message_seq);
        writer.write_u24(self.fragment_offset);
        writer.write_u24(self.fragment_length);
    }
}
