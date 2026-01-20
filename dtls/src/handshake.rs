use crate::buffer::BufReader;

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
    handshake_type: HandshakeType,
    length: u32, // u24
    message_seq: u16,
    fragment_offset: u32, // u24
    fragment_length: u32, // u24
}

impl HandshakeHeader {
    pub fn decode(reader: &mut BufReader) -> Result<Self, String> {
        let handshake_type_u8 = reader.read_u8()?;
        let handshake_type = HandshakeType::try_from(handshake_type_u8)?;

        let length1 = reader.read_u16()?;
        let length2 = reader.read_u8()?;
        let length = ((length1 as u32) << 1) + (length2 as u32);

        let message_seq = reader.read_u16()?;

        let fragment_offset1 = reader.read_u16()?;
        let fragment_offset2 = reader.read_u8()?;
        let fragment_offset = ((fragment_offset1 as u32) << 1) + (fragment_offset2 as u32);

        let fragment_length1 = reader.read_u16()?;
        let fragment_length2 = reader.read_u8()?;
        let fragment_length = ((fragment_length1 as u32) << 1) + (fragment_length2 as u32);

        Ok(Self {
            handshake_type,
            length,
            message_seq,
            fragment_offset,
            fragment_length,
        })
    }
}
