use anyhow::Result;

use crate::{dtls::buffer::BufReader, srtp::header::Header};

pub struct Packet {
    header: Header,
    header_size: usize,
    payload: Vec<u8>,
    raw: Vec<u8>,
}

impl Packet {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let pos = reader.pos;
        let buf_len = reader.rest_len();
        let header = Header::decode(reader)?;
        let header_size = header.raw.len();

        let mut payload = vec![0u8; reader.rest_len()];
        reader.read_exact(&mut payload)?;
        let padding_size = if header.padding {
            *payload.last().unwrap()
        } else {
            0
        } as usize;

        Ok(Self {
            header,
            header_size,
            payload: payload[0..payload.len() - padding_size].to_vec(),
            raw: reader.buf[pos..buf_len].to_vec(),
        })
    }
}
