use anyhow::Result;

use crate::srtp::header::RtpHeader;
use crate::common::buffer::BufReader;

#[derive(Debug, Clone, Copy)]
// packet index = roc * 2**16 + seq
pub struct SrtpPacketIndex {
    pub roc: u32,
    pub seq: u16,
}

impl SrtpPacketIndex {
    pub fn value(&self) -> u64 {
        (self.roc as u64) << 16 | self.seq as u64
    }
}

pub struct RtpPacket {
    pub header: RtpHeader,
    pub header_size: usize,
    pub payload: Vec<u8>,
    pub raw: Vec<u8>,
}

impl RtpPacket {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let pos = reader.pos;
        let buf_len = reader.rest_len();
        let header = RtpHeader::decode(reader)?;
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
