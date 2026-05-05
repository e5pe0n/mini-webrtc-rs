use anyhow::Result;

use common::buffer::BufReader;
use mini_webrtc_derive::FromPrimitive;

//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |V=2|P|X|  CC   |M|     PT      |       sequence number         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                           timestamp                           |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |           synchronization source (SSRC) identifier            |
//    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//    |            contributing source (CSRC) identifiers             |
//    |                             ....                              |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// https://datatracker.ietf.org/doc/html/rfc3550#section-5.1
pub struct RtpHeader {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub marker: bool,
    pub payload_type: PayloadType,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrc: Vec<u32>,
    pub raw: Vec<u8>,
}

impl RtpHeader {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let pos = reader.pos;
        let first_byte = reader.read_u8()?;
        let csrc_count = first_byte & 0b00001111;

        let second_byte = reader.read_u8()?;

        let mut csrc = vec![];
        for _ in 0..csrc_count {
            csrc.push(reader.read_u32()?);
        }

        Ok(Self {
            version: (first_byte & 0b11000000) >> 6,
            padding: ((first_byte & 0b0010000) >> 5) == 1,
            extension: ((first_byte & 0b00010000) >> 4) == 1,
            marker: ((second_byte & 0b10000000) >> 7) == 1,
            payload_type: PayloadType::from(second_byte & 0b01111111),
            sequence_number: reader.read_u16()?,
            timestamp: reader.read_u32()?,
            ssrc: reader.read_u32()?,
            csrc,
            raw: reader.buf[pos..reader.pos].to_vec(),
        })
    }
}

// https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-1
#[derive(FromPrimitive, Debug)]
#[from(type = "u8", default = "Unsupported")]
pub enum PayloadType {
    // https://datatracker.ietf.org/doc/html/rfc7741
    VP8 = 96,
    // https://datatracker.ietf.org/doc/html/rfc7587
    Opus = 109,
    Unsupported = 255,
}
