use crate::{
    common::{buffer::BufReader, error::MiniWebrtcRsError},
    sctp::chunk::ChunkHeader,
};
use anyhow::Result;

// https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.2
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Type = 1    |  Chunk Flags  |      Chunk Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Initiate Tag                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Advertised Receiver Window Credit (a_rwnd)           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Number of Outbound Streams   |   Number of Inbound Streams   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Initial TSN                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// \                                                               \
// /              Optional/Variable-Length Parameters              /
// \                                                               \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub struct CookieEchoChunk {
    pub header: ChunkHeader,
    pub value: CookieEchoChunkValue,
}

pub struct CookieEchoChunkValue {
    pub cookie: Vec<u8>,
}

impl CookieEchoChunkValue {
    pub fn decode(reader: &mut BufReader, cookie_length: u16) -> Result<Self, MiniWebrtcRsError> {
        let mut cookie = vec![0u8; cookie_length as usize];
        reader.read_exact(&mut cookie)?;
        Ok(Self { cookie })
    }
}
