use crate::sctp::chunk::{ChunkHeader, ChunkType};

// https://datatracker.ietf.org/doc/html/rfc9260#name-cookie-acknowledgement-cook
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Type = 11   |  Chunk Flags  |          Length = 4           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub struct CookieAckChunk {
    pub header: ChunkHeader,
    pub raw: Vec<u8>,
}

impl CookieAckChunk {
    pub fn new() -> Self {
        let header = ChunkHeader::new(ChunkType::CookieAck, 0, 4);
        let raw = header.raw.clone();

        Self { header, raw }
    }
}
