use crate::{
    common::buffer::BufReader,
    sctp::chunk::{Chunk, ChunkType},
};
use anyhow::{Result, anyhow};

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
pub struct InitChunk {
    pub chunk_type: ChunkType,
    pub chunk_flags: u8,
    pub chunk_length: u16,
    pub init_tag: u32,
    pub a_rwnd: u32,
    pub num_outbound_streams: u16,
    pub num_inbound_streams: u16,
    pub init_tsn: u32,
}

impl InitChunk {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let chunk_type = ChunkType::from(reader.read_u8()?);
        let expected_chunk_type = InitChunk::get_chunk_type();
        if chunk_type != expected_chunk_type {
            anyhow::bail!(anyhow!(
                "invalid chunk type: expected={:?}, actual={:?}",
                expected_chunk_type,
                chunk_type
            ));
        }

        let chunk_flags = reader.read_u8()?;
        let chunk_length = reader.read_u16()?;
        let init_tag = reader.read_u32()?;
        let a_rwnd = reader.read_u32()?;
        let num_outbound_streams = reader.read_u16()?;
        let num_inbound_streams = reader.read_u16()?;
        let init_tsn = reader.read_u32()?;

        Ok(Self {
            chunk_type,
            chunk_flags,
            chunk_length,
            init_tag,
            a_rwnd,
            num_outbound_streams,
            num_inbound_streams,
            init_tsn,
        })
    }
}

impl Chunk for InitChunk {
    fn get_chunk_type() -> ChunkType {
        ChunkType::Init
    }

    fn get_chunk_length(&self) -> u16 {
        self.chunk_length
    }
}
