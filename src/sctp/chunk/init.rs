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
#[derive(Debug)]
pub struct InitChunk {
    pub header: ChunkHeader,
    pub value: InitChunkValue,
}

#[derive(Debug)]
pub struct InitChunkValue {
    pub init_tag: u32,
    pub a_rwnd: u32,
    pub num_outbound_streams: u16,
    pub num_inbound_streams: u16,
    pub init_tsn: u32,
}

impl InitChunkValue {
    pub fn decode(reader: &mut BufReader) -> Result<Self, MiniWebrtcRsError> {
        let init_tag = reader.read_u32()?;
        let a_rwnd = reader.read_u32()?;
        let num_outbound_streams = reader.read_u16()?;
        let num_inbound_streams = reader.read_u16()?;
        let init_tsn = reader.read_u32()?;

        Ok(Self {
            init_tag,
            a_rwnd,
            num_outbound_streams,
            num_inbound_streams,
            init_tsn,
        })
    }
}
