use crate::{
    common::{
        buffer::{BufReader, BufWriter},
        error::MiniWebrtcRsError,
    },
    sctp::chunk::{ChunkHeader, ChunkType},
};

// https://datatracker.ietf.org/doc/html/rfc9260#name-selective-acknowledgement-s
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Type = 3    |  Chunk Flags  |         Chunk Length          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Cumulative TSN Ack                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Advertised Receiver Window Credit (a_rwnd)           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Number of Gap Ack Blocks = N  |  Number of Duplicate TSNs = M |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Gap Ack Block #1 Start     |     Gap Ack Block #1 End      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// \                              ...                              \
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Gap Ack Block #N Start     |     Gap Ack Block #N End      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Duplicate TSN 1                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// \                              ...                              \
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Duplicate TSN M                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct SackChunk {
    pub header: ChunkHeader,
    pub value: SackChunkValue,
    pub raw: Vec<u8>,
}

impl SackChunk {
    pub fn new(header: Option<ChunkHeader>, value: SackChunkValue) -> Self {
        let mut header = header.unwrap_or(ChunkHeader::new(ChunkType::Sack, 0, 0));
        let encoded_value: Vec<u8> = value.clone().into();
        let chunk_length = (header.raw.len() + encoded_value.len()) as u16;
        header.update_chunk_length(chunk_length);

        let mut writer = BufWriter::new();
        writer.write_bytes(&header.raw);
        writer.write_bytes(&encoded_value);

        Self {
            header,
            value,
            raw: writer.buf(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SackChunkValue {
    pub cumulative_tsn_ack: u32,
    pub a_rwnd: u32,
    pub gap_ack_blocks: Vec<(u16, u16)>,
    pub dup_tsns: Vec<u32>,
}

impl SackChunkValue {
    pub fn decode(reader: &mut BufReader) -> Result<Self, MiniWebrtcRsError> {
        let cumulative_tsn_ack = reader.read_u32()?;
        let a_rwnd = reader.read_u32()?;
        let num_gap_ack_blocks = reader.read_u16()?;
        let num_dup_tsns = reader.read_u16()?;
        let mut gap_ack_blocks = vec![];
        for _ in 0..num_gap_ack_blocks {
            let start = reader.read_u16()?;
            let end = reader.read_u16()?;
            gap_ack_blocks.push((start, end));
        }
        let mut dup_tsns = vec![];
        for _ in 0..num_dup_tsns {
            let tsn = reader.read_u32()?;
            dup_tsns.push(tsn);
        }
        Ok(Self {
            cumulative_tsn_ack,
            a_rwnd,
            gap_ack_blocks,
            dup_tsns,
        })
    }
}

impl From<SackChunkValue> for Vec<u8> {
    fn from(value: SackChunkValue) -> Self {
        let mut writer = BufWriter::new();
        writer.write_u32(value.cumulative_tsn_ack);
        writer.write_u32(value.a_rwnd);
        writer.write_u16(value.gap_ack_blocks.len() as u16);
        writer.write_u16(value.dup_tsns.len() as u16);
        for (start, end) in value.gap_ack_blocks {
            writer.write_u16(start);
            writer.write_u16(end);
        }
        for tsn in value.dup_tsns {
            writer.write_u32(tsn);
        }
        writer.buf()
    }
}
