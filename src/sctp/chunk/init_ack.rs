use crate::{
    common::{
        buffer::{BufReader, BufWriter},
        error::MiniWebrtcRsError,
    },
    sctp::chunk::{ChunkHeader, ChunkParam, ChunkType},
};
use anyhow::Result;

// https://datatracker.ietf.org/doc/html/rfc9260#name-initiation-acknowledgement-
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Type = 2    |  Chunk Flags  |         Chunk Length          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Initiate Tag                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Advertised Receiver Window Credit               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Number of Outbound Streams   |   Number of Inbound Streams   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Initial TSN                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// \                                                               \
// /              Optional/Variable-Length Parameters              /
// \                                                               \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub struct InitAckChunk {
    pub header: ChunkHeader,
    pub value: InitAckChunkValue,
    pub raw: Vec<u8>,
}

impl InitAckChunk {
    pub fn new(value: InitAckChunkValue) -> Self {
        let mut header = ChunkHeader::new(ChunkType::InitAck, 0, 0);
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
pub struct InitAckChunkValue {
    pub init_tag: u32,
    pub a_rwnd: u32,
    pub num_outbound_streams: u16,
    pub num_inbound_streams: u16,
    pub init_tsn: u32,
    pub params: Vec<ChunkParam>,
}

impl From<InitAckChunkValue> for Vec<u8> {
    fn from(value: InitAckChunkValue) -> Self {
        let mut writer = BufWriter::new();
        writer.write_u32(value.init_tag);
        writer.write_u32(value.a_rwnd);
        writer.write_u16(value.num_outbound_streams);
        writer.write_u16(value.num_inbound_streams);
        writer.write_u32(value.init_tsn);
        for param in value.params {
            param.encode(&mut writer);
        }
        writer.buf()
    }
}

impl InitAckChunkValue {
    // pub fn encode(&self, writer: &mut BufWriter) -> Result<Vec<u8>, MiniWebrtcRsError> {
    //     writer.write_u32(self.init_tag);
    //     writer.write_u32(self.a_rwnd);
    //     writer.write_u16(self.num_outbound_streams);
    //     writer.write_u16(self.num_inbound_streams);
    //     writer.write_u32(self.init_tsn);
    //     for param in self.params {}
    // }

    pub fn decode(reader: &mut BufReader) -> Result<Self, MiniWebrtcRsError> {
        let init_tag = reader.read_u32()?;
        let a_rwnd = reader.read_u32()?;
        let num_outbound_streams = reader.read_u16()?;
        let num_inbound_streams = reader.read_u16()?;
        let init_tsn = reader.read_u32()?;

        let mut params = vec![];
        while reader.rest_len() > 0 {
            let param = ChunkParam::decode(reader)?;
            params.push(param);
        }

        Ok(Self {
            init_tag,
            a_rwnd,
            num_outbound_streams,
            num_inbound_streams,
            init_tsn,
            params,
        })
    }
}
