use crate::{
    common::{buffer::BufReader, error::MiniWebrtcRsError},
    sctp::chunk::ChunkHeader,
};

// https://datatracker.ietf.org/doc/html/rfc9260#name-payload-data-data-0
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Type = 0    |  Res  |I|U|B|E|            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              TSN                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Stream Identifier S      |   Stream Sequence Number n    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Payload Protocol Identifier                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// \                                                               \
// /                 User Data (seq n of Stream S)                 /
// \                                                               \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct DataChunk {
    pub header: ChunkHeader,
    pub value: DataChunkValue,
}

#[derive(Debug)]
pub struct DataChunkValue {
    pub tsn: u32,
    pub stream_id: u16,
    pub stream_seq_num: u16,
    pub payload_protocol_id: u32,
    pub user_data: Vec<u8>,
}

impl DataChunkValue {
    pub fn decode(reader: &mut BufReader, value_length: u16) -> Result<Self, MiniWebrtcRsError> {
        let tsn = reader.read_u32()?;
        let stream_id = reader.read_u16()?;
        let stream_seq_num = reader.read_u16()?;
        let payload_protocol_id = reader.read_u32()?;

        let mut user_data = vec![0u8; value_length as usize - 12];
        reader.read_exact(&mut user_data)?;
        Ok(Self {
            tsn,
            stream_id,
            stream_seq_num,
            payload_protocol_id,
            user_data,
        })
    }
}
