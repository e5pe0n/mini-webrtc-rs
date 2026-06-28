use mini_webrtc_derive::FromPrimitive;

use crate::{
    common::{
        buffer::{BufReader, BufWriter},
        error::MiniWebrtcRsError,
    },
    sctp::chunk::{ChunkHeader, ChunkType},
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
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DataChunkValue {
    pub tsn: u32,
    pub stream_id: u16,
    pub stream_seq_num: u16,
    pub payload_protocol: PayloadProtocol,
    pub user_data: Vec<u8>,
}

impl DataChunk {
    pub fn new(header: Option<ChunkHeader>, value: DataChunkValue) -> Self {
        let mut header = header.unwrap_or(ChunkHeader::new(ChunkType::Data, 0b0000_0011, 0));
        let encoded_value: Vec<u8> = value.clone().into();
        let chunk_length = (header.raw.len() + encoded_value.len()) as u16;
        header.update_chunk_length(chunk_length);

        let mut writer = BufWriter::new();
        writer.write_bytes(&header.raw);
        writer.write_bytes(&encoded_value);

        let padding = (4 - (chunk_length as usize % 4)) % 4;
        for _ in 0..padding {
            writer.write_u8(0);
        }

        Self {
            header,
            value,
            raw: writer.buf(),
        }
    }
}

impl DataChunkValue {
    pub fn decode(reader: &mut BufReader, value_length: u16) -> Result<Self, MiniWebrtcRsError> {
        let tsn = reader.read_u32()?;
        let stream_id = reader.read_u16()?;
        let stream_seq_num = reader.read_u16()?;
        let payload_protocol_id = reader.read_u32()?;
        let payload_protocol = PayloadProtocol::from(payload_protocol_id);

        let mut user_data = vec![0u8; value_length as usize - 12];
        reader.read_exact(&mut user_data)?;
        Ok(Self {
            tsn,
            stream_id,
            stream_seq_num,
            payload_protocol,
            user_data,
        })
    }
}

impl From<DataChunkValue> for Vec<u8> {
    fn from(value: DataChunkValue) -> Self {
        let mut writer = BufWriter::new();
        writer.write_u32(value.tsn);
        writer.write_u16(value.stream_id);
        writer.write_u16(value.stream_seq_num);
        writer.write_u32(value.payload_protocol.into());
        writer.write_bytes(&value.user_data);

        writer.buf()
    }
}

#[derive(FromPrimitive)]
#[from(type = "u32", default = "Unsupported")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadProtocol {
    WebrtcDcep = 50,
    WebrtcString = 51,
    WebrtcBinary = 53,
    WebrtcStringEmpty = 56,
    WebrtcBinaryEmpty = 57,
    Unsupported = 0,
}

impl From<PayloadProtocol> for u32 {
    fn from(value: PayloadProtocol) -> Self {
        value as u32
    }
}
