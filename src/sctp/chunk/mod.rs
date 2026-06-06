pub mod init;

use anyhow::{Result, anyhow};
use mini_webrtc_derive::FromPrimitive;

use crate::{
    common::{buffer::BufReader, error::MiniWebrtcRsError},
    sctp::chunk::init::{InitChunk, InitChunkValue},
};

#[derive(FromPrimitive)]
#[from(type = "u8", default = "Unsupported")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChunkType {
    Data = 0,
    Init = 1,
    InitAck = 2,
    Sack = 3,
    Heartbeat = 4,
    HeartbeatAck = 5,
    Abort = 6,
    Shutdown = 7,
    ShutdownAck = 8,
    Error = 9,
    CookieEcho = 10,
    CookieAck = 11,
    ShutdownComplete = 14,
    Unsupported = 255,
}

pub enum Chunk {
    Init(InitChunk),
}

impl Chunk {
    pub fn decode(reader: &mut BufReader) -> Result<Self, MiniWebrtcRsError> {
        let header = ChunkHeader::decode(reader)?;

        match header.chunk_type {
            ChunkType::Init => {
                let value = InitChunkValue::decode(reader)?;
                Ok(Chunk::Init(InitChunk { header, value }))
            }
            _ => Err(MiniWebrtcRsError::NotImplementedError {
                message: format!("{:?}", header.chunk_type),
            }),
        }
    }
}

pub struct ChunkHeader {
    pub chunk_type: ChunkType,
    pub chunk_flags: u8,
    pub chunk_length: u16,
}

impl ChunkHeader {
    pub fn decode(reader: &mut BufReader) -> Result<Self, MiniWebrtcRsError> {
        let chunk_type = ChunkType::from(reader.read_u8()?);
        let chunk_flags = reader.read_u8()?;
        let chunk_length = reader.read_u16()?;

        Ok(Self {
            chunk_type,
            chunk_flags,
            chunk_length,
        })
    }
}

pub trait ChunkTrait {
    fn get_chunk_type(&self) -> ChunkType;
    fn get_chunk_length(&self) -> u16;
}
