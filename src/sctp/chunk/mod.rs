pub mod cookie_ack;
pub mod cookie_echo;
pub mod data;
pub mod init;
pub mod init_ack;
pub mod sack;

use anyhow::Result;
use mini_webrtc_derive::FromPrimitive;
use tracing::warn;

use crate::{
    common::{
        buffer::{BufReader, BufWriter, RefBufWriter},
        error::MiniWebrtcRsError,
    },
    sctp::chunk::{
        cookie_echo::{CookieEchoChunk, CookieEchoChunkValue},
        data::DataChunk,
        init::{InitChunk, InitChunkValue},
        sack::{SackChunk, SackChunkValue},
    },
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

impl From<ChunkType> for u8 {
    fn from(value: ChunkType) -> Self {
        value as u8
    }
}

#[derive(Debug)]
pub enum Chunk {
    Data(DataChunk),
    Init(InitChunk),
    CookieEcho(CookieEchoChunk),
    Sack(SackChunk),
    NotImplemented,
}

impl Chunk {
    pub fn decode(reader: &mut BufReader) -> Result<Self, MiniWebrtcRsError> {
        let header = ChunkHeader::decode(reader)?;

        match header.chunk_type {
            ChunkType::Init => {
                let value = InitChunkValue::decode(reader)?;
                Ok(Chunk::Init(InitChunk { header, value }))
            }
            ChunkType::CookieEcho => {
                let cookie_length = header.chunk_length - COOKIE_LENGTH_IN_BYTES;
                let value = CookieEchoChunkValue::decode(reader, cookie_length)?;
                Ok(Chunk::CookieEcho(CookieEchoChunk { header, value }))
            }
            ChunkType::Sack => {
                let value = SackChunkValue::decode(reader)?;
                Ok(Chunk::Sack(SackChunk::new(Some(header), value)))
            }
            _ => Err(MiniWebrtcRsError::NotImplementedError {
                message: format!("{:?}", header.chunk_type),
            }),
        }
    }
}

pub const CHUNK_HEADER_LENGTH_IN_BYTES: usize = 4;

#[derive(Debug)]
pub struct ChunkHeader {
    pub chunk_type: ChunkType,
    pub chunk_flags: u8,
    pub chunk_length: u16,
    pub raw: Vec<u8>,
}

impl ChunkHeader {
    pub fn new(chunk_type: ChunkType, chunk_flags: u8, chunk_length: u16) -> Self {
        let mut writer = BufWriter::new();
        writer.write_u8(chunk_type.into());
        writer.write_u8(chunk_flags);
        writer.write_u16(chunk_length);
        Self {
            chunk_type,
            chunk_flags,
            chunk_length,
            raw: writer.buf(),
        }
    }

    pub fn update_chunk_length(&mut self, chunk_length: u16) {
        self.chunk_length = chunk_length;

        let mut writer = RefBufWriter::new(&mut self.raw);
        writer.write_u16_at(chunk_length, 3);
    }

    pub fn decode(reader: &mut BufReader) -> Result<Self, MiniWebrtcRsError> {
        reader.start();
        let chunk_type = ChunkType::from(reader.read_u8()?);
        let chunk_flags = reader.read_u8()?;
        let chunk_length = reader.read_u16()?;
        let raw = reader.clone_from_start();

        Ok(Self {
            chunk_type,
            chunk_flags,
            chunk_length,
            raw,
        })
    }
}

pub trait ChunkTrait {
    fn get_chunk_type(&self) -> ChunkType;
    fn get_chunk_length(&self) -> u16;
}

pub const COOKIE_LENGTH_IN_BYTES: u16 = 32;

#[derive(Debug, Clone)]
pub enum ChunkParam {
    StateCookie(Vec<u8>),
    Unsupported(u16),
}

impl From<ChunkParam> for Vec<u8> {
    fn from(value: ChunkParam) -> Self {
        let mut writer = BufWriter::new();
        match value {
            ChunkParam::StateCookie(cookie) => {
                writer.write_u16(7);
                writer.write_u16(cookie.len() as u16);
                writer.write_bytes(&cookie);
            }
            _ => {
                warn!("unsupported chunk params: {:?}", value);
            }
        }
        writer.buf()
    }
}

impl ChunkParam {
    pub fn encode(&self, writer: &mut BufWriter) {
        match self {
            ChunkParam::StateCookie(cookie) => {
                writer.write_u16(7);
                writer.write_u16(cookie.len() as u16);
                writer.write_bytes(cookie);
            }
            _ => {}
        }
    }

    pub fn decode(reader: &mut BufReader) -> Result<Self, MiniWebrtcRsError> {
        let param_type = reader.read_u16()?;
        let length = reader.read_u16()?;
        let mut value = vec![0u8; length as usize];
        reader.read_exact(&mut value)?;

        match param_type {
            7 => Ok(ChunkParam::StateCookie(value)),
            n => Ok(ChunkParam::Unsupported(n)),
        }
    }
}
