pub mod init;

use anyhow::{Result, anyhow};
use mini_webrtc_derive::FromPrimitive;

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

pub trait Chunk {
    fn get_chunk_type() -> ChunkType;
    fn get_chunk_length(&self) -> u16;
}
