use std::time::{Duration, SystemTime};

use crate::buffer::{BufReader, BufWriter};

const RANDOM_BYTES_LENGTH: usize = 28;

#[derive(Debug, Clone, Copy)]
pub struct Random {
    gmt_unix_time: SystemTime,
    random_bytes: [u8; RANDOM_BYTES_LENGTH],
}

impl Random {
    pub fn new() -> Self {
        let mut random_bytes = [0u8; RANDOM_BYTES_LENGTH];
        rand::fill(&mut random_bytes);
        Self {
            gmt_unix_time: SystemTime::now(),
            random_bytes,
        }
    }

    pub fn decode(reader: &mut BufReader) -> Result<Self, String> {
        let gmt_unix_time_u32 = reader.read_u32()?;
        let gmt_unix_time = SystemTime::UNIX_EPOCH + Duration::from_secs(gmt_unix_time_u32 as u64);
        let mut random_bytes = [0u8; RANDOM_BYTES_LENGTH];
        reader.read_exact(&mut random_bytes)?;
        Ok(Self {
            gmt_unix_time,
            random_bytes,
        })
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        let gmt_unix_time_u32 = self
            .gmt_unix_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        writer.write_u32(gmt_unix_time_u32);
        writer.write_bytes(&self.random_bytes.to_vec());
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = BufWriter::new();
        self.encode(&mut writer);
        writer.buf()
    }
}
