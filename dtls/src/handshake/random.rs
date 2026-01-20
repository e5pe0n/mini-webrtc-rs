use std::time::{Duration, SystemTime};

use crate::buffer::BufReader;

const RANDOM_BYTES_LENGTH: usize = 28;

pub struct Random {
    gmt_unix_time: SystemTime,
    random_bytes: [u8; RANDOM_BYTES_LENGTH],
}

impl Random {
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
}
