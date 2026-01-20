use std::time::SystemTime;

const RANDOM_BYTES_LENGTH: usize = 28;

pub struct Random {
    gmt_unix_time: SystemTime,
    random_bytes: [u8; RANDOM_BYTES_LENGTH],
}
