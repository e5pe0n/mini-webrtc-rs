pub mod buffer;
pub mod error;

use anyhow::{Result, anyhow};

pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        anyhow::bail!(anyhow!(
            "hex str length should be even; received length={}",
            s.len()
        ))
    } else {
        let mut v: Vec<u8> = vec![];
        for i in (0..s.len()).step_by(2) {
            let u = u8::from_str_radix(&s[i..i + 2], 16)?;
            v.push(u);
        }
        Ok(v)
    }
}
