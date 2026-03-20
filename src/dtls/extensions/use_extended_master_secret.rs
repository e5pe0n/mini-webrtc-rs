use crate::dtls::buffer::BufReader;
use anyhow::Result;

#[derive(Debug)]
pub struct UseExtendedMasterSecret {}

impl UseExtendedMasterSecret {
    pub fn decode(_: BufReader) -> Result<Self> {
        Ok(Self {})
    }
}
