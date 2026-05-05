use anyhow::Result;
use common::buffer::BufReader;

#[derive(Debug)]
pub struct UseExtendedMasterSecret {}

impl UseExtendedMasterSecret {
    pub fn decode(_: BufReader) -> Result<Self> {
        Ok(Self {})
    }
}
