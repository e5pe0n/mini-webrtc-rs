use anyhow::Result;
use crate::common::buffer::{BufReader, BufWriter};

#[derive(Debug)]
pub struct UseExtendedMasterSecret {}

impl UseExtendedMasterSecret {
    pub fn decode(_: BufReader) -> Result<Self> {
        Ok(Self {})
    }

    pub fn encode(&self, _: &mut BufWriter) {}
}
