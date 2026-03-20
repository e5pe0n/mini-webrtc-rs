use crate::dtls::{
    buffer::BufReader,
    extensions::{Extension, ExtensionType},
};
use anyhow::Result;

pub struct UseExtendedMasterSecret {}

impl UseExtendedMasterSecret {
    pub fn decode(_: BufReader) -> Result<Self> {
        Ok(Self {})
    }
}

impl Extension for UseExtendedMasterSecret {
    fn get_extension_type(&self) -> ExtensionType {
        ExtensionType::UseExtendedMasterSecret
    }
}
