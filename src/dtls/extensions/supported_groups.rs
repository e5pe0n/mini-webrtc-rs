use anyhow::Result;

use crate::dtls::{
    buffer::BufReader,
    common::ECCurve,
    extensions::{Extension, ExtensionType},
};

pub struct SupportedGroups {
    curves: Vec<ECCurve>,
}

impl SupportedGroups {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let length = reader.read_u16()? as usize;
        let offset = reader.pos;
        let mut curves = vec![];
        loop {
            let curve = reader.read_u16()?;
            curves.push(ECCurve::from(curve));
            if offset + reader.pos >= length {
                break;
            }
        }

        Ok(Self { curves })
    }
}

impl Extension for SupportedGroups {
    fn get_extension_type(&self) -> super::ExtensionType {
        ExtensionType::SupportedGroups
    }
}
