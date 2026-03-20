use anyhow::Result;

use crate::dtls::{buffer::BufReader, common::ECCurve};

#[derive(Debug)]
pub struct SupportedGroups {
    pub curves: Vec<ECCurve>,
}

impl SupportedGroups {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let length = reader.read_u16()? as usize;
        let offset = reader.pos;
        let mut curves = vec![];
        while reader.pos - offset < length {
            let curve = reader.read_u16()?;
            curves.push(ECCurve::from(curve));
        }

        Ok(Self { curves })
    }
}
