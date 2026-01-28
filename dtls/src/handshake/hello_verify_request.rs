use crate::{
    buffer::{BufReader, BufWriter},
    common::Cookie,
    record_header::DtlsVersion,
};

pub struct HelloVerifyRequest {
    pub version: DtlsVersion,
    pub cookie: Cookie,
}

impl HelloVerifyRequest {
    pub fn new(version: DtlsVersion) -> Self {
        Self {
            version,
            cookie: Cookie::new(),
        }
    }

    pub fn decode(reader: &mut BufReader) -> Result<Self, String> {
        let version_u16 = reader.read_u16()?;
        let version = DtlsVersion::try_from(version_u16)?;

        let cookie_length = reader.read_u8()?;
        let mut cookie_buf = vec![0u8; cookie_length as usize];
        reader.read_exact(&mut cookie_buf)?;

        Ok(Self {
            version,
            cookie: Cookie::try_from(cookie_buf)?,
        })
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        self.version.encode(writer);
        writer.write_u8(self.cookie.0.len() as u8);
        for byte in &self.cookie.0 {
            writer.write_u8(*byte);
        }
    }
}
