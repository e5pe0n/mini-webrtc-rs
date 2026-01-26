use crate::{buffer::BufReader, record_header::DtlsVersion};

struct HelloVerifyRequest {
    version: DtlsVersion,
    cookie: Vec<u8>,
}

impl HelloVerifyRequest {
    pub fn decode(reader: &mut BufReader) -> Result<Self, String> {
        let version_u16 = reader.read_u16()?;
        let version = DtlsVersion::try_from(version_u16)?;

        let cookie_length = reader.read_u8()?;
        let mut cookie = vec![0u8; cookie_length as usize];
        reader.read_exact(&mut cookie)?;

        Ok(Self { version, cookie })
    }
}
