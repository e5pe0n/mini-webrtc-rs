#[derive(Debug, Clone)]
pub struct Cookie(pub Vec<u8>); // 20 bytes

impl Cookie {
    pub fn new() -> Self {
        let mut cookie = [0u8; 20];
        rand::fill(&mut cookie);
        Self(cookie.into())
    }
}

impl TryFrom<Vec<u8>> for Cookie {
    type Error = String;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 20 {
            Err(format!(
                "invalid cookie; expected 20 bytes, but {} bytes",
                value.len(),
            ))
        } else {
            Ok(Cookie(value.into()))
        }
    }
}

pub type SessionId = Vec<u8>;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CipherSuiteId {
    TlsEcdheEcdheWithAes128GcmSha256 = 0xc02b,
    Unsupported,
}

impl From<u16> for CipherSuiteId {
    fn from(value: u16) -> Self {
        match value {
            0xc02b => CipherSuiteId::TlsEcdheEcdheWithAes128GcmSha256,
            _ => CipherSuiteId::Unsupported,
        }
    }
}

impl From<CipherSuiteId> for u16 {
    fn from(value: CipherSuiteId) -> Self {
        value as u16
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CompressionMethodId {
    Null = 0,
    Unsupported,
}

impl From<u8> for CompressionMethodId {
    fn from(value: u8) -> Self {
        match value {
            0 => CompressionMethodId::Null,
            _ => CompressionMethodId::Unsupported,
        }
    }
}

impl From<CompressionMethodId> for u8 {
    fn from(value: CompressionMethodId) -> Self {
        value as u8
    }
}
