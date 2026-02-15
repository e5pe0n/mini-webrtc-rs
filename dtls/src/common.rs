use crate::buffer::BufWriter;

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

#[derive(Debug, Clone, Copy)]
pub enum ECCurveType {
    // https://datatracker.ietf.org/doc/html/rfc4492#section-5.4
    NamedCurve = 0x03,
}

impl From<ECCurveType> for u8 {
    fn from(value: ECCurveType) -> Self {
        value as u8
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ECCurve {
    Unsupported = 0x0000,
    X25519 = 0x001d,
}

impl From<ECCurve> for u16 {
    fn from(value: ECCurve) -> Self {
        value as u16
    }
}

#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    // https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4.1
    Sha256 = 4,
    // Unsupported,
}

impl From<HashAlgorithm> for u8 {
    fn from(value: HashAlgorithm) -> Self {
        value as u8
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SignatureAlgorithm {
    // https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4.1
    Ecdsa = 3,
    // Unsupported,
}

impl From<SignatureAlgorithm> for u8 {
    fn from(value: SignatureAlgorithm) -> Self {
        value as u8
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CertificateType {
    Ecdsa = 64,
}

impl From<CertificateType> for u8 {
    fn from(value: CertificateType) -> Self {
        value as u8
    }
}

#[derive(Debug)]
pub struct AlgoPair {
    pub hash: HashAlgorithm,
    pub signature: SignatureAlgorithm,
}

impl AlgoPair {
    pub fn encode(&self, writer: &mut BufWriter) {
        writer.write_u8(self.hash.into());
        writer.write_u8(self.signature.into());
    }
}
