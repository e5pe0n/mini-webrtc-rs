use anyhow::{Result, anyhow};
use hmac::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256, digest::generic_array::typenum::U32};
use x25519_dalek::{EphemeralSecret, PublicKey};

use mini_webrtc_derive::FromPrimitive;

use crate::dtls::buffer::BufWriter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie(pub Vec<u8>); // 20 bytes

impl Cookie {
    pub fn new() -> Self {
        let mut cookie = [0u8; 20];
        rand::fill(&mut cookie);
        Self(cookie.into())
    }
}

impl TryFrom<Vec<u8>> for Cookie {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        if value.len() != 20 {
            Err(anyhow!(
                "invalid cookie; expected 20 bytes, but {} bytes",
                value.len(),
            ))
        } else {
            Ok(Cookie(value.into()))
        }
    }
}

pub type SessionId = Vec<u8>;

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[from(type = "u8", default = "Unsupported")]
pub enum CompressionMethodId {
    Null = 0,
    Unsupported = 0xff,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[from(type = "u16", default = "Unsupported")]
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

pub struct CurveKeyPair {
    pub public_key: PublicKey,
    pub secret: EphemeralSecret,
}

pub fn generate_curve_key_pair() -> CurveKeyPair {
    // generate X25519 key pair
    let secret = EphemeralSecret::random();
    let public_key = PublicKey::from(&secret);
    CurveKeyPair { public_key, secret }
}

#[derive(Debug, Clone)]
pub struct Fingerprint(pub GenericArray<u8, U32>);

impl Fingerprint {
    pub fn new(data: &[u8]) -> Self {
        Self(Sha256::digest(data))
    }

    pub fn to_string(&self) -> String {
        self.0
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}
