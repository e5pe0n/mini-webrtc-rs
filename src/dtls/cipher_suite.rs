use mini_webrtc_derive::FromPrimitive;

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[from(type = "u16", default = "Unsupported")]
pub enum CipherSuiteId {
    TlsEcdheEcdsaWithAes128GcmSha256 = 0xc02b,
    Unsupported = 0x0000,
}

impl From<CipherSuiteId> for u16 {
    fn from(value: CipherSuiteId) -> Self {
        value as u16
    }
}
