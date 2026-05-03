// https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SrtpProtectionProfile {
    SrtpAeadAes128Gcm(ProtectionProfile),
    Unsupported,
}

impl From<u16> for SrtpProtectionProfile {
    fn from(value: u16) -> Self {
        match value {
            0x0007 => Self::SrtpAeadAes128Gcm(ProtectionProfile {
                value,
                key_length: 16,
                salt_length: 12,
                aead_auth_tag_length: 16,
            }),
            _ => Self::Unsupported,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ProtectionProfile {
    pub value: u16,
    pub key_length: usize,
    pub salt_length: usize,
    pub aead_auth_tag_length: usize,
}

pub struct SrtpEncryptionKeys {
    pub server_master_key: Vec<u8>,
    pub server_master_salt: Vec<u8>,
    pub client_master_key: Vec<u8>,
    pub client_master_salt: Vec<u8>,
}
