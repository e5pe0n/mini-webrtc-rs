use anyhow::Result;
use common::buffer::BufReader;

// https://datatracker.ietf.org/doc/html/rfc5764
#[derive(Debug)]
pub struct UseSrtp {
    pub srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    pub srtp_mki: Vec<u8>, // master key identifier
}

impl UseSrtp {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let profiles_length = reader.read_u16()?;
        let mut profiles = vec![];
        for _ in 0..profiles_length / 2 {
            profiles.push(SrtpProtectionProfile::from(reader.read_u16()?));
        }

        let mki_length = reader.read_u8()?;
        let mut mki = vec![0u8; mki_length as usize];
        reader.read_exact(&mut mki)?;

        Ok(Self {
            srtp_protection_profiles: profiles,
            srtp_mki: mki.to_vec(),
        })
    }
}

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
