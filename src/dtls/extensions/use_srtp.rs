use anyhow::Result;
use crate::common::buffer::{BufReader, BufWriter};

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

    pub fn encode(&self, writer: &mut BufWriter) {
        writer.write_u16((self.srtp_protection_profiles.len() * 2) as u16);
        for profile in &self.srtp_protection_profiles {
            writer.write_u16(profile.value());
        }
        writer.write_u8(self.srtp_mki.len() as u8);
        writer.write_bytes(&self.srtp_mki);
    }
}

// https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SrtpProtectionProfile {
    SrtpAeadAes128Gcm(ProtectionProfile),
    Unsupported,
}

impl SrtpProtectionProfile {
    pub fn value(&self) -> u16 {
        match self {
            Self::SrtpAeadAes128Gcm(profile) => profile.value,
            Self::Unsupported => 0,
        }
    }
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
