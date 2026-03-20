use anyhow::Result;
use mini_webrtc_derive::FromPrimitive;

use crate::dtls::{
    buffer::BufReader,
    extensions::{Extension, ExtensionType},
};

// https://datatracker.ietf.org/doc/html/rfc5764
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

        let mki_length = reader.read_u16()?;
        let mut mki = vec![0u8; mki_length as usize];
        reader.read_exact(&mut mki);

        Ok(Self {
            srtp_protection_profiles: profiles,
            srtp_mki: mki.to_vec(),
        })
    }
}

impl Extension for UseSrtp {
    fn get_extension_type(&self) -> ExtensionType {
        ExtensionType::UseSrtp
    }
}

// https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[from(type = "u16", default = "Unsupported")]
pub enum SrtpProtectionProfile {
    SrtpAeadAes128Gcm = 0x0007,
    Unsupported = 0x0000,
}
