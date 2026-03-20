pub mod supported_groups;
pub mod use_extended_master_secret;
pub mod use_srtp;

use mini_webrtc_derive::FromPrimitive;

use crate::dtls::extensions::{
    supported_groups::SupportedGroups, use_extended_master_secret::UseExtendedMasterSecret,
    use_srtp::UseSrtp,
};

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, Hash)]
#[from(type = "u16", default = "Unsupported")]
pub enum ExtensionType {
    ServerName = 0,
    SupportedGroups = 10, // renamed from "elliptic_curves"
    SupportedPointFormats = 11,
    SupportedSignatureAlgorithms = 13,
    UseSrtp = 14,
    ALTP = 16,
    UseExtendedMasterSecret = 23,
    RenegotiationInfo = 65281,
    Unsupported = 65535,
}

#[derive(Debug)]
pub enum Extension {
    SupportedGroups(SupportedGroups),
    UseSrtp(UseSrtp),
    UseExtendedMasterSecret(UseExtendedMasterSecret),
    Unsupported,
}

impl Extension {
    pub fn get_extension_type(&self) -> ExtensionType {
        match self {
            Self::SupportedGroups(_) => ExtensionType::SupportedGroups,
            Self::UseSrtp(_) => ExtensionType::UseSrtp,
            Self::UseExtendedMasterSecret(_) => ExtensionType::UseExtendedMasterSecret,
            _ => ExtensionType::Unsupported,
        }
    }
}
