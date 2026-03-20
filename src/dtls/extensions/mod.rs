pub mod supported_groups;
pub mod use_extended_master_secret;
pub mod use_srtp;

use mini_webrtc_derive::FromPrimitive;

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

pub trait Extension {
    fn get_extension_type(&self) -> ExtensionType;
}
