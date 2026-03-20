mod use_srtp;

use mini_webrtc_derive::FromPrimitive;

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[from(type = "u16", default = "Unsupported")]
pub enum ExtensionType {
    ServerName = 0,
    SupportedEllipticCurves = 10,
    SupportedPointFormats = 11,
    SupportedSignatureAlgorithms = 13,
    UseSrtp = 14,
    ALTP = 16,
    UseExtendedMasterSecret = 23,
    RenegotiationInfo = 65281,
    Unsupported = 65535,
}
