pub enum ExtensionValue {
    ServerName = 0,
    SupportedEllipticCurves = 10,
    SupportedPointFormats = 11,
    SupportedSignatureAlgorithms = 13,
    UseSrtp = 14,
    ALTP = 16,
    UseExtendedMasterSecret = 23,
    RenegotiationInfo = 65281,
}

impl TryFrom<u16> for ExtensionValue {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ExtensionValue::ServerName),
            10 => Ok(ExtensionValue::SupportedEllipticCurves),
            11 => Ok(ExtensionValue::SupportedPointFormats),
            13 => Ok(ExtensionValue::SupportedSignatureAlgorithms),
            14 => Ok(ExtensionValue::UseSrtp),
            16 => Ok(ExtensionValue::ALTP),
            23 => Ok(ExtensionValue::UseExtendedMasterSecret),
            65281 => Ok(ExtensionValue::RenegotiationInfo),
            _ => Err(format!("invalid extension value: {}", value)),
        }
    }
}
