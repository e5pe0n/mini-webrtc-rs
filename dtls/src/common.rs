pub struct Cookie(pub Vec<u8>); // 20 bytes

impl Cookie {
    pub fn new() -> Self {
        let mut cookie = [0u8; 20];
        rand::fill(&mut cookie);
        Self(cookie.into())
    }
}

impl TryFrom<Vec<u8>> for Cookie {
    type Error = String;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 20 {
            Err(format!(
                "invalid cookie; expected 20 bytes, but {} bytes",
                value.len(),
            ))
        } else {
            Ok(Cookie(value.into()))
        }
    }
}

pub type SessionId = Vec<u8>;

pub type CipherSuiteId = u16;

pub type CompressionMethodId = u8;
