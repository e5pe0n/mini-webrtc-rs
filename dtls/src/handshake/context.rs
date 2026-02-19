use x25519_dalek::EphemeralSecret;

use crate::common::Cookie;

pub enum HandshakeFlightContext {
    Flight0,
    Flight4(Flight4Context),
    Flight6(Flight6Context),
}

#[derive(Debug, Clone)]
pub struct Flight4Context {
    pub cookie: Cookie,
}

impl Flight4Context {
    pub fn new(cookie: Cookie) -> Self {
        Self { cookie }
    }
}

pub struct Flight6Context {
    pub secret: EphemeralSecret,
}

impl Flight6Context {
    pub fn new(secret: EphemeralSecret) -> Flight6Context {
        Self { secret }
    }
}
