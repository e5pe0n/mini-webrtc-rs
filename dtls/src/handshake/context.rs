use x25519_dalek::EphemeralSecret;

use crate::{common::Cookie, handshake::random::Random};

impl std::fmt::Debug for HandshakeFlightContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeFlightContext::Flight0 => write!(f, "Flight0"),
            HandshakeFlightContext::Flight4(ctx) => f.debug_tuple("Flight4").field(ctx).finish(),
            HandshakeFlightContext::Flight6(ctx) => f.debug_tuple("Flight6").field(ctx).finish(),
        }
    }
}

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

impl std::fmt::Debug for Flight6Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flight6Context")
            .field("ephemeral_secret", &"<secret>")
            .field("client_random", &self.client_random)
            .field("server_random", &self.server_random)
            .finish()
    }
}

pub struct Flight6Context {
    pub ephemeral_secret: EphemeralSecret,
    pub client_random: Random,
    pub server_random: Random,
}
