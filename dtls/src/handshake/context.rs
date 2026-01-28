use crate::common::Cookie;

pub enum HandshakeFlightContext {
    Flight0,
    Flight2(Flight2Context),
}

#[derive(Debug, Clone)]
pub struct Flight2Context {
    pub cookie: Cookie,
}

impl Flight2Context {
    pub fn new(cookie: Cookie) -> Self {
        Self { cookie }
    }
}
