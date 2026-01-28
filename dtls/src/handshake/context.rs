pub enum HandshakeFlightContext {
    Flight0,
    Flight2(Flight2Context),
}

pub struct Flight2Context {
    pub cookie: Vec<u8>, // 20 bytes
}

impl Flight2Context {
    pub fn new(cookie: Vec<u8>) -> Self {
        Self { cookie }
    }
}
