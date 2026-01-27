pub enum HandshakeFlightContext {
    Flight0,
    Flight2(Flight2Context),
}

pub struct Flight2Context {
    cookie: Vec<u8>, // 20 bytes
}

impl Flight2Context {
    pub fn new() -> Self {
        Self {
            cookie: Flight2Context::generate_cookie(),
        }
    }

    fn generate_cookie() -> Vec<u8> {
        let mut cookie = [0u8; 20];
        rand::fill(&mut cookie);
        cookie.into()
    }

    pub fn cookie(&self) -> Vec<u8> {
        self.cookie.clone()
    }
}
