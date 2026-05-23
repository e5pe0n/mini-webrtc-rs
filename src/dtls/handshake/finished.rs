use crate::dtls::handshake::{HandshakeMessage, header::HandshakeType};
use crate::common::buffer::BufWriter;

pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl HandshakeMessage for Finished {
    fn get_handshake_type(&self) -> HandshakeType {
        HandshakeType::Finished
    }

    fn encode(&self, writer: &mut BufWriter) {
        writer.write_bytes(&self.verify_data);
    }
}
