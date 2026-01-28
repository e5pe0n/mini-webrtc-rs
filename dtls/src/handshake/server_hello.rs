use crate::{
    buffer::BufWriter,
    common::{CipherSuiteId, SessionId},
    handshake::random::Random,
    record_header::DtlsVersion,
};

pub struct ServerHello {
    version: DtlsVersion,
    random: Random,
    session_id: SessionId,
    cipher_suite_id: CipherSuiteId,
    // extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn encode(&self, writer: &mut BufWriter) {
        self.version.encode(writer);
        self.random.encode(writer);
    }
}
