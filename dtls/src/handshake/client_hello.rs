use crate::{handshake::random::Random, record_header::DtlsVersion};

struct ClientHello {
    version: DtlsVersion,
    random: Random,
}
