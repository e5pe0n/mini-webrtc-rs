use rcgen::{CertifiedKey, KeyPair, generate_simple_self_signed};
use sha2::{
    Digest, Sha256,
    digest::generic_array::{GenericArray, typenum::U32},
};

struct DtlsServer {
    certified_key: CertifiedKey<KeyPair>,
    fingerprint: GenericArray<u8, U32>,
}

impl DtlsServer {
    pub fn new() -> Self {
        let certified_key = generate_simple_self_signed(vec![]).unwrap();
        let fingerprint = Sha256::digest(certified_key.cert.der());

        DtlsServer {
            certified_key,
            fingerprint,
        }
    }
}

fn main() {
    DtlsServer::new();
}
