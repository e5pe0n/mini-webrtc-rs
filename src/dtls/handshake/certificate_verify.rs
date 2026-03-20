use anyhow::Result;

use crate::dtls::{
    buffer::BufReader,
    common::{AlgoPair, HashAlgorithm, SignatureAlgorithm},
};

pub struct CertificateVerify {
    pub algo_pair: AlgoPair,
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let hash_algo = reader.read_u8()?;
        let signature_algo = reader.read_u8()?;
        let signature_length = reader.read_u16()? as usize;
        let mut signature = vec![0u8; signature_length];
        reader.read_exact(&mut signature);
        Ok(Self {
            algo_pair: AlgoPair {
                hash: HashAlgorithm::from(hash_algo),
                signature: SignatureAlgorithm::from(signature_algo),
            },
            signature,
        })
    }
}
