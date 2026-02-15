use rcgen::{CertifiedKey, KeyPair, SigningKey};
use sha2::{Digest, Sha256};

use crate::{
    buffer::BufWriter,
    common::{AlgoPair, ECCurve, ECCurveType, HashAlgorithm, SignatureAlgorithm},
    handshake::{HandshakeMessage, header::HandshakeType, random::Random},
};

#[derive(Debug)]
pub struct ServerKeyExchange {
    // https://datatracker.ietf.org/doc/html/rfc8422#autoid-18
    // https://datatracker.ietf.org/doc/html/rfc4492#section-5.4
    // ServerECDHParams
    curve_type: ECCurveType,
    curve: ECCurve,
    public_key: Vec<u8>, // ephemeral public key

    // https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4.1
    algo_pair: AlgoPair,
    signature: Vec<u8>,
}

impl ServerKeyExchange {
    pub fn new(
        certified_key: &CertifiedKey<KeyPair>,
        client_random: &Random,
        server_random: &Random,
    ) -> Self {
        let public_key = certified_key.cert.der();
        let private_key = &certified_key.signing_key;

        let mut message_writer = BufWriter::new();
        message_writer.write_bytes(&client_random.to_bytes());
        message_writer.write_bytes(&server_random.to_bytes());
        message_writer.write_u8(ECCurveType::NamedCurve.into());
        message_writer.write_u16(ECCurve::CurveX25519.into());
        message_writer.write_u8(public_key.len() as u8);
        message_writer.write_bytes(public_key);

        let message_buf = message_writer.buf_ref();
        let hashed = Sha256::digest(message_buf);
        let signature = private_key.sign(&hashed).unwrap();

        // TODO: support others
        Self {
            curve_type: ECCurveType::NamedCurve,
            curve: ECCurve::CurveX25519,
            public_key: public_key.to_vec(),
            algo_pair: AlgoPair {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Ecdsa,
            },
            signature: signature,
        }
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        writer.write_u8(self.curve_type.into());
        writer.write_u16(self.curve.into());
        writer.write_u8(self.public_key.len() as u8);
        writer.write_bytes(&self.public_key);
        self.algo_pair.encode(writer);
        writer.write_u16(self.signature.len() as u16);
        writer.write_bytes(&self.signature);
    }
}

impl HandshakeMessage for ServerKeyExchange {
    fn get_handshake_type(&self) -> super::header::HandshakeType {
        HandshakeType::ServerKeyExchange
    }

    fn encode(&self, writer: &mut BufWriter) {
        self.encode(writer);
    }
}
