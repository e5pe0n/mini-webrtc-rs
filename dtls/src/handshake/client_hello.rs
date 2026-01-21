use crate::{buffer::BufReader, handshake::random::Random, record_header::DtlsVersion};

struct ClientHello {
    version: DtlsVersion,
    random: Random,
    session_id: Vec<u8>,
    cookie: Vec<u8>,
    cipher_suite_ids: Vec<u16>,
    compression_method_ids: Vec<u8>,
    // extensions: Vec<Extension>,
}

impl ClientHello {
    pub fn decode(reader: &mut BufReader) -> Result<Self, String> {
        let raw_version = reader.read_u16()?;
        let version = DtlsVersion::try_from(raw_version)?;

        let random = Random::decode(reader)?;

        let session_id_length = reader.read_u8()?;
        let mut session_id = vec![0u8; session_id_length as usize];
        reader.read_exact(&mut session_id)?;

        let cookie_length = reader.read_u8()?;
        let mut cookie = vec![0u8; cookie_length as usize];
        reader.read_exact(&mut cookie)?;

        let cipher_suite_ids_length = reader.read_u16()?;
        let num_cipher_suite_ids = cipher_suite_ids_length / 2;
        let mut cipher_suite_ids = vec![0u16; num_cipher_suite_ids as usize];
        for i in 0..num_cipher_suite_ids {
            let cipher_suite_id = reader.read_u16()?;
            cipher_suite_ids[i as usize] = cipher_suite_id;
        }

        let num_compression_method_ids = reader.read_u8()?;
        let mut compression_method_ids = vec![0u8; num_compression_method_ids as usize];
        for i in 0..num_compression_method_ids {
            let compression_method_id = reader.read_u8()?;
            compression_method_ids[i as usize] = compression_method_id;
        }

        // TODO: decode extensions

        Ok(Self {
            version,
            random,
            session_id,
            cookie,
            cipher_suite_ids,
            compression_method_ids,
        })
    }
}
