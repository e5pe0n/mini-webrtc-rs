use std::collections::HashMap;

use anyhow::Result;
use tracing::info;

use crate::dtls::{
    buffer::BufReader,
    common::{CipherSuiteId, CompressionMethodId, Cookie},
    extensions::{Extension, ExtensionType, use_srtp::UseSrtp},
    handshake::random::Random,
    record_header::DtlsVersion,
};

pub struct ClientHello {
    pub version: DtlsVersion,
    pub random: Random,
    // session_id: SessionId,
    pub cookie: Cookie,
    pub cipher_suite_ids: Vec<CipherSuiteId>,
    pub compression_method_ids: Vec<CompressionMethodId>,
    // extensions: Vec<Extension>,
}

impl ClientHello {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let raw_version = reader.read_u16()?;
        let version = DtlsVersion::try_from(raw_version)?;

        let random = Random::decode(reader)?;
        // ignore session id; not support session resumption
        let session_id_length = reader.read_u8()?;
        let mut session_id = vec![0u8; session_id_length as usize];
        reader.read_exact(&mut session_id)?;

        let cookie_length = reader.read_u8()?;
        let mut cookie_buf = vec![0u8; cookie_length as usize];
        reader.read_exact(&mut cookie_buf)?;

        let cipher_suite_ids_length = reader.read_u16()?;
        let num_cipher_suite_ids = cipher_suite_ids_length / 2;
        let mut cipher_suite_ids: Vec<CipherSuiteId> = vec![];
        for _ in 0..num_cipher_suite_ids {
            let cipher_suite_id = reader.read_u16()?;
            cipher_suite_ids.push(CipherSuiteId::from(cipher_suite_id));
        }

        let num_compression_method_ids = reader.read_u8()?;
        let mut compression_method_ids: Vec<CompressionMethodId> = vec![];
        for _ in 0..num_compression_method_ids {
            let compression_method_id = reader.read_u8()?;
            compression_method_ids.push(CompressionMethodId::from(compression_method_id));
        }

        // TODO: decode extensions
        let mut extensions: HashMap<ExtensionType, Box<dyn Extension>> = HashMap::new();
        let extension_map_length = reader.read_u16()? as usize;
        let extensions_offset = reader.pos;
        loop {
            let extension_type = ExtensionType::from(reader.read_u16()?);
            let extension_length = reader.read_u16()?;
            let mut extension_value = vec![0u8; extension_length as usize];
            reader.read_exact(&mut extension_value);
            match extension_type {
                ExtensionType::UseSrtp => {
                    let extension = UseSrtp::decode(reader)?;
                    extensions.insert(extension_type, Box::new(extension));
                }
                _ => {
                    info!("ignore unsupported extension; {extension_type:?}");
                    continue;
                }
            }
            if reader.pos - extensions_offset >= extension_map_length {
                break;
            }
        }

        Ok(Self {
            version,
            random,
            // session_id,
            cookie: Cookie::try_from(cookie_buf)?,
            cipher_suite_ids,
            compression_method_ids,
        })
    }
}
