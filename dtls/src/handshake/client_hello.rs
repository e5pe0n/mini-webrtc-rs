use anyhow::Result;
use tracing::{debug, info};

use crate::{
    cipher_suite::CipherSuiteId,
    extensions::{
        Extension, ExtensionType, renegotiation_info::RenegotiationInfo,
        supported_groups::SupportedGroups, use_extended_master_secret::UseExtendedMasterSecret,
        use_srtp::UseSrtp,
    },
    handshake::random::Random,
    record_header::DtlsVersion,
    {CompressionMethodId, Cookie},
};
use common::buffer::BufReader;

#[derive(Debug)]
pub struct ClientHello {
    pub version: DtlsVersion,
    pub random: Random,
    // session_id: SessionId,
    pub cookie: Option<Cookie>,
    pub cipher_suite_ids: Vec<CipherSuiteId>,
    pub compression_method_ids: Vec<CompressionMethodId>,
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let raw_version = reader.read_u16()?;
        let version = DtlsVersion::try_from(raw_version)?;
        debug!("{version:?}");

        let random = Random::decode(reader)?;
        debug!("{random:?}");

        // ignore session id; not support session resumption
        let session_id_length = reader.read_u8()?;
        debug!("{session_id_length:?}");
        let mut session_id = vec![0u8; session_id_length as usize];
        reader.read_exact(&mut session_id)?;
        debug!("{session_id:?}");

        let cookie_length = reader.read_u8()?;
        debug!("{cookie_length:?}");
        let mut cookie_buf = vec![0u8; cookie_length as usize];
        reader.read_exact(&mut cookie_buf)?;
        debug!("{cookie_buf:?}");

        let cipher_suite_ids_length = reader.read_u16()?;
        debug!("{cipher_suite_ids_length:?}");
        let num_cipher_suite_ids = cipher_suite_ids_length / 2;
        let mut cipher_suite_ids: Vec<CipherSuiteId> = vec![];
        for _ in 0..num_cipher_suite_ids {
            let cipher_suite_id = reader.read_u16()?;
            cipher_suite_ids.push(CipherSuiteId::from(cipher_suite_id));
        }
        debug!("{cipher_suite_ids:?}");

        let num_compression_method_ids = reader.read_u8()?;
        debug!("{num_compression_method_ids:?}");
        let mut compression_method_ids: Vec<CompressionMethodId> = vec![];
        for _ in 0..num_compression_method_ids {
            let compression_method_id = reader.read_u8()?;
            compression_method_ids.push(CompressionMethodId::from(compression_method_id));
        }
        debug!("{compression_method_ids:?}");

        // TODO: decode extensions
        let mut extensions: Vec<Extension> = vec![];
        let extension_map_length = reader.read_u16()? as usize;
        debug!("{extension_map_length:?}");
        let extensions_offset = reader.pos;
        while reader.pos - extensions_offset < extension_map_length {
            let extension_type = ExtensionType::from(reader.read_u16()?);
            debug!("{extension_type:?}");
            let extension_length = reader.read_u16()? as usize;
            debug!("{extension_length:?}");
            let mut extension_data = vec![0u8; extension_length];
            reader.read_exact(&mut extension_data)?;

            let extension: Extension = {
                let mut extension_reader = BufReader::new(&extension_data);
                match extension_type {
                    ExtensionType::UseSrtp => {
                        Extension::UseSrtp(UseSrtp::decode(&mut extension_reader)?)
                    }
                    ExtensionType::SupportedGroups => {
                        Extension::SupportedGroups(SupportedGroups::decode(&mut extension_reader)?)
                    }
                    ExtensionType::UseExtendedMasterSecret => Extension::UseExtendedMasterSecret(
                        UseExtendedMasterSecret::decode(extension_reader)?,
                    ),
                    ExtensionType::RenegotiationInfo => Extension::RenegotiationInfo(
                        RenegotiationInfo::decode(&mut extension_reader)?,
                    ),
                    _ => {
                        info!("ignore unsupported extension; {extension_type:?}");
                        continue;
                    }
                }
            };

            extensions.push(extension);
        }

        Ok(Self {
            version,
            random,
            // session_id,
            cookie: Cookie::try_from(cookie_buf).ok(),
            cipher_suite_ids,
            compression_method_ids,
            extensions,
        })
    }
}
