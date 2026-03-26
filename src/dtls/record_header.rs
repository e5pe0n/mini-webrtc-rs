use crate::dtls::buffer::{BufReader, BufWriter};
use mini_webrtc_derive::TryFromPrimitive;

use anyhow::anyhow;

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
#[derive(TryFromPrimitive)]
#[try_from(type = "u8")]
#[derive(Debug, Clone, Copy)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

const DTLS_VERSION_1_0: u16 = 0xfeff;
const DTLS_VERSION_1_2: u16 = 0xfefd;

#[derive(Debug)]
pub struct DtlsVersion {
    pub major: u8,
    pub minor: u8,
}

impl TryFrom<u16> for DtlsVersion {
    type Error = anyhow::Error;

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            DTLS_VERSION_1_0 => Ok(DtlsVersion { major: 1, minor: 0 }),
            DTLS_VERSION_1_2 => Ok(DtlsVersion { major: 1, minor: 2 }),
            _ => Err(anyhow!("invalid dtls version: {}", val)),
        }
    }
}

impl DtlsVersion {
    pub fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        writer.write_u8(self.major);
        writer.write_u8(self.minor);
    }
}

pub struct RecordHeader {
    pub content_type: ContentType,
    pub version: DtlsVersion,
    pub epoch: u16,
    pub sequence_number: u64, // u48
    pub length: u16,
}

impl RecordHeader {
    pub fn new(
        content_type: ContentType,
        version: DtlsVersion,
        epoch: u16,
        sequence_number: u64,
        length: u16,
    ) -> Self {
        Self {
            content_type,
            version,
            epoch,
            sequence_number,
            length,
        }
    }

    pub fn decode(reader: &mut BufReader) -> anyhow::Result<Self> {
        let content_type_byte = reader.read_u8()?;
        let content_type = content_type_byte.try_into()?;

        let version_bytes = reader.read_u16()?;
        let version = DtlsVersion::try_from(version_bytes)?;

        let epoch = reader.read_u16()?;

        let sequence_number1 = reader.read_u16()?;
        let sequence_number2 = reader.read_u32()?;
        let sequence_number = ((sequence_number1 as u64) << 4) + (sequence_number2 as u64);

        let length = reader.read_u16()?;

        Ok(Self {
            content_type,
            version,
            epoch,
            sequence_number,
            length,
        })
    }

    pub fn encode(&self, writer: &mut BufWriter) {
        writer.write_u8(self.content_type as u8);
        self.version.encode(writer);
        writer.write_u16(self.epoch);
        // Write 48-bit sequence number as u16 + u32
        writer.write_u16((self.sequence_number >> 32) as u16);
        writer.write_u32((self.sequence_number & 0xFFFFFFFF) as u32);
        writer.write_u16(self.length);
    }
}
