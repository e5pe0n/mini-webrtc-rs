use anyhow::Result;
use crc::{CRC_32_ISCSI, Crc};
use tracing::warn;

use crate::{
    common::{
        buffer::{BufReader, BufWriter},
        error::MiniWebrtcRsError::{self, BufferOutOfIndexError},
    },
    sctp::chunk::Chunk,
};

// https://datatracker.ietf.org/doc/html/rfc9260#name-sctp-packet-format
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Common Header                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Chunk #1                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Chunk #n                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// https://datatracker.ietf.org/doc/html/rfc9260#section-3.2
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Chunk Type   |  Chunk Flags  |         Chunk Length          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// \                                                               \
// /                          Chunk Value                          /
// \                                                               \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct SctpPacket {
    pub header: CommonHeader,
    pub chunks: Vec<Chunk>,
}

const HEADER_LENGTH_IN_BYTES: usize = 4 * 3;

impl SctpPacket {
    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        let header = CommonHeader::decode(reader)?;
        let mut chunks = vec![];
        while reader.rest_len() >= HEADER_LENGTH_IN_BYTES {
            match Chunk::decode(reader) {
                Ok(chunk) => chunks.push(chunk),
                Err(err) => match err {
                    BufferOutOfIndexError { pos: _, len: _ } => {
                        break;
                    }
                    err => {
                        warn!("{err:?}");
                        continue;
                    }
                },
            }
        }
        Ok(Self { header, chunks })
    }

    pub fn encode_single_chunk(
        src_port: u16,
        dst_port: u16,
        verification_tag: u32,
        chunk_raw: &[u8],
    ) -> Vec<u8> {
        let mut writer = BufWriter::new();
        writer.write_u16(src_port);
        writer.write_u16(dst_port);
        writer.write_u32(verification_tag);
        writer.write_u32(0);
        writer.write_bytes(chunk_raw);

        let mut raw = writer.buf();
        let checksum = Crc::<u32>::new(&CRC_32_ISCSI).checksum(&raw);
        raw[8..12].copy_from_slice(&checksum.to_be_bytes());
        raw
    }
}

// https://datatracker.ietf.org/doc/html/rfc9260#name-sctp-common-header-field-de
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Source Port Number       |    Destination Port Number    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Verification Tag                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Checksum                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct CommonHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub verification_tag: u32,
    pub checksum: u32,
    pub raw: Vec<u8>,
}

impl CommonHeader {
    pub fn decode(reader: &mut BufReader) -> Result<Self, MiniWebrtcRsError> {
        reader.start();
        let src_port = reader.read_u16()?;
        let dst_port = reader.read_u16()?;
        let verification_tag = reader.read_u32()?;
        let checksum = reader.read_u32()?;
        let raw = reader.clone_from_start();

        Ok(Self {
            src_port,
            dst_port,
            verification_tag,
            checksum,
            raw,
        })
    }
}
