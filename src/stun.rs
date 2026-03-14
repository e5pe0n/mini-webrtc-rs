use aes_gcm::KeyInit;
use anyhow::{Result, anyhow};
use hmac::Hmac;
use sha2::Sha256;
use std::collections::HashMap;

use mini_webrtc_derive::{FromPrimitive, TryFromPrimitive};

use crate::dtls::{
    buffer::{BufReader, BufWriter},
    crypto::hmac_sha,
};

pub const HEADER_BYTES: usize = 20;

const MAGIC_COOKIE_BYTES: usize = 4;
pub const MAGIC_COOKIE: u32 = 0x2112A442;

const METHOD_A_BITS: u16 = 0xf; // 0b0000000000001111
const METHOD_B_BITS: u16 = 0x70; // 0b0000000001110000
const METHOD_D_BITS: u16 = 0xf80; // 0b0000111110000000

const METHOD_B_SHIFT: u16 = 1;
const METHOD_D_SHIFT: u16 = 2;

const C0_BIT: u16 = 0x01;
const C1_BIT: u16 = 0x02;

const C0_SHIFT: u16 = 4;
const C1_SHIFT: u16 = 7;

pub const TRANSACTION_ID_BYTES: usize = 12;

const ATTRIBUTE_HEADER_BYTES: usize = 4;
const HMAC_SIGNATURE_BYTES: usize = 20;

pub struct StunMessage {
    pub message_type: StunMessageType,
    pub transaction_id: Vec<u8>, // 12 bytes
    pub attributes: HashMap<AttributeType, Attribute>,
    pub raw: Vec<u8>,
}

impl StunMessage {
    pub fn is_stun_message(buf: &[u8]) -> bool {
        buf.len() >= HEADER_BYTES
            && u32::from_be_bytes(buf[0..MAGIC_COOKIE_BYTES].try_into().unwrap()) == MAGIC_COOKIE
    }

    pub fn verify_message_integrity(&self, pwd: String) -> Result<bool> {
        let message_integrity = self
            .attributes
            .get(&AttributeType::MessageIntegrity)
            .ok_or(anyhow!("message integrity attribute does not exist."))?;

        let mut raw_message = self.raw[0..message_integrity.offset_in_message].to_vec();
        let message_length =
            raw_message.len() - HEADER_BYTES + ATTRIBUTE_HEADER_BYTES + HMAC_SIGNATURE_BYTES;
        raw_message[2] = (message_length >> 8) as u8;
        raw_message[3] = message_length as u8;

        let calculated_message_integrity = hmac_sha(pwd.as_bytes(), &raw_message);
        Ok(calculated_message_integrity == message_integrity.value)
    }

    pub fn decode(reader: &mut BufReader) -> Result<Self> {
        // message type
        // class
        let message_type_u16 = reader.read_u16()?;
        let c0 = (message_type_u16 >> C0_SHIFT) & C0_BIT;
        let c1 = (message_type_u16 >> C1_SHIFT) & C1_BIT;
        let class = c0 + c1;
        // method
        let a = message_type_u16 & METHOD_A_BITS;
        let b = (message_type_u16 >> METHOD_B_SHIFT) & METHOD_B_BITS;
        let d = (message_type_u16 >> METHOD_D_SHIFT) & METHOD_D_BITS;
        let method = a + b + d;

        let message_type = StunMessageType {
            class: StunMessageClass::try_from(class)?,
            method: StunMessageMethod::try_from(method)?,
        };

        let message_length = reader.read_u16()? as usize;
        let _magic_cookie = reader.read_u32()?;

        let mut transaction_id = vec![0u8; TRANSACTION_ID_BYTES];
        reader.read_exact(&mut transaction_id);

        let mut attributes: HashMap<AttributeType, Attribute> = HashMap::new();

        loop {
            let offset = (message_length as usize) - reader.rest_len();
            let attr_type = AttributeType::from(reader.read_u16()?);
            let attr_length = reader.read_u16()?;
            let mut attr_value = vec![0u8; attr_length as usize];
            reader.read_exact(&mut attr_value);
            attributes.insert(
                attr_type.clone(),
                Attribute {
                    attribute_type: attr_type,
                    value: attr_value,
                    offset_in_message: offset,
                },
            );
            if reader.rest_len() == 0 {
                return Ok(StunMessage {
                    message_type,
                    transaction_id,
                    attributes,
                    raw: reader.buf[..HEADER_BYTES + message_length].to_vec(),
                });
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct StunMessageType {
    pub method: StunMessageMethod,
    pub class: StunMessageClass,
}

#[derive(TryFromPrimitive, Clone, Copy)]
#[try_from(type = "u16")]
pub enum StunMessageMethod {
    Binding = 0x0001,
}

#[derive(TryFromPrimitive, Clone, Copy)]
#[try_from(type = "u16")]
pub enum StunMessageClass {
    Request = 0x00,
    Indication = 0x01,
    SuccessResponse = 0x02,
    ErrorResponse = 0x03,
}

#[derive(FromPrimitive, Eq, PartialEq, Hash, Clone, Copy)]
#[from(type = "u16", default = "Unsupported")]
pub enum AttributeType {
    Unsupported = 0x0000,
    Username = 0x0006,
    Password = 0x0007,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000a,
    XorMappedAddress = 0x0020,
    Fingerprint = 0x8028,
}

pub struct Attribute {
    pub attribute_type: AttributeType,
    pub value: Vec<u8>,
    pub offset_in_message: usize,
}

pub struct StunMessageBuilder {
    pub message_type: StunMessageType,
    pub transaction_id: Vec<u8>, // 12 bytes
    pub attributes: HashMap<AttributeType, Attribute>,
    pub writer: BufWriter,
    message_length: usize,
}

impl StunMessageBuilder {
    pub fn new(message_type: StunMessageType, transaction_id: Vec<u8>) -> Self {
        let mut writer = BufWriter::new();

        let method = message_type.method as u16;
        let a = method & METHOD_A_BITS;
        let b = method & METHOD_B_BITS;
        let d = method & METHOD_D_BITS;
        let m = a + (b << METHOD_B_SHIFT) + (d << METHOD_D_SHIFT);

        let class = message_type.class as u16;
        let c0 = (class & C0_BIT) << C0_SHIFT;
        let c1 = (class & C1_BIT) << C1_SHIFT;
        let c = c0 + c1;

        writer.write_u16(m + c);
        writer.write_u16(0);
        writer.write_u32(MAGIC_COOKIE);
        writer.write_bytes(&transaction_id);

        Self {
            message_type,
            transaction_id,
            attributes: HashMap::new(),
            writer,
            message_length: 0,
        }
    }

    pub fn add_attr(mut self, attr_type: AttributeType, value: Vec<u8>) -> Self {
        self.attributes.insert(
            attr_type,
            Attribute {
                attribute_type: attr_type,
                value: value.clone(),
                offset_in_message: self.writer.buf_ref().len(),
            },
        );
        self.writer.write_u16(attr_type as u16);
        self.writer.write_u16(value.len() as u16);
        self.writer.write_bytes(&value);
        self.message_length += 2 + 2 + &value.len();
        self
    }

    pub fn build(self) -> StunMessage {
        StunMessage {
            message_type: self.message_type,
            transaction_id: self.transaction_id,
            attributes: self.attributes,
            raw: self.writer.buf(),
        }
    }
}
