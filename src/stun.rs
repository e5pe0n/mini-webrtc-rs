use std::collections::HashMap;

use mini_webrtc_derive::TryFromPrimitive;

use crate::dtls::buffer::BufReader;

const HEADER_BYTES: usize = 20;
const MAGIC_COOKIE_BYTES: usize = 4;
const MAGIC_COOKIE: u32 = 0x2112A442;

const METHOD_A_BITS: u16 = 0xf; // 0b0000000000001111
const METHOD_B_BITS: u16 = 0x70; // 0b0000000001110000
const METHOD_D_BITS: u16 = 0xf80; // 0b0000111110000000

const METHOD_B_SHIFT: u16 = 1;
const METHOD_D_SHIFT: u16 = 2;

const C0_BIT: u16 = 0x01;
const C1_BIT: u16 = 0x02;

const C0_SHIFT: u16 = 4;
const C1_SHIFT: u16 = 7;

const TRANSACTION_ID_BYTES: usize = 12;

pub struct StunMessage {
    pub message_type: StunMessageType,
    pub transaction_id: Vec<u8>, // 12 bytes
    // pub attributes: HashMap<AttributeType, Attribute>,
    pub raw_message: Vec<u8>,
}

impl StunMessage {
    pub fn is_stun_message(buf: &[u8]) -> bool {
        buf.len() >= HEADER_BYTES
            && u32::from_be_bytes(buf[0..MAGIC_COOKIE_BYTES].try_into().unwrap()) == MAGIC_COOKIE
    }

    pub fn decode(reader: &mut BufReader) -> Result<Self, String> {
        let raw_message = reader.buf();

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

        let message_length = reader.read_u16()?;
        let _magic_cookie = reader.read_u32()?;

        let mut transaction_id = vec![0u8; TRANSACTION_ID_BYTES];
        reader.read_exact(&mut transaction_id);

        // let attributes: HashMap<AttributeType, Attribute>

        loop {
            match reader.read_u16() {
                Ok(attr_type) => match reader.read_u16() {
                    Ok(attr_length) => {
                        let mut attr_value = vec![0u8; attr_length as usize];
                        reader.read_exact(&mut attr_value);
                    }
                    Err(e) => {
                        return Ok(StunMessage {
                            message_type,
                            transaction_id,
                            raw_message,
                        });
                    }
                },
                Err(e) => {
                    return Ok(StunMessage {
                        message_type,
                        transaction_id,
                        raw_message,
                    });
                }
            }
        }
    }
}

struct StunMessageType {
    pub method: StunMessageMethod,
    pub class: StunMessageClass,
}

#[derive(TryFromPrimitive)]
#[try_from(type = "u16")]
pub enum StunMessageMethod {
    Binding = 0x0001,
}

#[derive(TryFromPrimitive)]
#[try_from(type = "u16")]
pub enum StunMessageClass {
    Request = 0x00,
    Indication = 0x01,
    SuccessResponse = 0x02,
    ErrorResponse = 0x03,
}

pub enum AttributeType {
    UserName = 0x0006,
    Password = 0x0007,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000a,
    Fingerprint = 0x8028,
}
