use std::collections::HashMap;

const HEADER_BYTES: usize = 20;
const MAGIC_COOKIE_BYTES: usize = 4;
const MAGIC_COOKIE: u32 = 0x2112A442;

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
}

struct StunMessageType {
    pub method: StunMessageMethod,
    pub class: StunMessageClass,
}

pub enum StunMessageMethod {
    Binding = 0x0001,
}

pub enum StunMessageClass {
    Request,
}

pub enum Attribute {}
