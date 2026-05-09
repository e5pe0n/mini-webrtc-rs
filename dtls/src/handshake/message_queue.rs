use anyhow::{Context, Result};
use common::buffer::BufReader;
use std::collections::HashMap;
use tracing::debug;

use crate::{
    handshake::header::{HANDSHAKE_HEADER_BYTES, HandshakeHeader},
    record_header::RecordHeader,
};

pub struct HandshakeMessageQueue {
    next_message_seq: u16,
    fragments: HashMap<u16, EncodedHandshakeMessage>,
}

impl HandshakeMessageQueue {
    pub fn new() -> Self {
        Self {
            next_message_seq: 0,
            fragments: HashMap::new(),
        }
    }

    pub fn push(&mut self, data: &[u8]) -> Result<Vec<EncodedHandshakeMessage>> {
        let mut reader = BufReader::new(data);

        while reader.rest_len() > 0 {
            let _ = RecordHeader::decode(&mut reader).context("decode record header")?;

            let handshake_header_raw =
                reader.buf[reader.pos..reader.pos + HANDSHAKE_HEADER_BYTES].to_vec();
            let handshake_header = HandshakeHeader::decode(&mut reader)?;
            debug!("{:?}", handshake_header);

            let mut payload = vec![0u8; handshake_header.fragment_length as usize];
            reader
                .read_exact(&mut payload)
                .context(format!("reading payload; {:?}", handshake_header))?;

            if let Some(message) = self.fragments.get_mut(&handshake_header.message_seq) {
                message.add(handshake_header.fragment_offset, &payload);
            } else {
                let mut message =
                    EncodedHandshakeMessage::new(handshake_header.clone(), &handshake_header_raw);
                message.add(handshake_header.fragment_offset, &payload);
                self.fragments.insert(handshake_header.message_seq, message);
            };
        }

        let mut res = vec![];
        while let Some(message) = self.fragments.get(&self.next_message_seq)
            && message.completed()
        {
            res.push(message.clone());
            self.fragments.remove(&self.next_message_seq);
            self.next_message_seq += 1;
        }
        Ok(res)
    }
}

#[derive(Debug, Clone)]
pub struct EncodedHandshakeMessage {
    pub handshake_header: HandshakeHeader,
    pub handshake_header_raw: Vec<u8>,
    pub mask: Vec<bool>,
    pub payload: Vec<u8>,
}

impl EncodedHandshakeMessage {
    pub fn new(handshake_header: HandshakeHeader, handshake_header_raw: &[u8]) -> Self {
        let length = handshake_header.length as usize;
        Self {
            handshake_header,
            handshake_header_raw: handshake_header_raw.to_vec(),
            mask: vec![false; length],
            payload: vec![0u8; length],
        }
    }

    pub fn add(&mut self, offset: u32, payload: &[u8]) {
        let offset = offset as usize;
        if offset >= self.payload.len() {
            return;
        }
        let length = payload.len().min(self.payload.len() - offset);
        self.payload[offset..offset + length].copy_from_slice(&payload[..length]);
        self.mask[offset..offset + length].fill(true);
    }

    pub fn completed(&self) -> bool {
        self.mask.iter().all(|b| *b)
    }

    pub fn raw(&self) -> Vec<u8> {
        vec![self.handshake_header_raw.clone(), self.payload.clone()].concat()
    }
}
