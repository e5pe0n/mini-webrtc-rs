pub mod dcep;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{Mutex, mpsc};

use crate::sctp::manager::SctpManager;

pub const PAYLOAD_PROTOCOL_ID_DCEP: u32 = 50;
pub const PAYLOAD_PROTOCOL_ID_STRING: u32 = 51;
pub const PAYLOAD_PROTOCOL_ID_BINARY: u32 = 53;
pub const PAYLOAD_PROTOCOL_ID_STRING_EMPTY: u32 = 56;
pub const PAYLOAD_PROTOCOL_ID_BINARY_EMPTY: u32 = 57;

#[derive(Debug, Clone)]
pub struct IncomingDataChannelMessage {
    pub payload_protocol_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DataChannelMessage {
    Text(String),
    Binary(Vec<u8>),
}

pub struct DataChannel {
    stream_id: u16,
    sctp_manager: Arc<Mutex<SctpManager>>,
    incoming: mpsc::UnboundedReceiver<IncomingDataChannelMessage>,
}

impl DataChannel {
    pub async fn new(stream_id: u16, sctp_manager: Arc<Mutex<SctpManager>>) -> Self {
        let incoming = sctp_manager.lock().await.register_data_channel(stream_id);

        Self {
            stream_id,
            sctp_manager,
            incoming,
        }
    }

    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }

    pub async fn send_text(&self, text: &str) -> Result<()> {
        let payload_protocol_id = if text.is_empty() {
            PAYLOAD_PROTOCOL_ID_STRING_EMPTY
        } else {
            PAYLOAD_PROTOCOL_ID_STRING
        };

        self.sctp_manager
            .lock()
            .await
            .send_data(
                self.stream_id,
                payload_protocol_id,
                text.as_bytes().to_vec(),
            )
            .await
    }

    pub async fn send_binary(&self, data: &[u8]) -> Result<()> {
        let payload_protocol_id = if data.is_empty() {
            PAYLOAD_PROTOCOL_ID_BINARY_EMPTY
        } else {
            PAYLOAD_PROTOCOL_ID_BINARY
        };

        self.sctp_manager
            .lock()
            .await
            .send_data(self.stream_id, payload_protocol_id, data.to_vec())
            .await
    }

    pub async fn recv(&mut self) -> Option<DataChannelMessage> {
        let msg = self.incoming.recv().await?;

        let message = match msg.payload_protocol_id {
            PAYLOAD_PROTOCOL_ID_STRING | PAYLOAD_PROTOCOL_ID_STRING_EMPTY => {
                match String::from_utf8(msg.payload) {
                    Ok(text) => DataChannelMessage::Text(text),
                    Err(err) => DataChannelMessage::Binary(err.into_bytes()),
                }
            }
            _ => DataChannelMessage::Binary(msg.payload),
        };

        Some(message)
    }
}
