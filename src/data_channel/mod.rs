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
pub struct InternalDataChannelMessage {
    pub stream_id: u16,
    pub payload_protocol_id: u32,
    pub user_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DataChannelMessage {
    Text(String),
    Binary(Vec<u8>),
}

pub struct DataChannel {
    pub stream_id: u16,
    pub inbound_dc_rx: mpsc::UnboundedReceiver<InternalDataChannelMessage>,
    pub sctp_manager: Arc<Mutex<SctpManager>>,
}

impl DataChannel {
    pub async fn new(stream_id: u16, sctp_manager: Arc<Mutex<SctpManager>>) -> Self {
        let (inbound_dc_tx, inbound_dc_rx) =
            mpsc::unbounded_channel::<InternalDataChannelMessage>();
        sctp_manager
            .lock()
            .await
            .set_data_channel_transport(inbound_dc_tx);
        Self {
            stream_id,
            inbound_dc_rx,
            sctp_manager,
        }
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
            .await?;

        Ok(())
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
            .await?;

        Ok(())
    }

    pub async fn recv(&mut self) -> Option<DataChannelMessage> {
        let msg = self.inbound_dc_rx.recv().await?;

        let message = match msg.payload_protocol_id {
            PAYLOAD_PROTOCOL_ID_STRING | PAYLOAD_PROTOCOL_ID_STRING_EMPTY => {
                match String::from_utf8(msg.user_data) {
                    Ok(text) => DataChannelMessage::Text(text),
                    Err(err) => DataChannelMessage::Binary(err.into_bytes()),
                }
            }
            _ => DataChannelMessage::Binary(msg.user_data),
        };

        Some(message)
    }
}
