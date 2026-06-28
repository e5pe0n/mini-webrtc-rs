pub mod dcep;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{Mutex, mpsc};

use crate::sctp::{chunk::data::PayloadProtocol, manager::SctpManager};

#[derive(Debug)]
pub enum DataChannelEvent {
    Open,
    Message(DataChannelMessage),
    Close,
}

#[derive(Debug, Clone)]
pub enum DataChannelMessage {
    Text(String),
    Binary(Vec<u8>),
}

pub struct DataChannel {
    pub stream_id: u16,
    pub inbound_dc_rx: mpsc::UnboundedReceiver<DataChannelEvent>,
    pub sctp_manager: Arc<Mutex<SctpManager>>,
}

impl DataChannel {
    pub async fn new(stream_id: u16, sctp_manager: Arc<Mutex<SctpManager>>) -> Self {
        let (inbound_dc_tx, inbound_dc_rx) = mpsc::unbounded_channel::<DataChannelEvent>();
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
        let payload_protocol = if text.is_empty() {
            PayloadProtocol::WebrtcStringEmpty
        } else {
            PayloadProtocol::WebrtcString
        };

        self.sctp_manager
            .lock()
            .await
            .send_data(self.stream_id, payload_protocol, text.as_bytes().to_vec())
            .await?;

        Ok(())
    }

    pub async fn send_binary(&self, data: &[u8]) -> Result<()> {
        let payload_protocol = if data.is_empty() {
            PayloadProtocol::WebrtcBinaryEmpty
        } else {
            PayloadProtocol::WebrtcBinary
        };

        self.sctp_manager
            .lock()
            .await
            .send_data(self.stream_id, payload_protocol, data.to_vec())
            .await?;

        Ok(())
    }

    pub async fn recv(&mut self) -> Option<DataChannelEvent> {
        self.inbound_dc_rx.recv().await
    }
}
