use std::{collections::HashMap, u16};

use anyhow::{Result, anyhow};
use rand::{RngExt, random};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, error::TryRecvError};
use tracing::{info, warn};

use crate::{
    common::buffer::BufReader,
    data_channel::IncomingDataChannelMessage,
    sctp::{
        chunk::{
            COOKIE_LENGTH_IN_BYTES, Chunk, ChunkParam,
            cookie_ack::CookieAckChunk,
            data::{DataChunk, DataChunkValue},
            init_ack::{InitAckChunk, InitAckChunkValue},
            sack::{SackChunk, SackChunkValue},
        },
        packet::SctpPacket,
    },
};

pub struct SctpManager {
    inbound_sctp_rx: UnboundedReceiver<Vec<u8>>,
    outbound_sctp_tx: UnboundedSender<Vec<u8>>,
    local_a_rwnd: u32,
    remote_a_rwnd: u32,
    max_num_outbound_streams: u16,
    max_num_inbound_streams: u16,
    local_tsn: u32,
    remote_tsn: Option<u32>,
    cookie: Option<Vec<u8>>,
    peer_verification_tag: Option<u32>,
    local_port: Option<u16>,
    remote_port: Option<u16>,
    stream_seq_nums: HashMap<u16, u16>,
    data_channels: HashMap<u16, UnboundedSender<IncomingDataChannelMessage>>,
}

impl SctpManager {
    pub fn new(
        outbound_sctp_tx: UnboundedSender<Vec<u8>>,
        inbound_sctp_rx: UnboundedReceiver<Vec<u8>>,
    ) -> Self {
        Self {
            outbound_sctp_tx,
            inbound_sctp_rx,
            local_a_rwnd: 1024 * 1024,
            remote_a_rwnd: 0,
            max_num_outbound_streams: u16::MAX,
            max_num_inbound_streams: u16::MAX,
            local_tsn: random::<u32>(),
            remote_tsn: None,
            cookie: None,
            peer_verification_tag: None,
            local_port: None,
            remote_port: None,
            stream_seq_nums: HashMap::new(),
            data_channels: HashMap::new(),
        }
    }

    pub fn register_data_channel(
        &mut self,
        stream_id: u16,
    ) -> UnboundedReceiver<IncomingDataChannelMessage> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.data_channels.insert(stream_id, tx);
        rx
    }

    pub async fn send_data(
        &mut self,
        stream_id: u16,
        payload_protocol_id: u32,
        user_data: Vec<u8>,
    ) -> Result<()> {
        let stream_seq_num = self.stream_seq_nums.entry(stream_id).or_insert(0);
        let data_chunk = DataChunk::new(
            None,
            DataChunkValue {
                tsn: self.local_tsn,
                stream_id,
                stream_seq_num: *stream_seq_num,
                payload_protocol_id,
                user_data,
            },
        );

        *stream_seq_num = stream_seq_num.wrapping_add(1);
        self.local_tsn = self.local_tsn.wrapping_add(1);
        self.send_sctp_chunk(data_chunk.raw, None)
    }

    pub fn process_inbound_pending(&mut self) -> Result<()> {
        loop {
            match self.inbound_sctp_rx.try_recv() {
                Ok(data) => self.handle_inbound_packet(&data)?,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        Ok(())
    }

    fn handle_inbound_packet(&mut self, data: &[u8]) -> Result<()> {
        let mut reader = BufReader::new(data);
        let packet = SctpPacket::decode(&mut reader)?;
        info!("received sctp packet: {:?}", packet);

        if packet.chunks.is_empty() {
            warn!("no chunks in packet");
            return Ok(());
        }

        self.local_port = Some(packet.header.dst_port);
        self.remote_port = Some(packet.header.src_port);

        match &packet.chunks[0] {
            Chunk::Init(chunk) => {
                // TODO: https://datatracker.ietf.org/doc/html/rfc9260#sec_generating_state_cookie
                let mut cookie = vec![0u8; COOKIE_LENGTH_IN_BYTES as usize];
                rand::rng().fill(&mut cookie);

                self.peer_verification_tag = Some(chunk.value.init_tag);
                self.remote_a_rwnd = chunk.value.a_rwnd;

                let init_ack = InitAckChunk::new(InitAckChunkValue {
                    init_tag: random::<u32>(),
                    a_rwnd: self.local_a_rwnd,
                    num_outbound_streams: u16::min(
                        self.max_num_outbound_streams,
                        chunk.value.num_outbound_streams,
                    ),
                    num_inbound_streams: u16::min(
                        self.max_num_inbound_streams,
                        chunk.value.num_inbound_streams,
                    ),
                    init_tsn: self.local_tsn,
                    params: vec![ChunkParam::StateCookie(cookie.clone())],
                });

                self.send_sctp_chunk(init_ack.raw, Some(chunk.value.init_tag))?;
                self.cookie = Some(cookie);
                self.remote_tsn = Some(chunk.value.init_tsn.wrapping_sub(1));
            }
            Chunk::CookieEcho(chunk) => match &self.cookie {
                None => {
                    anyhow::bail!(anyhow!("cookie not created."));
                }
                Some(cookie) => {
                    if cookie != &chunk.value.cookie {
                        anyhow::bail!(anyhow!("invalid cookie."));
                    }
                    let cookie_ack = CookieAckChunk::new();
                    self.send_sctp_chunk(cookie_ack.raw, None)?;
                }
            },
            Chunk::Data(chunk) => {
                // TODO: https://datatracker.ietf.org/doc/html/rfc9260#name-acknowledgement-on-receptio
                if self.remote_tsn.is_none() {
                    anyhow::bail!(anyhow!("remote tsn none."));
                }

                info!("{:?}", chunk);
                let sack = SackChunk::new(
                    None,
                    SackChunkValue {
                        cumulative_tsn_ack: chunk.value.tsn,
                        a_rwnd: self.local_a_rwnd,
                        gap_ack_blocks: vec![],
                        dup_tsns: vec![],
                    },
                );
                self.send_sctp_chunk(sack.raw, None)?;
                self.remote_tsn = Some(chunk.value.tsn.wrapping_add(1));

                if let Some(channel_tx) = self.data_channels.get(&chunk.value.stream_id)
                    && let Err(err) = channel_tx.send(IncomingDataChannelMessage {
                        payload_protocol_id: chunk.value.payload_protocol_id,
                        payload: chunk.value.user_data.clone(),
                    })
                {
                    warn!(
                        "failed to deliver data channel message; stream_id={}; error={err}",
                        chunk.value.stream_id
                    );
                }
            }
            Chunk::Sack(_chunk) => {
                // TODO: https://datatracker.ietf.org/doc/html/rfc9260#sec_processing_of_received_sack
            }
            Chunk::NotImplemented => {
                warn!("chunk type not implemented")
            }
        }

        Ok(())
    }

    fn send_sctp_chunk(&self, chunk_raw: Vec<u8>, verification_tag: Option<u32>) -> Result<()> {
        let src_port = self
            .local_port
            .ok_or(anyhow!("sctp local port is not initialized yet."))?;
        let dst_port = self
            .remote_port
            .ok_or(anyhow!("sctp remote port is not initialized yet."))?;
        let verification_tag = verification_tag
            .or(self.peer_verification_tag)
            .ok_or(anyhow!("sctp verification tag is not initialized yet."))?;

        let packet =
            SctpPacket::encode_single_chunk(src_port, dst_port, verification_tag, &chunk_raw);
        self.outbound_sctp_tx.send(packet)?;
        Ok(())
    }
}
