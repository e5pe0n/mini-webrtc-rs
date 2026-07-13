use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
    u16,
};

use anyhow::{Result, anyhow};
use rand::{RngExt, random};
use tokio::sync::{Mutex, mpsc::UnboundedSender};
use tracing::{debug, info, warn};

use crate::{
    common::{TransportMessage, buffer::BufReader},
    data_channel::{
        DataChannelEvent, DataChannelMessage,
        dcep::{DataChannelOpenMessage, MessageType},
    },
    internal_event::InternalEvent,
    rtc_peer_connection::PeerConnection,
    rtc_sctp::{RtcSctpTransport, RtcSctpTransportState},
    sctp::{
        chunk::{
            COOKIE_LENGTH_IN_BYTES, Chunk, ChunkParam,
            cookie_ack::CookieAckChunk,
            data::{DataChunk, DataChunkValue, PayloadProtocol},
            init_ack::{InitAckChunk, InitAckChunkValue},
            sack::{SackChunk, SackChunkValue},
        },
        packet::SctpPacket,
    },
};

pub struct SctpManager {
    inbound_dc_tx: Option<UnboundedSender<DataChannelEvent>>,
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
    event_queue: Arc<Mutex<VecDeque<InternalEvent>>>,
    peer_addr: Option<SocketAddr>,
    pc: Arc<Mutex<PeerConnection>>,
}

impl SctpManager {
    pub fn new(
        event_queue: Arc<Mutex<VecDeque<InternalEvent>>>,
        pc: Arc<Mutex<PeerConnection>>,
    ) -> Self {
        Self {
            inbound_dc_tx: None,
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
            event_queue,
            peer_addr: None,
            pc,
        }
    }

    pub async fn set_data_channel_transport(
        &mut self,
        inbound_dc_tx: UnboundedSender<DataChannelEvent>,
    ) {
        self.pc.lock().await.sctp = Some(RtcSctpTransport::new());
        self.inbound_dc_tx = Some(inbound_dc_tx);
    }

    pub async fn send_data(
        &mut self,
        stream_id: u16,
        payload_protocol: PayloadProtocol,
        user_data: Vec<u8>,
    ) -> Result<()> {
        match self.peer_addr {
            Some(peer_addr) => {
                let stream_seq_num = self.stream_seq_nums.entry(stream_id).or_insert(0);
                let data_chunk = DataChunk::new(
                    None,
                    DataChunkValue {
                        tsn: self.local_tsn,
                        stream_id,
                        stream_seq_num: *stream_seq_num,
                        payload_protocol,
                        user_data,
                    },
                );

                *stream_seq_num = stream_seq_num.wrapping_add(1);
                self.local_tsn = self.local_tsn.wrapping_add(1);
                self.send_sctp_chunk(data_chunk.raw, None, peer_addr).await
            }
            None => Err(anyhow!("data channel not established.")),
        }
    }

    pub async fn handle_inbound_packet(
        &mut self,
        data: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<()> {
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
                    params: vec![
                        ChunkParam::StateCookie(cookie.clone()),
                        ChunkParam::ForwardTsn,
                    ],
                });

                self.send_sctp_chunk(init_ack.raw, Some(chunk.value.init_tag), peer_addr)
                    .await?;
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
                    self.peer_addr = Some(peer_addr);
                    self.send_sctp_chunk(cookie_ack.raw, None, peer_addr)
                        .await?;
                    if let Some(sctp) = &mut self.pc.lock().await.sctp {
                        sctp.state = RtcSctpTransportState::Connected;
                    }
                }
            },
            Chunk::Data(chunk) => {
                // TODO: https://datatracker.ietf.org/doc/html/rfc9260#name-acknowledgement-on-receptio
                if self.remote_tsn.is_none() {
                    anyhow::bail!(anyhow!("remote tsn none."));
                }

                let sack = SackChunk::new(
                    None,
                    SackChunkValue {
                        cumulative_tsn_ack: chunk.value.tsn,
                        a_rwnd: self.local_a_rwnd,
                        gap_ack_blocks: vec![],
                        dup_tsns: vec![],
                    },
                );
                self.send_sctp_chunk(sack.raw, None, peer_addr).await?;
                self.remote_tsn = Some(chunk.value.tsn.wrapping_add(1));

                let mut reader = BufReader::new(&chunk.value.user_data);
                if let Some(inbound_dc_tx) = &self.inbound_dc_tx {
                    match chunk.value.payload_protocol {
                        PayloadProtocol::WebrtcDcep => {
                            let message_type = reader.read_u8()?;
                            let message_type = MessageType::try_from(message_type)?;
                            match message_type {
                                MessageType::DataChannelOpen => {
                                    let data_channel_open_message =
                                        DataChannelOpenMessage::decode(&mut reader)?;
                                    debug!(
                                        "received data channel open message: {data_channel_open_message:?}"
                                    );
                                    let ack_message = vec![0u8];
                                    self.send_data(
                                        chunk.value.stream_id,
                                        PayloadProtocol::WebrtcDcep,
                                        ack_message,
                                    )
                                    .await?;
                                }
                                MessageType::DataChannelAck => {
                                    inbound_dc_tx.send(DataChannelEvent::Open)?;
                                }
                            }
                        }
                        PayloadProtocol::WebrtcBinary => {
                            inbound_dc_tx.send(DataChannelEvent::Open)?;
                        }
                        PayloadProtocol::WebrtcBinaryEmpty => {
                            inbound_dc_tx.send(DataChannelEvent::Message(
                                DataChannelMessage::Binary(vec![0u8]),
                            ))?;
                        }
                        PayloadProtocol::WebrtcString => {
                            inbound_dc_tx.send(DataChannelEvent::Message(
                                DataChannelMessage::Text(String::from_utf8(
                                    chunk.value.user_data.clone(),
                                )?),
                            ))?;
                        }
                        PayloadProtocol::WebrtcStringEmpty => {
                            inbound_dc_tx.send(DataChannelEvent::Message(
                                DataChannelMessage::Text("".to_string()),
                            ))?;
                        }
                        PayloadProtocol::Unsupported => {
                            warn!("ignore unsupported payload protocol.");
                        }
                    }
                }
            }
            Chunk::Sack(_chunk) => {
                // TODO: https://datatracker.ietf.org/doc/html/rfc9260#sec_processing_of_received_sack
            }
            Chunk::NotImplemented => {
                warn!("not implemented chunk type")
            }
        }

        Ok(())
    }

    async fn send_sctp_chunk(
        &self,
        chunk_raw: Vec<u8>,
        verification_tag: Option<u32>,
        peer_addr: SocketAddr,
    ) -> Result<()> {
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
        self.event_queue
            .lock()
            .await
            .push_back(InternalEvent::OutboundSctpPacket(TransportMessage {
                peer_addr,
                data: packet,
            }));
        Ok(())
    }
}
