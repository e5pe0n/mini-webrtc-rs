use std::{net::SocketAddr, sync::Arc, u16};

use anyhow::{Result, anyhow};
use rand::{RngExt, random};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::{
    common::buffer::BufReader,
    sctp::{
        chunk::{
            COOKIE_LENGTH_IN_BYTES, Chunk, ChunkParam,
            cookie_ack::CookieAckChunk,
            init_ack::{InitAckChunk, InitAckChunkValue},
            sack::{SackChunk, SackChunkValue},
        },
        packet::SctpPacket,
    },
};

pub struct SctpManager {
    pub socket: Arc<UdpSocket>,
    local_a_rwnd: u32,
    remote_a_rwnd: u32,
    max_num_outbound_streams: u16,
    max_num_inbound_streams: u16,
    local_tsn: u32,
    remote_tsn: Option<u32>,
    cookie: Option<Vec<u8>>,
}

impl SctpManager {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            local_a_rwnd: 1024 * 1024,
            remote_a_rwnd: 0,
            max_num_outbound_streams: u16::MAX,
            max_num_inbound_streams: u16::MAX,
            local_tsn: random::<u32>(),
            remote_tsn: None,
            cookie: None,
        }
    }

    pub async fn handle_sctp_packet(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        let mut reader = BufReader::new(data);
        let packet = SctpPacket::decode(&mut reader)?;
        info!("received sctp packet: {:?}", packet);

        if packet.chunks.len() == 0 {
            warn!("no chunks in packet");
            return Ok(());
        }

        match &packet.chunks[0] {
            Chunk::Init(chunk) => {
                // TODO: https://datatracker.ietf.org/doc/html/rfc9260#sec_generating_state_cookie
                let mut cookie = vec![0u8; COOKIE_LENGTH_IN_BYTES as usize];
                rand::rng().fill(&mut cookie);

                let init_ack = InitAckChunk::new(InitAckChunkValue {
                    init_tag: chunk.value.init_tag,
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

                self.socket.send_to(&init_ack.raw, peer_addr).await?;
                self.cookie = Some(cookie);
                self.remote_tsn = Some(chunk.value.init_tsn.wrapping_sub(1));
                Ok(())
            }
            Chunk::CookieEcho(chunk) => match &self.cookie {
                None => {
                    anyhow::bail!(anyhow!("cookie not created."));
                }
                Some(cookie) => {
                    if cookie != &chunk.value.cookie {
                        anyhow::bail!(anyhow!("invalid cookie."));
                    }
                    // TODO: send CookieAck
                    let cookie_ack = CookieAckChunk::new();
                    self.socket.send_to(&cookie_ack.raw, peer_addr).await?;
                    Ok(())
                }
            },
            Chunk::Data(chunk) => {
                // TODO: https://datatracker.ietf.org/doc/html/rfc9260#name-acknowledgement-on-receptio
                match self.remote_tsn {
                    None => {
                        anyhow::bail!(anyhow!("remote tsn none."));
                    }
                    Some(remote_tsn) => {
                        info!("{:?}", chunk);
                        let sack = SackChunk::new(
                            None,
                            SackChunkValue {
                                cumulative_tsn_ack: remote_tsn,
                                a_rwnd: self.local_a_rwnd,
                                gap_ack_blocks: vec![],
                                dup_tsns: vec![],
                            },
                        );
                        self.socket.send_to(&sack.raw, peer_addr).await?;
                        self.remote_tsn = Some(remote_tsn.wrapping_add(1));
                        Ok(())
                    }
                }
            }
            Chunk::Sack(chuck) => {
                // TODO: https://datatracker.ietf.org/doc/html/rfc9260#sec_processing_of_received_sack
                Ok(())
            }
            Chunk::NotImplemented => Ok(()),
        }
    }
}
