use std::{net::SocketAddr, sync::Arc, u16};

use anyhow::{Result, anyhow};
use rand::{RngExt, random};
use tokio::net::UdpSocket;
use tracing::warn;

use crate::{
    common::buffer::BufReader,
    sctp::{
        chunk::{
            COOKIE_LENGTH_IN_BYTES, Chunk, ChunkParam,
            cookie_ack::CookieAckChunk,
            init_ack::{InitAckChunk, InitAckChunkValue},
        },
        packet::SctpPacket,
    },
};

pub struct SctpManager {
    pub socket: Arc<UdpSocket>,
    a_rwnd: u32,
    max_num_outbound_streams: u16,
    max_num_inbound_streams: u16,
    tsn: u32,
    cookie: Option<Vec<u8>>,
}

impl SctpManager {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            a_rwnd: 1024 * 1024,
            max_num_outbound_streams: u16::MAX,
            max_num_inbound_streams: u16::MAX,
            tsn: random::<u32>(),
            cookie: None,
        }
    }

    pub async fn handle_sctp_packet(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        let mut reader = BufReader::new(data);
        let packet = SctpPacket::decode(&mut reader)?;

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
                    a_rwnd: self.a_rwnd,
                    num_outbound_streams: u16::min(
                        self.max_num_outbound_streams,
                        chunk.value.num_outbound_streams,
                    ),
                    num_inbound_streams: u16::min(
                        self.max_num_inbound_streams,
                        chunk.value.num_inbound_streams,
                    ),
                    init_tsn: self.tsn,
                    params: vec![ChunkParam::StateCookie(cookie.clone())],
                });

                self.socket.send_to(&init_ack.raw, peer_addr).await?;
                self.cookie = Some(cookie);
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
                // TODO: handle data
                // TODO: send SACK
                Ok(())
            }
        }
    }
}
