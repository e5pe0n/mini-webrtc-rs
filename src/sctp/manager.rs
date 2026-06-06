use std::{net::SocketAddr, sync::Arc, u16};

use anyhow::Result;
use rand::random;
use tokio::net::UdpSocket;
use tracing::warn;

use crate::{
    common::buffer::BufReader,
    sctp::{
        chunk::{
            Chunk,
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
}

impl SctpManager {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            a_rwnd: 1024 * 1024,
            max_num_outbound_streams: u16::MAX,
            max_num_inbound_streams: u16::MAX,
            tsn: random::<u32>(),
        }
    }

    pub async fn handle_sctp_packet(&self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        let mut reader = BufReader::new(data);
        let packet = SctpPacket::decode(&mut reader)?;

        if packet.chunks.len() == 0 {
            warn!("no chunks in packet");
            return Ok(());
        }

        match &packet.chunks[0] {
            Chunk::Init(chunk) => {
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
                    params: vec![],
                });

                self.socket.send_to(&init_ack.raw, peer_addr).await?;
                Ok(())
            }
        }
    }
}
