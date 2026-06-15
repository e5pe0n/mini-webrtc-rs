use anyhow::{Result, anyhow};
use tokio::{select, sync::mpsc::UnboundedReceiver};

use crate::{
    common::{TransportMessage, buffer::BufReader},
    srtp::{
        SrtpSsrcState,
        crypto::{SrtpEncryptionKeys, SrtpGcm},
        packet::{RtpPacket, SrtpPacketIndex},
    },
};
use std::{
    collections::HashMap,
    env,
    net::{SocketAddr, UdpSocket},
};
use tracing::{info, warn};

const LIVE_VIDEO_FORWARD_ADDR: &str = "127.0.0.1:5004";
const LIVE_VIDEO_FORWARD_ENABLED_ENV: &str = "MINI_WEBRTC_LIVE_RTP_FORWARD";

pub struct SrtpManager {
    gcm: Option<SrtpGcm>,
    ssrc_states: HashMap<u32, SrtpSsrcState>,
    rtp_forward_socket: Option<UdpSocket>,
    rtp_forward_addr: SocketAddr,
    forwarded_rtp_packets: u64,
    inbound_rtp_rx: UnboundedReceiver<TransportMessage>,
    encryption_keys_rx: UnboundedReceiver<SrtpEncryptionKeys>,
}

impl SrtpManager {
    pub fn new(
        inbound_rtp_rx: UnboundedReceiver<TransportMessage>,
        encryption_keys_rx: UnboundedReceiver<SrtpEncryptionKeys>,
    ) -> Self {
        let rtp_forward_addr = LIVE_VIDEO_FORWARD_ADDR
            .parse()
            .expect("invalid LIVE_VIDEO_FORWARD_ADDR");
        let rtp_forward_socket = if is_live_video_forward_enabled() {
            match UdpSocket::bind("127.0.0.1:0") {
                Ok(socket) => Some(socket),
                Err(err) => {
                    warn!("failed to initialize local RTP forwarding socket for live view: {err}");
                    None
                }
            }
        } else {
            info!(
                "live RTP forwarding disabled by env {}",
                LIVE_VIDEO_FORWARD_ENABLED_ENV
            );
            None
        };

        if rtp_forward_socket.is_some() {
            info!(
                "SRTP decrypt path will forward plaintext RTP to {} for local viewers",
                LIVE_VIDEO_FORWARD_ADDR
            );
        }

        Self {
            gcm: None,
            ssrc_states: HashMap::new(),
            rtp_forward_socket,
            rtp_forward_addr,
            forwarded_rtp_packets: 0,
            inbound_rtp_rx,
            encryption_keys_rx,
        }
    }

    pub fn set_encryption_keys(&mut self, srtp_encryption_keys: SrtpEncryptionKeys) {
        // use client key and salt to decrypt data from client
        self.gcm = Some(SrtpGcm::new(
            &srtp_encryption_keys.client_master_key,
            &srtp_encryption_keys.client_master_salt,
        ));
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            select! {
                inbound_srtp = self.inbound_rtp_rx.recv() => {
                    if let Some(message) = inbound_srtp {
                        self.handle_rtp_packet(&message.data, message.peer_addr)?;
                    }
                }
                encryption_keys = self.encryption_keys_rx.recv() => {
                    if let Some(encryption_keys) = encryption_keys {
                        self.set_encryption_keys(encryption_keys);
                    }
                }
            }
        }
    }

    pub fn handle_rtp_packet(&mut self, data: &[u8], _peer_addr: SocketAddr) -> Result<()> {
        let mut packet_reader = BufReader::new(data);
        let packet = RtpPacket::decode(&mut packet_reader)?;

        let decrypted_packet = self.decrypt(packet)?;
        self.forward_decrypted_packet(&decrypted_packet);
        Ok(())
    }

    fn forward_decrypted_packet(&mut self, packet: &RtpPacket) {
        let Some(socket) = self.rtp_forward_socket.as_ref() else {
            return;
        };

        let mut raw_rtp = Vec::with_capacity(packet.header_size + packet.payload.len());
        raw_rtp.extend_from_slice(&packet.raw[..packet.header_size]);
        raw_rtp.extend_from_slice(&packet.payload);

        if let Err(err) = socket.send_to(&raw_rtp, self.rtp_forward_addr) {
            warn!(
                "failed to forward decrypted RTP packet to {}: {}",
                self.rtp_forward_addr, err
            );
            return;
        }

        self.forwarded_rtp_packets += 1;
        if self.forwarded_rtp_packets == 1 {
            info!(
                "forwarded first decrypted RTP packet to {} (pt={:?}, ssrc=0x{:08x})",
                self.rtp_forward_addr, packet.header.payload_type, packet.header.ssrc
            );
        }
    }

    fn decrypt(&mut self, packet: RtpPacket) -> Result<RtpPacket> {
        let ssrc = packet.header.ssrc;
        let sequence_number = packet.header.sequence_number;
        let packet_index = {
            let ssrc_state = self.ssrc_states.entry(ssrc).or_insert(SrtpSsrcState {
                ssrc,
                index: SrtpPacketIndex {
                    roc: 0,
                    seq: sequence_number,
                },
                rollover_has_processed: false,
            });
            ssrc_state.estimate_packet_index(sequence_number)
        };

        let decrypted_packet = self
            .gcm
            .clone()
            .ok_or(anyhow!("failed to decrypt srtp packet; srtp gcm is none."))?
            .decrypt(packet, packet_index.roc)?;

        let ssrc_state = self
            .ssrc_states
            .get_mut(&ssrc)
            .ok_or(anyhow!("ssrc state not found; ssrc={ssrc}"))?;
        ssrc_state.commit_packet_index(packet_index);

        Ok(decrypted_packet)
    }
}

fn is_live_video_forward_enabled() -> bool {
    match env::var(LIVE_VIDEO_FORWARD_ENABLED_ENV) {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}
