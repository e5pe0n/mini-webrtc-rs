use anyhow::{Result, anyhow};
use tokio::sync::{Mutex, mpsc::UnboundedSender};

use crate::{
    common::buffer::BufReader,
    event_loop::InternalEvent,
    media_track::MediaPacket,
    srtp::{
        SrtpSsrcState,
        crypto::{SrtpEncryptionKeys, SrtpGcm},
        packet::{RtpPacket, SrtpPacketIndex},
    },
};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
};
use tracing::{info, warn};

pub struct SrtpManager {
    gcm: Option<SrtpGcm>,
    ssrc_states: HashMap<u32, SrtpSsrcState>,
    media_track_tx: Option<UnboundedSender<MediaPacket>>,
    dispatched_rtp_packets: u64,
    _event_queue: Arc<Mutex<VecDeque<InternalEvent>>>,
}

impl SrtpManager {
    pub fn new(event_queue: Arc<Mutex<VecDeque<InternalEvent>>>) -> Self {
        Self {
            gcm: None,
            ssrc_states: HashMap::new(),
            media_track_tx: None,
            dispatched_rtp_packets: 0,
            _event_queue: event_queue,
        }
    }

    /// Registers the sink that receives decrypted RTP packets. The application
    /// consumes them through a [`crate::media_track::MediaTrackStream`].
    pub fn set_media_track_transport(&mut self, media_track_tx: UnboundedSender<MediaPacket>) {
        self.media_track_tx = Some(media_track_tx);
    }

    pub fn set_encryption_keys(&mut self, srtp_encryption_keys: SrtpEncryptionKeys) {
        // use client key and salt to decrypt data from client
        self.gcm = Some(SrtpGcm::new(
            &srtp_encryption_keys.client_master_key,
            &srtp_encryption_keys.client_master_salt,
        ));
    }

    pub fn handle_inbound_packet(&mut self, data: &[u8], _peer_addr: SocketAddr) -> Result<()> {
        let mut packet_reader = BufReader::new(data);
        let packet = RtpPacket::decode(&mut packet_reader)?;

        let decrypted_packet = self.decrypt(packet)?;
        self.dispatch_media_packet(&decrypted_packet);
        Ok(())
    }

    fn dispatch_media_packet(&mut self, packet: &RtpPacket) {
        let Some(media_track_tx) = self.media_track_tx.as_ref() else {
            return;
        };

        let mut rtp = Vec::with_capacity(packet.header_size + packet.payload.len());
        rtp.extend_from_slice(&packet.raw[..packet.header_size]);
        rtp.extend_from_slice(&packet.payload);

        // The payload type is the low 7 bits of the second RTP header byte.
        let payload_type = packet.raw.get(1).map(|byte| byte & 0b0111_1111).unwrap_or(0);
        let media_packet = MediaPacket {
            ssrc: packet.header.ssrc,
            payload_type,
            sequence_number: packet.header.sequence_number,
            timestamp: packet.header.timestamp,
            marker: packet.header.marker,
            rtp,
        };

        if media_track_tx.send(media_packet).is_err() {
            // The media track stream was dropped; stop dispatching packets.
            self.media_track_tx = None;
            warn!("media track stream dropped; stop dispatching decrypted RTP packets");
            return;
        }

        self.dispatched_rtp_packets += 1;
        if self.dispatched_rtp_packets == 1 {
            info!(
                "dispatched first decrypted RTP packet to media track (pt={:?}, ssrc=0x{:08x})",
                packet.header.payload_type, packet.header.ssrc
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
