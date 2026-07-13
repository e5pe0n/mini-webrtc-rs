use anyhow::{Result, anyhow};
use tokio::sync::{Mutex, mpsc::UnboundedSender};

use crate::{
    common::buffer::BufReader,
    internal_event::InternalEvent,
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
use tracing::debug;

pub struct SrtpManager {
    gcm: Option<SrtpGcm>,
    ssrc_states: HashMap<u32, SrtpSsrcState>,
    media_track_tx: Option<UnboundedSender<RtpPacket>>,
    _event_queue: Arc<Mutex<VecDeque<InternalEvent>>>,
}

impl SrtpManager {
    pub fn new(event_queue: Arc<Mutex<VecDeque<InternalEvent>>>) -> Self {
        Self {
            gcm: None,
            ssrc_states: HashMap::new(),
            media_track_tx: None,
            _event_queue: event_queue,
        }
    }

    /// Registers the sink that receives decrypted RTP packets. The application
    /// consumes them through a [`crate::media_track::MediaTrackStream`].
    pub fn set_media_track_transport(&mut self, media_track_tx: UnboundedSender<RtpPacket>) {
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

        let Some(media_track_tx) = self.media_track_tx.as_ref() else {
            debug!("ignore rtp packet; media track tx not ready.");
            return Ok(());
        };

        media_track_tx.send(decrypted_packet)?;
        Ok(())
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
