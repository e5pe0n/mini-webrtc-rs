use anyhow::{Result, anyhow};

use crate::{
    common::buffer::BufReader,
    srtp::{
        SrtpSsrcState,
        crypto::{SrtpEncryptionKeys, SrtpGcm},
        packet::{RtpPacket, SrtpPacketIndex},
    },
};
use std::{collections::HashMap, net::SocketAddr};

pub struct SrtpManager {
    gcm: SrtpGcm,
    ssrc_states: HashMap<u32, SrtpSsrcState>,
}

impl SrtpManager {
    pub fn new(srtp_encryption_keys: SrtpEncryptionKeys) -> Self {
        // use client key and salt to decrypt data from client
        let srtp_gcm = SrtpGcm::new(
            &srtp_encryption_keys.client_master_key,
            &srtp_encryption_keys.client_master_salt,
        );
        Self {
            gcm: srtp_gcm,
            ssrc_states: HashMap::new(),
        }
    }

    pub fn handle_rtp_packet(&mut self, data: &[u8], _peer_addr: SocketAddr) -> Result<()> {
        let mut packet_reader = BufReader::new(data);
        let packet = RtpPacket::decode(&mut packet_reader)?;

        self.decrypt(packet)?;
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

        let decrypted_packet = self.gcm.decrypt(packet, packet_index.roc)?;

        let ssrc_state = self
            .ssrc_states
            .get_mut(&ssrc)
            .ok_or(anyhow!("ssrc state not found; ssrc={ssrc}"))?;
        ssrc_state.commit_packet_index(packet_index);

        Ok(decrypted_packet)
    }
}
