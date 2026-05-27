pub mod crypto;
pub mod header;
pub mod manager;
pub mod packet;

use crate::srtp::packet::SrtpPacketIndex;

pub use manager::SrtpManager;

//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |V=2|P|X|  CC   |M|     PT      |       sequence number         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                           timestamp                           |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |           synchronization source (SSRC) identifier            |
//    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//    |            contributing source (CSRC) identifiers             |
//    |                             ....                              |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// https://datatracker.ietf.org/doc/html/rfc3550#section-5.1
pub fn is_rtp_packet(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }

    let version = (data[0] & 0b1100_0000) >> 6;
    if version != 2 {
        return false;
    }

    let payload_type = data[1] & 0b01111111;
    payload_type <= 35 || (payload_type >= 96 && payload_type <= 127)
}

// https://datatracker.ietf.org/doc/html/rfc5761#section-4
pub fn is_rtcp_packet(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }

    let version = (data[0] & 0b1100_0000) >> 6;
    if version != 2 {
        return false;
    }

    let packet_type = data[1];
    (192..=223).contains(&packet_type)
}

pub struct SrtpSsrcState {
    pub ssrc: u32,
    pub index: SrtpPacketIndex,
    pub rollover_has_processed: bool,
}

impl SrtpSsrcState {
    pub fn estimate_packet_index(&self, sequence_number: u16) -> SrtpPacketIndex {
        if !self.rollover_has_processed {
            return SrtpPacketIndex {
                roc: self.index.roc,
                seq: sequence_number,
            };
        }

        let mut candidate_indexes = vec![
            SrtpPacketIndex {
                roc: self.index.roc,
                seq: sequence_number,
            },
            SrtpPacketIndex {
                roc: self.index.roc + 1,
                seq: sequence_number,
            },
        ];
        if self.index.roc > 0 {
            candidate_indexes.push(SrtpPacketIndex {
                roc: self.index.roc - 1,
                seq: sequence_number,
            });
        }

        let mut min_index = candidate_indexes[0];
        let mut min_diff = min_index.value().abs_diff(self.index.value());
        for candidate_index in &candidate_indexes[1..] {
            let diff = candidate_index.value().abs_diff(self.index.value());
            if diff < min_diff {
                min_diff = diff;
                min_index = *candidate_index;
            }
        }
        min_index
    }

    pub fn commit_packet_index(&mut self, next_index: SrtpPacketIndex) {
        if !self.rollover_has_processed {
            self.index = next_index;
            self.rollover_has_processed = true;
            return;
        }

        if next_index.value() > self.index.value() {
            self.index = next_index;
        }
    }
}
