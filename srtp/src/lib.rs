pub mod crypto;
pub mod header;
pub mod packet;

use crate::packet::SrtpPacketIndex;

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
    let payload_type = data[1] & 0b01111111;
    payload_type <= 35 || (payload_type >= 96 && payload_type <= 127)
}

pub struct SrtpSsrcState {
    pub ssrc: u32,
    pub index: SrtpPacketIndex,
    pub rollover_has_processed: bool,
}
