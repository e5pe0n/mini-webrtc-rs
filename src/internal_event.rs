use std::collections::VecDeque;

use crate::{common::TransportMessage, sdp::SdpMessage, srtp::crypto::SrtpEncryptionKeys};

pub type EventQueue = VecDeque<InternalEvent>;

pub enum InternalEvent {
    SdpAnswer(SdpMessage),
    InboundDtlsPacket(TransportMessage),
    OutboundDtlsPacket(TransportMessage),
    InboundSctpPacket(TransportMessage),
    OutboundSctpPacket(TransportMessage),
    InboundRtpPacket(TransportMessage),
    DtlsConnected(SrtpEncryptionKeys),
}
