use std::collections::VecDeque;

use crate::common::TransportMessage;

pub type EventQueue = VecDeque<InternalEvent>;

pub enum InternalEvent {
    InboundDtlsPacket(TransportMessage),
    OutboundDtlsPacket(TransportMessage),
    InboundSctpPacket(TransportMessage),
    OutboundSctpPacket(TransportMessage),
    InboundRtpPacket(TransportMessage),
}

pub struct EventLoop {}

impl EventLoop {
    pub async fn run() {}
}
