use mini_webrtc_derive::TryFromPrimitive;

use crate::common::{buffer::BufReader, error::MiniWebrtcRsError};

// https://datatracker.ietf.org/doc/html/rfc8832
#[derive(Debug, TryFromPrimitive)]
#[try_from(type = "u8")]
pub enum MessageType {
    DataChannelAck = 0x02,
    DataChannelOpen = 0x03,
}

// https://datatracker.ietf.org/doc/html/rfc8832#iana_channel_type
#[derive(Debug, TryFromPrimitive)]
#[try_from(type = "u8")]
pub enum ChannelType {
    DataChannelReliable = 0x00,
    DataChannelReliableUnordered = 0x80,
    DataChannelPartialReliableRexmit = 0x01,
    DataChannelPartialReliableRexmitUnordered = 0x81,
    DataChannelPartialReliableTimed = 0x02,
    DataChannelPartialReliableTimedUnordered = 0x82,
}

pub enum DcepMessage {
    DataChannelAck(DataChannelAckMessage),
    DataChannelOpen(DataChannelOpenMessage),
}

// https://datatracker.ietf.org/doc/html/rfc8832#name-data_channel_open-message
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Message Type |  Channel Type |            Priority           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Reliability Parameter                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Label Length          |       Protocol Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// \                                                               /
// |                             Label                             |
// /                                                               \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// \                                                               /
// |                            Protocol                           |
// /                                                               \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub struct DataChannelOpenMessage {
    message_type: MessageType,
    channel_type: ChannelType,
    priority: u16,
    reliability_param: u32,
    label: Vec<u8>,
    protocol: Vec<u8>,
}

impl DataChannelOpenMessage {
    pub fn decode(reader: &mut BufReader) -> Result<Self, MiniWebrtcRsError> {
        let message_type = reader.read_u8()?;
        let channel_type = reader.read_u8()?;
        let priority = reader.read_u16()?;
        let reliability_param = reader.read_u32()?;
        let label_length = reader.read_u16()?;
        let protocol_length = reader.read_u16()?;
        let mut label = vec![0u8; label_length as usize];
        let mut protocol = vec![0u8; protocol_length as usize];
        reader.read_exact(&mut label)?;
        reader.read_exact(&mut protocol)?;

        Ok(Self {
            message_type: MessageType::try_from(message_type)?,
            channel_type: ChannelType::try_from(channel_type)?,
            priority,
            reliability_param,
            label,
            protocol,
        })
    }
}

pub struct DataChannelAckMessage {
    message_type: MessageType,
}

impl DataChannelAckMessage {
    pub fn decode(reader: &mut BufReader) -> Result<Self, MiniWebrtcRsError> {
        let message_type = reader.read_u8()?;
        Ok(Self {
            message_type: MessageType::try_from(message_type)?,
        })
    }
}
