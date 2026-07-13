use crate::common::TransportMessage;
use crate::common::buffer::{BufReader, BufWriter};
use crate::dtls::is_dtls_packet;
use crate::ice::{IceAgent, Peer};
use crate::internal_event::{EventQueue, InternalEvent};
use crate::srtp::{is_rtcp_packet, is_rtp_packet};
use crate::stun::{
    AttributeType, IpFamily, MAGIC_COOKIE, StunMessage, StunMessageBuilder, StunMessageClass,
    StunMessageMethod, StunMessageType,
};
use anyhow::{Result, anyhow};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

pub struct UdpServer {
    pub ice_agent: Arc<Mutex<IceAgent>>,
    pub socket: Arc<UdpSocket>,
    event_queue: Arc<Mutex<EventQueue>>,
}

impl UdpServer {
    pub async fn new(
        addr: &str,
        ice_agent: Arc<Mutex<IceAgent>>,
        event_queue: Arc<Mutex<EventQueue>>,
    ) -> Result<Self> {
        // Bind UDP socket
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!("Udp Server listening on {}", addr);

        Ok(UdpServer {
            ice_agent,
            socket,
            event_queue,
        })
    }

    pub async fn recv(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        let (len, peer_addr) = self.socket.recv_from(&mut buf).await?;
        debug!("Received {} bytes from {}", len, peer_addr);

        self.handle_inbound_message(&buf[..len], peer_addr).await
    }

    pub async fn send(&self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        self.socket.send_to(&data, peer_addr).await?;
        debug!("Sent {} bytes to {}", &data.len(), peer_addr);
        Ok(())
    }

    pub async fn set_remote_peers(&mut self, peers: Vec<Peer>) {
        self.ice_agent.lock().await.remote_peers = peers;
    }

    async fn handle_inbound_message(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        if StunMessage::is_stun_message(data) {
            debug!("stun message received");
            return self.handle_stun_message(data, peer_addr).await;
        }

        if is_dtls_packet(data) {
            debug!("dtls packet received");
            self.event_queue
                .lock()
                .await
                .push_back(InternalEvent::InboundDtlsPacket(TransportMessage {
                    peer_addr,
                    data: data.to_vec(),
                }));
            return Ok(());
        }

        if is_rtp_packet(data) {
            debug!("rtp packet received");
            self.event_queue
                .lock()
                .await
                .push_back(InternalEvent::InboundRtpPacket(TransportMessage {
                    peer_addr,
                    data: data.to_vec(),
                }));
            return Ok(());
        }

        if is_rtcp_packet(data) {
            debug!(
                "rtcp-like packet received; peer={}, len={}, pt={}",
                peer_addr,
                data.len(),
                data[1]
            );
            return Ok(());
        }

        debug!(
            "ignored unknown data; peer={}, len={}, first_byte=0x{:02x}",
            peer_addr,
            data.len(),
            data[0]
        );
        Ok(())
    }

    async fn handle_stun_message(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        // respond to stun binding request of ice
        // - decode stun message
        let mut reader = BufReader::new(data);
        let message = StunMessage::decode(&mut reader)?;
        // - extract server username and client username
        let username_attr = message
            .attributes
            .get(&AttributeType::Username)
            .ok_or(anyhow!("username attribute does not exists."))?;
        let (local_ufrag, local_pwd, remote_ufrags) = {
            let ice_agent = self.ice_agent.lock().await;
            (
                ice_agent.local_peer.ufrag.clone(),
                ice_agent.local_peer.pwd.clone(),
                ice_agent
                    .remote_peers
                    .iter()
                    .map(|peer| peer.ufrag.clone())
                    .collect::<Vec<_>>(),
            )
        };

        if remote_ufrags.is_empty() {
            warn!("remote ufrags not configured; ignore the message.");
            return Ok(()); // ignore message
        }

        // https://datatracker.ietf.org/doc/html/rfc8445#section-7.2.2
        // - verify username in the message
        let username = unsafe { String::from_utf8_unchecked(username_attr.value.clone()) };

        let expected_usernames = remote_ufrags
            .iter()
            .map(|remote_ufrag| format!("{local_ufrag}:{remote_ufrag}"))
            .collect::<Vec<_>>();
        if !expected_usernames.contains(&username) {
            warn!(
                "username attribute mismatch: actual={username}, expected={expected_usernames:?}; ignore the message."
            );
            return Ok(()); // ignore message
        }

        // - verify message integrity
        message.verify_message_integrity(local_pwd.clone())?;

        // - send stun binding response
        let xor_mapped_address = {
            let mut value_buf = BufWriter::new();
            value_buf.write_u8(0);
            value_buf.write_u8(IpFamily::V4 as u8);
            let x_port = peer_addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            value_buf.write_u16(x_port);
            let ip_addr_bytes = match peer_addr.ip() {
                IpAddr::V4(addr) => addr.octets(),
                IpAddr::V6(addr) => {
                    return Err(anyhow!("ip address is not ipv4; {addr}"));
                }
            };
            for (i, octet) in ip_addr_bytes.iter().enumerate() {
                value_buf.write_u8(octet ^ (MAGIC_COOKIE >> (8 * (3 - i))) as u8);
            }
            value_buf.buf()
        };
        let response_message = StunMessageBuilder::new(
            StunMessageType {
                method: StunMessageMethod::Binding,
                class: StunMessageClass::SuccessResponse,
            },
            message.transaction_id,
        )
        .add_attr(AttributeType::XorMappedAddress, &xor_mapped_address)
        .add_attr(AttributeType::Username, &username_attr.value[..])
        .build(local_pwd);
        self.socket
            .send_to(&response_message.raw, peer_addr)
            .await?;
        Ok(())
    }
}
