use crate::common::buffer::{BufReader, BufWriter};
use crate::dtls::manager::DtlsManager;
use crate::dtls::{DtlsMessage, DtlsState, Fingerprint, is_dtls_packet};
use crate::ice::IceAgent;
use crate::srtp::header::PayloadType;
use crate::srtp::packet::{RtpPacket, SrtpPacketIndex};
use crate::srtp::{SrtpSsrcState, is_rtp_packet};
use crate::stun::{
    AttributeType, MAGIC_COOKIE, StunMessage, StunMessageBuilder, StunMessageClass,
    StunMessageMethod, StunMessageType,
};
use anyhow::{Result, anyhow};
use rcgen::{CertifiedKey, KeyPair};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

pub struct UdpServer {
    ice_agent: IceAgent,
    socket: Arc<UdpSocket>,
    dtls_manager: DtlsManager,
}

impl UdpServer {
    pub async fn new(
        addr: &str,
        certified_key: CertifiedKey<KeyPair>,
        fingerprint: Fingerprint,
        ice_agent: IceAgent,
    ) -> Result<Self> {
        // Bind UDP socket
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!("Udp Server listening on {}", addr);

        let dtls_manager = DtlsManager::new(socket.clone(), certified_key, fingerprint);

        Ok(UdpServer {
            ice_agent,
            socket,
            dtls_manager,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        loop {
            // Receive data from client
            let (len, peer_addr) = self.socket.recv_from(&mut buf).await?;
            debug!("Received {} bytes from {}", len, peer_addr);

            // Parse DTLS handshake message
            self.handle_message(&buf[..len], peer_addr).await?;
        }
    }

    async fn handle_message(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        if StunMessage::is_stun_message(data) {
            return self.handle_stun_message(data, peer_addr).await;
        }

        if is_dtls_packet(data) {
            self.dtls_manager
                .handle_dtls_packet(data, peer_addr)
                .await?;
            if matches!(self.dtls_manager.state, DtlsState::Connected) {}
        }

        if is_rtp_packet(data) {
            return self.handle_rtp_packet(data, peer_addr).await;
        }

        info!("ignored unknown data.");
        Ok(())
    }

    async fn handle_rtp_packet(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        let _ = data;
        let _ = peer_addr;
        warn!("received RTP packet, but SRTP decrypt path is not wired in UdpServer yet");
        Ok(())
    }

    async fn handle_decrypted_rtp_packet(
        &mut self,
        packet: RtpPacket,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        match packet.header.payload_type {
            PayloadType::VP8 => {}
            _ => warn!("unsupported payload type: {:?}", packet.header.payload_type),
        }
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
        // https://datatracker.ietf.org/doc/html/rfc8445#section-7.2.2
        // - verify username in the message
        let username = unsafe { String::from_utf8_unchecked(username_attr.value.clone()) };
        let expected_username = self.ice_agent.local_peer.ufrag.clone()
            + ":"
            + &self.ice_agent.remote_peer.as_ref().unwrap().ufrag.clone();
        if username != expected_username {
            warn!(
                "username attribute mismatch: expected={expected_username}, actual={username}; ignore the message."
            );
            return Ok(()); // ignore message
        }
        // - verify message integrity
        if !message.verify_message_integrity(self.ice_agent.local_peer.pwd.clone())? {
            warn!("message integrity mismatch; ignore the message.");
            return Ok(()); // ignore message
        }

        // - send stun binding response
        let xor_mapped_address = {
            let mut value_buf = BufWriter::new();
            value_buf.write_u8(0);
            value_buf.write_u8(
                0x0a, // ip v4
            );
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
        .build(self.ice_agent.local_peer.pwd.clone());
        self.socket
            .send_to(&response_message.raw, peer_addr)
            .await?;
        Ok(())
    }
}
