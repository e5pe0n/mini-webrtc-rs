use crate::common::buffer::{BufReader, BufWriter};
use crate::dtls::manager::DtlsManager;
use crate::dtls::{DtlsState, Fingerprint, is_dtls_packet};
use crate::ice::IceAgent;
use crate::srtp::{SrtpManager, is_rtcp_packet, is_rtp_packet};
use crate::stun::{
    AttributeType, IpFamily, MAGIC_COOKIE, StunMessage, StunMessageBuilder, StunMessageClass,
    StunMessageMethod, StunMessageType,
};
use anyhow::{Result, anyhow};
use rcgen::{CertifiedKey, KeyPair};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

pub struct UdpServer {
    ice_agent: Arc<Mutex<IceAgent>>,
    socket: Arc<UdpSocket>,
    dtls_manager: DtlsManager,
    srtp_manager: Option<SrtpManager>,
    logged_first_dtls_packet: bool,
    logged_first_stun_response: bool,
}

impl UdpServer {
    pub async fn new(
        addr: &str,
        certified_key: CertifiedKey<KeyPair>,
        fingerprint: Fingerprint,
        ice_agent: Arc<Mutex<IceAgent>>,
    ) -> Result<Self> {
        // Bind UDP socket
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!("Udp Server listening on {}", addr);

        let dtls_manager = DtlsManager::new(socket.clone(), certified_key, fingerprint);

        Ok(UdpServer {
            ice_agent,
            socket,
            dtls_manager,
            srtp_manager: None,
            logged_first_dtls_packet: false,
            logged_first_stun_response: false,
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
            info!("stun message received");
            return self.handle_stun_message(data, peer_addr).await;
        }

        if is_dtls_packet(data) {
            info!("dtls packet received");
            if !self.logged_first_dtls_packet {
                info!("received first dtls packet from {peer_addr}");
                self.logged_first_dtls_packet = true;
            }
            if let Err(err) = self.dtls_manager.handle_dtls_packet(data, peer_addr).await {
                if matches!(self.dtls_manager.state, DtlsState::Connected) {
                    warn!(
                        "ignored dtls packet parse error after connected; peer={peer_addr}; error={err:#}"
                    );
                    return Ok(());
                }
                return Err(err);
            }
            if self.srtp_manager.is_none()
                && matches!(self.dtls_manager.state, DtlsState::Connected)
            {
                let srtp_encryption_keys = self.dtls_manager.export_keying_material()?;
                self.srtp_manager = Some(SrtpManager::new(srtp_encryption_keys));
                info!("srtp manager initialized after dtls connected");
            }
            return Ok(());
        }

        if is_rtp_packet(data) {
            info!("rtp packet received");
            return self.handle_rtp_packet(data, peer_addr).await;
        }

        if is_rtcp_packet(data) {
            info!(
                "rtcp-like packet received; peer={}, len={}, pt={}",
                peer_addr,
                data.len(),
                data[1]
            );
            return Ok(());
        }

        info!(
            "ignored unknown data; peer={}, len={}, first_byte=0x{:02x}",
            peer_addr,
            data.len(),
            data[0]
        );
        Ok(())
    }

    async fn handle_rtp_packet(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        if let Some(srtp_manager) = self.srtp_manager.as_mut() {
            if let Err(err) = srtp_manager.handle_rtp_packet(data, peer_addr) {
                warn!(
                    "failed to handle RTP/SRTP packet; peer={peer_addr}; len={}; error={err:#}",
                    data.len()
                );
            }
        } else {
            warn!("received RTP packet before SRTP is ready; peer={peer_addr}");
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
        let (local_ufrag, local_pwd, remote_ufrag) = {
            let ice_agent = self.ice_agent.lock().await;
            (
                ice_agent.local_peer.ufrag.clone(),
                ice_agent.local_peer.pwd.clone(),
                ice_agent.remote_peer.as_ref().map(|p| p.ufrag.clone()),
            )
        };
        // https://datatracker.ietf.org/doc/html/rfc8445#section-7.2.2
        // - verify username in the message
        let username = unsafe { String::from_utf8_unchecked(username_attr.value.clone()) };

        if let Some(remote_ufrag) = remote_ufrag {
            let expected_username = format!("{local_ufrag}:{remote_ufrag}");
            if username != expected_username {
                warn!(
                    "username attribute mismatch: actual={username}, expected={expected_username}; ignore the message."
                );
                return Ok(()); // ignore message
            }
        } else {
            warn!("remote ufrag not configured; ignore the message.");
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
        if !self.logged_first_stun_response {
            info!("sent first stun binding success response to {peer_addr}");
            self.logged_first_stun_response = true;
        }
        Ok(())
    }
}
