use crate::common::TransportMessage;
use crate::common::buffer::{BufReader, BufWriter};
use crate::data_channel::{DataChannel, InternalDataChannelMessage};
use crate::dtls::manager::DtlsManager;
use crate::dtls::{DtlsState, Fingerprint, is_dtls_packet};
use crate::ice::IceAgent;
use crate::sctp::manager::SctpManager;
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
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};

pub enum UdpServerControlMessage {
    CreateDataChannel {
        response_tx: oneshot::Sender<Result<DataChannel>>,
    },
}

pub struct UdpServer {
    pub ice_agent: Arc<Mutex<IceAgent>>,
    pub socket: Arc<UdpSocket>,
    pub inbound_message_tx: UnboundedSender<TransportMessage>,
    pub outbound_message_rx: UnboundedReceiver<TransportMessage>,
    pub inbound_dtls_tx: UnboundedSender<TransportMessage>,
    pub inbound_dtls_rx: UnboundedReceiver<TransportMessage>,
    pub dtls_manager: DtlsManager,
    pub srtp_manager: Option<SrtpManager>,
    pub sctp_manager: SctpManager,
    control_rx: UnboundedReceiver<UdpServerControlMessage>,
    pub control_tx: UnboundedSender<UdpServerControlMessage>,
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

        let (inbound_message_tx, inbound_message_rx) =
            mpsc::unbounded_channel::<TransportMessage>();
        let (outbound_message_tx, outbound_message_rx) =
            mpsc::unbounded_channel::<TransportMessage>();

        let (inbound_dtls_tx, inbound_dtls_rx) = mpsc::unbounded_channel::<TransportMessage>();

        let (inbound_sctp_tx, inbound_sctp_rx) = mpsc::unbounded_channel();
        let (outbound_sctp_tx, outbound_sctp_rx) = mpsc::unbounded_channel();
        let (control_tx, control_rx) = mpsc::unbounded_channel::<UdpServerControlMessage>();

        let dtls_manager = DtlsManager::new(
            inbound_message_rx,
            outbound_message_tx,
            certified_key,
            fingerprint,
            inbound_sctp_tx,
            outbound_sctp_rx,
        );
        let sctp_manager = SctpManager::new(outbound_sctp_tx, inbound_sctp_rx);

        Ok(UdpServer {
            ice_agent,
            socket,
            inbound_message_tx,
            outbound_message_rx,
            inbound_dtls_tx,
            inbound_dtls_rx,
            dtls_manager,
            srtp_manager: None,
            sctp_manager,
            control_rx,
            control_tx,
        })
    }

    pub async fn create_data_channel(&mut self) -> Result<DataChannel> {
        let (inbound_dc_tx, inbound_dc_rx) =
            mpsc::unbounded_channel::<InternalDataChannelMessage>();
        let (outbound_dc_tx, outbound_dc_rx) =
            mpsc::unbounded_channel::<InternalDataChannelMessage>();

        self.sctp_manager
            .set_data_channel_transport(inbound_dc_tx, outbound_dc_rx);

        Ok(DataChannel::new(0, inbound_dc_rx, outbound_dc_tx).await)
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                recv_result = self.socket.recv_from(&mut buf) => {
                    let (len, peer_addr) = recv_result?;
                    debug!("Received {} bytes from {}", len, peer_addr);

                    self.handle_inbound_message(&buf[..len], peer_addr).await?;
                }
                outbound_message = self.outbound_message_rx.recv() => {
                    if let Some(message) = outbound_message {
                        self.socket.send_to(&message.data, message.peer_addr).await?;
                        debug!("Sent {} bytes to {}", &message.data.len(), message.peer_addr);
                    }
                }
                _ = self.dtls_manager.recv_outbound_sctp() => {}
                _ = self.sctp_manager.recv() => {}
                control_message = self.control_rx.recv() => {
                    if let Some(UdpServerControlMessage::CreateDataChannel { response_tx }) = control_message {
                        let _ = response_tx.send(self.create_data_channel().await);
                    }
                }
            }
        }
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
            debug!("rtp packet received");
            return self.handle_rtp_packet(data, peer_addr).await;
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
        Ok(())
    }
}
