use crate::common::TransportMessage;
use crate::data_channel::{DataChannel, InternalDataChannelMessage};
use crate::dtls::Fingerprint;
use crate::dtls::manager::DtlsManager;
use crate::sctp::manager::SctpManager;
use crate::srtp::SrtpManager;
use crate::srtp::crypto::SrtpEncryptionKeys;
use crate::{
    ice::{IceAgent, IceCandidate},
    signaling_server::SignalingServer,
    stun::StunClient,
    udp_server::UdpServer,
};
use anyhow::{Context, Result, anyhow};
use local_ip_address::local_ip;
use rcgen::generate_simple_self_signed;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{info, warn};

const UDP_SERVER_PORT: u64 = 4433;
const STUN_SERVER_ADDRESS: &'static str = "stun.l.google.com:19302";

pub struct PeerConnection {
    sctp_manager: Arc<Mutex<SctpManager>>,
    udp_server_handle: JoinHandle<Result<()>>,
    signaling_server_handle: JoinHandle<Result<()>>,
    dtls_manager_handle: JoinHandle<Result<()>>,
    srtp_manager_handle: JoinHandle<Result<()>>,
    sctp_manager_handle: JoinHandle<Result<()>>,
}

impl PeerConnection {
    pub async fn new() -> Result<Self> {
        tracing_subscriber::fmt::init();

        // Generate self-signed certificate
        let certified_key = generate_simple_self_signed(vec!["localhost".to_string()])?;
        let fingerprint = Fingerprint::new(certified_key.cert.der());

        let local_ip = local_ip().unwrap();
        info!("local_ip={local_ip:?}");

        let mut stun_addrs = STUN_SERVER_ADDRESS
            .to_socket_addrs()
            .context("resolve STUN server address")?;
        let stun_addr = stun_addrs
            .find(|addr| addr.is_ipv4())
            .or_else(|| stun_addrs.next())
            .ok_or(anyhow!("resolved STUN server address list is empty"))?;
        let stun_client = StunClient::new(stun_addr);

        let mut ice_candidates = vec![IceCandidate {
            ip: local_ip,
            port: UDP_SERVER_PORT,
        }];

        match stun_client.binding_request().await {
            Ok(mapped_address) => {
                info!("mapped_address={mapped_address:?}");
                ice_candidates.push(IceCandidate {
                    ip: mapped_address.ip(),
                    port: UDP_SERVER_PORT,
                });
            }
            Err(err) => {
                warn!("stun mapping failed; continue with host candidate only: {err}");
            }
        }

        let ice_agent = Arc::new(Mutex::new(IceAgent::new(
            ice_candidates,
            fingerprint.clone(),
        )));

        let (inbound_dtls_tx, inbound_dtls_rx) = mpsc::unbounded_channel::<TransportMessage>();
        let (outbound_dtls_tx, outbound_dtls_rx) = mpsc::unbounded_channel::<TransportMessage>();

        let (inbound_rtp_tx, inbound_rtp_rx) = mpsc::unbounded_channel::<TransportMessage>();
        let (encryption_keys_tx, encryption_keys_rx) =
            mpsc::unbounded_channel::<SrtpEncryptionKeys>();

        let (inbound_sctp_tx, inbound_sctp_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (outbound_sctp_tx, outbound_sctp_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        let mut dtls_manager = DtlsManager::new(
            // inbound_message_rx,
            // outbound_message_tx,
            certified_key,
            fingerprint,
            inbound_dtls_rx,
            outbound_dtls_tx,
            inbound_sctp_tx,
            outbound_sctp_rx,
            encryption_keys_tx,
        );
        let mut srtp_manager = SrtpManager::new(inbound_rtp_rx, encryption_keys_rx);
        let sctp_manager = SctpManager::new(outbound_sctp_tx, inbound_sctp_rx);
        let sctp_manager = Arc::new(Mutex::new(sctp_manager));
        let sctp_manager_clone = sctp_manager.clone();

        let udp_server = UdpServer::new(
            &format!("0.0.0.0:{UDP_SERVER_PORT}"),
            ice_agent.clone(),
            inbound_dtls_tx,
            outbound_dtls_rx,
            inbound_rtp_tx,
        )
        .await
        .context("init udp server")?;
        let signaling_server = SignalingServer::new(ice_agent).await;

        let udp_server_handle = tokio::spawn(async move {
            let mut udp_server = udp_server;
            udp_server.run().await
        });
        let dtls_manager_handle = tokio::spawn(async move { dtls_manager.run().await });
        let srtp_manager_handle = tokio::spawn(async move { srtp_manager.run().await });
        let sctp_manager_handle =
            tokio::spawn(async move { sctp_manager_clone.lock().await.run().await });
        let signaling_server_handle = tokio::spawn(async move { signaling_server.run().await });

        Ok(Self {
            udp_server_handle,
            dtls_manager_handle,
            srtp_manager_handle,
            sctp_manager_handle,
            signaling_server_handle,
            sctp_manager,
        })
    }

    pub async fn close(self) {
        self.udp_server_handle.abort();
        self.signaling_server_handle.abort();
        drop(self)
    }

    pub async fn create_data_channel(&self) -> Result<DataChannel> {
        let (inbound_dc_tx, inbound_dc_rx) =
            mpsc::unbounded_channel::<InternalDataChannelMessage>();
        let (outbound_dc_tx, outbound_dc_rx) =
            mpsc::unbounded_channel::<InternalDataChannelMessage>();
        self.sctp_manager
            .lock()
            .await
            .set_data_channel_transport(inbound_dc_tx, outbound_dc_rx);
        Ok(DataChannel::new(0, inbound_dc_rx, outbound_dc_tx))
    }
}
