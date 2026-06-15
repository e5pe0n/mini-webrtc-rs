use crate::data_channel::DataChannel;
use crate::dtls::Fingerprint;
use crate::{
    ice::{IceAgent, IceCandidate},
    signaling_server::SignalingServer,
    stun::StunClient,
    udp_server::{UdpServer, UdpServerControlMessage},
};
use anyhow::{Context, Result, anyhow};
use local_ip_address::local_ip;
use rcgen::generate_simple_self_signed;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{info, warn};

const UDP_SERVER_PORT: u64 = 4433;
const STUN_SERVER_ADDRESS: &'static str = "stun.l.google.com:19302";

pub struct PeerConnection {
    udp_server_handle: JoinHandle<Result<()>>,
    signaling_server_handle: JoinHandle<Result<()>>,
    udp_server_control_tx: UnboundedSender<UdpServerControlMessage>,
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

        let udp_server = UdpServer::new(
            &format!("0.0.0.0:{UDP_SERVER_PORT}"),
            certified_key,
            fingerprint,
            ice_agent.clone(),
        )
        .await
        .context("init udp server")?;
        let signaling_server = SignalingServer::new(ice_agent).await;
        let udp_server_control_tx = udp_server.control_tx.clone();

        let udp_server_handle = tokio::spawn(async move {
            let mut udp_server = udp_server;
            udp_server.run().await
        });
        let signaling_server_handle = tokio::spawn(async move { signaling_server.run().await });

        Ok(Self {
            udp_server_handle,
            signaling_server_handle,
            udp_server_control_tx,
        })
    }

    pub async fn close(self) {
        self.udp_server_handle.abort();
        self.signaling_server_handle.abort();
        drop(self)
    }

    pub async fn create_data_channel(&self) -> Result<DataChannel> {
        let (response_tx, response_rx) = oneshot::channel::<Result<DataChannel>>();
        self.udp_server_control_tx
            .send(UdpServerControlMessage::CreateDataChannel { response_tx })
            .context("send create data channel request")?;
        response_rx
            .await
            .context("receive create data channel response")?
    }
}
