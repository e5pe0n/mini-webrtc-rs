mod dtls;
mod error;
mod ice;
mod sdp;
mod signaling_server;
mod stun;
mod udp_server;

use local_ip_address::local_ip;

use anyhow::Result;
use rcgen::generate_simple_self_signed;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::{
    dtls::common::Fingerprint,
    ice::{IceAgent, IceCandidate},
    stun::StunClient,
};
use crate::{signaling_server::SignalingServer, udp_server::UdpServer};

const UDP_SERVER_PORT: u64 = 4433;
const STUN_SERVER_ADDRESS: &'static str = "stun.l.google.com:19302";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Generate self-signed certificate
    let certified_key = generate_simple_self_signed(vec!["localhost".to_string()])?;
    let fingerprint = Fingerprint(Sha256::digest(certified_key.cert.der()));

    let local_ip = local_ip().unwrap();
    info!("local_ip={local_ip:?}");

    let stun_client = StunClient::new(STUN_SERVER_ADDRESS.parse()?);
    let mapped_address = stun_client.binding_request().await?;
    info!("mapped_address={mapped_address:?}");

    let ice_candidates = vec![
        IceCandidate {
            ip: local_ip,
            port: UDP_SERVER_PORT,
        },
        IceCandidate {
            ip: mapped_address.ip(),
            port: UDP_SERVER_PORT,
        },
    ];

    let ice_agent = IceAgent::new(ice_candidates, fingerprint.clone());

    let mut udp_server = UdpServer::new(
        &format!("127.0.0.1:{UDP_SERVER_PORT}"),
        certified_key,
        ice_agent.clone(),
    )
    .await?;
    let signaling_server = SignalingServer::new(ice_agent).await;

    // Run both servers concurrently
    tokio::try_join!(udp_server.run(), signaling_server.run())?;

    Ok(())
}
