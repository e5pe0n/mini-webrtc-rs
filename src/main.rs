mod dtls;
mod ice;
mod sdp;
mod signaling_server;
mod stun;
mod udp_server;

use crate::{signaling_server::SignalingServer, udp_server::UdpServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut udp_server = UdpServer::new("127.0.0.1:4433").await?;
    let signaling_server = SignalingServer::new(udp_server.get_fingerprint()).await;

    // Run both servers concurrently
    tokio::try_join!(udp_server.run(), signaling_server.run())?;

    Ok(())
}
