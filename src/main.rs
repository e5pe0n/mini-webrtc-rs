use anyhow::Result;
use mini_webrtc_rs::peer_connection::PeerConnection;

#[tokio::main]
async fn main() -> Result<()> {
    let _pc = PeerConnection::new().await?;
    tokio::signal::ctrl_c().await?;
    Ok(())
}
