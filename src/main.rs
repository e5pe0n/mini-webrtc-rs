use anyhow::Result;
use mini_webrtc_rs::peer_connection::PeerConnection;

#[tokio::main]
async fn main() -> Result<()> {
    let pc = PeerConnection::new().await?;
    pc.run().await
}
