use anyhow::Result;
use rcgen::generate_simple_self_signed;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{Level, info};

use dtls::{Fingerprint, manager::DtlsManager};

const UDP_SERVER_PORT: u64 = 4433;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    // Generate self-signed certificate
    let certified_key = generate_simple_self_signed(vec!["localhost".to_string()])?;
    let fingerprint = Fingerprint::new(certified_key.cert.der());

    let addr = format!("127.0.0.1:{UDP_SERVER_PORT}");

    // Bind UDP socket
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    info!("Udp Server listening on {}", &addr);

    let mut buf = vec![0u8; 65535];
    let mut manager = DtlsManager::new(socket.clone(), certified_key, fingerprint);

    loop {
        // Receive data from client
        let (len, peer_addr) = socket.recv_from(&mut buf).await?;
        info!("Received {} bytes from {}", len, peer_addr);

        // Parse DTLS handshake message
        manager.handle_dtls_packet(&buf[..len], peer_addr).await?;
    }

    Ok(())
}
