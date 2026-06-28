use std::time::{Duration, SystemTime};

use anyhow::Result;
use mini_webrtc_rs::{data_channel::DataChannelEvent, peer_connection::PeerConnection};
use tokio::{select, time::interval};
use tracing::{debug, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    let pc = PeerConnection::new().await?;
    let mut dc = pc.create_data_channel().await?;
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(5));
        loop {
            select! {
                event = dc.recv() => {
                    if let Some(event) = event {
                        info!("data channel event: {event:?}");
                    }
                }
                // _ = interval.tick() => {
                //     let now = SystemTime::now()
                //         .duration_since(SystemTime::UNIX_EPOCH)
                //         .expect("failed to system time.")
                //         .as_millis();
                //     match dc.send_text(&format!("{now}")).await {
                //         Ok(_) => debug!("sent data {now}"),
                //         Err(err) => warn!("{err:?}"),
                //     }
                // }
            }
        }
    });
    tokio::signal::ctrl_c().await?;
    pc.close();
    Ok(())
}
