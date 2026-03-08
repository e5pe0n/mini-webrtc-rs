use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use local_ip_address::local_ip;
use tokio::{net::TcpListener, sync::Mutex};
use tracing::info;

use crate::{
    ice::{IceAgent, IceCandidate, RemotePeer},
    sdp::SdpMessage,
};

pub struct SignalingServer {
    app: Router,
    listener: TcpListener,
}

struct AppState {
    ice_agent: Mutex<IceAgent>,
}

impl SignalingServer {
    pub async fn new(ice_agent: IceAgent) -> Self {
        let shared_state = Arc::new(AppState {
            ice_agent: Mutex::new(ice_agent),
        });

        let app = Router::new()
            .route("/", get(handle_get_offer))
            .route("/", post(handle_post_answer))
            .with_state(shared_state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
            .await
            .unwrap();
        info!(
            "signaling server listening on {}",
            listener.local_addr().unwrap()
        );

        Self { app, listener }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(axum::serve(self.listener, self.app).await?)
    }
}

async fn handle_get_offer(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ice_agent = state.ice_agent.lock().await;
    let sdp_offer = ice_agent.generate_sdp_offer();
    Json(sdp_offer)
}

async fn handle_post_answer(
    State(state): State<Arc<AppState>>,
    Json(answer): Json<SdpMessage>,
) -> impl IntoResponse {
    let remote_peers = answer
        .medias
        .iter()
        .map(|media| RemotePeer {
            ufrag: media.ufrag.clone(),
            pwd: media.pwd.clone(),
            fingerprint: media.fingerprint_hash.clone(),
        })
        .collect();
    let mut ice_agent = state.ice_agent.lock().await;
    ice_agent.add_remote_peers(remote_peers);
}
