use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::Mutex};
use tracing::info;

use crate::{
    ice::{IceAgent, Peer},
    sdp::SdpMessage,
};

pub struct SignalingServer {
    app: Router,
    listener: TcpListener,
}

struct AppState {
    ice_agent: Mutex<IceAgent>,
}

type Return<T> = Result<(StatusCode, Json<T>), (StatusCode, String)>;

#[derive(Deserialize, Serialize)]
struct SimpleResponse {
    message: String,
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
    if let Some(remote_peer) = answer
        .medias
        .iter()
        .map(|media| Peer {
            ufrag: media.ufrag.clone(),
            pwd: media.pwd.clone(),
            fingerprint: media.fingerprint_hash.clone(),
        })
        .next()
    {
        let mut ice_agent = state.ice_agent.lock().await;
        ice_agent.remote_peer = Some(remote_peer);
        return Ok((
            StatusCode::OK,
            Json(SimpleResponse {
                message: "post answer succeeded.".to_string(),
            }),
        ));
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(SimpleResponse {
                message: "media not found in sdp message.".to_string(),
            }),
        ));
    }
}
