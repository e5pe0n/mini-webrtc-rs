use std::sync::Arc;

use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::Mutex};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::{
    ice::{IceAgent, Peer},
    internal_event::{EventQueue, InternalEvent::SdpAnswer},
    sdp::SdpMessage,
};

pub struct SignalingServer {
    app: Router,
    listener: TcpListener,
}

struct AppState {
    ice_agent: Arc<Mutex<IceAgent>>,
    internal_event_queue: Arc<Mutex<EventQueue>>,
}

#[derive(Deserialize, Serialize)]
struct SimpleResponse {
    message: String,
}

impl SignalingServer {
    pub async fn new(
        ice_agent: Arc<Mutex<IceAgent>>,
        internal_event_queue: Arc<Mutex<EventQueue>>,
    ) -> Self {
        let shared_state = Arc::new(AppState {
            ice_agent,
            internal_event_queue,
        });

        let cors = CorsLayer::new()
            .allow_origin(HeaderValue::from_static("http://localhost:5173"))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(Any);

        let app = Router::new()
            .route("/", get(handle_get_offer))
            .route("/", post(handle_post_answer))
            .layer(cors)
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

    pub async fn run(self) -> Result<()> {
        Ok(axum::serve(self.listener, self.app).await?)
    }
}

async fn handle_get_offer(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ice_agent = state.ice_agent.lock().await;
    let sdp_offer = ice_agent.generate_sdp_offer();
    info!(
        "GET / signaling: served offer; medias={}",
        sdp_offer.medias.len()
    );
    Json(sdp_offer)
}

async fn handle_post_answer(
    State(state): State<Arc<AppState>>,
    Json(answer): Json<SdpMessage>,
) -> (StatusCode, Json<SimpleResponse>) {
    for media in &answer.medias {
        info!("POST / signaling: media answer; {media:?}");
    }

    info!(
        "POST / signaling: received answer; session_id={}, medias={}",
        answer.session_id,
        answer.medias.len()
    );

    state
        .internal_event_queue
        .lock()
        .await
        .push_back(SdpAnswer(answer));

    (
        StatusCode::OK,
        Json(SimpleResponse {
            message: "post answer succeeded.".to_string(),
        }),
    )
}
