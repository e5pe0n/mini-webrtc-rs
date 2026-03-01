use std::{net::Ipv4Addr, sync::Arc};

use axum::{Router, extract::State, routing::get, serve::Serve};
use local_ip_address::local_ip;
use tokio::net::TcpListener;

use crate::ice::{IceAgent, IceCandidate};

pub struct SignalingServer {
    app: Router,
    listener: TcpListener,
}

struct AppState {
    fingerprint_hash: String,
}

impl SignalingServer {
    pub async fn new(fingerprint_hash: String) -> Self {
        let shared_state = Arc::new(AppState { fingerprint_hash });

        let app = Router::new()
            .route("/", get(handler))
            .with_state(shared_state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
            .await
            .unwrap();
        println!(
            "signaling server listening on {}",
            listener.local_addr().unwrap()
        );

        Self { app, listener }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(axum::serve(self.listener, self.app).await?)
    }
}

async fn handler(State(state): State<Arc<AppState>>) {
    // local ips
    let local_ip = local_ip().unwrap();
    let ice_candidates = vec![IceCandidate {
        ip: local_ip,
        port: 4433,
    }];
    let ice_agent = IceAgent::new(ice_candidates, state.fingerprint_hash.clone());
}
