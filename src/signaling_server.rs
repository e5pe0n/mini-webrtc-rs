use axum::{Router, routing::get};
use tokio::net::TcpListener;

pub struct SignalingServer {
    app: Router,
    listener: TcpListener,
}

impl SignalingServer {
    pub async fn new() -> Self {
        let app = Router::new().route("/", get(handler));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
            .await
            .unwrap();
        println!(
            "signaling server listening on {}",
            listener.local_addr().unwrap()
        );
        Self { app, listener }
    }
}

async fn handler() {}
