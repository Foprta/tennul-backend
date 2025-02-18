use axum::{routing::{post, delete}, Router};
use std::sync::Arc;
use tokio::sync::Mutex;
use x25519_dalek::PublicKey;

mod config;
use config::Config;

use tennul_backend::{
    handlers::{create_client, remove_client},
    models::AppState,
    wireguard::WireguardManager,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let (config, server_private_key) = Config::load_or_create()?;
    let server_public_key = PublicKey::from(&server_private_key);

    let wg_manager = WireguardManager::new(
        &config.wireguard.interface,
        &config.wireguard.subnet,
        config.wireguard.port
    )?;
    wg_manager.init(&server_private_key).await?;

    let state = AppState {
        server_private_key,
        server_public_key,
        clients: Arc::new(Mutex::new(Vec::new())),
        wg_manager: Arc::new(wg_manager),
    };

    let app = Router::new()
        .route("/client", post(create_client))
        .route("/client", delete(remove_client))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(
        format!("0.0.0.0:{}", config.server.listen_port)
    ).await?;
    tracing::info!("Server running on http://0.0.0.0:{}", config.server.listen_port);
    axum::serve(listener, app).await?;
    Ok(())
}
