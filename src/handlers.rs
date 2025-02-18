use axum::{extract::State, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use x25519_dalek::{PublicKey, StaticSecret};
use std::net::Ipv4Addr;
use reqwest;
use anyhow::Result;

use crate::models::{AppState, Client, ClientResponse, CreateClientRequest, WireGuardConfig};

async fn get_server_ip() -> Result<String> {
    let ip = reqwest::get("https://eth0.me")
        .await?
        .text()
        .await?
        .trim()
        .to_string();
    Ok(ip)
}

pub async fn create_client(
    State(state): State<AppState>,
    Json(req): Json<CreateClientRequest>,
) -> Result<Json<ClientResponse>, String> {
    let private_key = StaticSecret::random_from_rng(rand::thread_rng());
    let public_key = PublicKey::from(&private_key);

    // Get existing IPs
    let clients = state.clients.lock().await;
    let existing_ips: Vec<Ipv4Addr> = clients
        .iter()
        .filter_map(|c| c.ip_address.strip_suffix("/32"))
        .filter_map(|ip| ip.parse().ok())
        .collect();

    // Assign new IP
    let client_ip = state.wg_manager.assign_ip(&existing_ips)
        .ok_or("No available IPs")?;
    
    drop(clients); // Release lock

    // Add peer to WireGuard interface
    state.wg_manager.add_peer(
        public_key.as_bytes(),
        client_ip
    ).await.map_err(|e| e.to_string())?;

    let client = Client {
        id: req.client_id,
        public_key: STANDARD.encode(public_key.as_bytes()),
        private_key: STANDARD.encode(private_key.to_bytes()),
        ip_address: format!("{}/32", client_ip),
    };

    let mut clients = state.clients.lock().await;
    clients.push(client);

    // Get server IP
    let server_ip = get_server_ip()
        .await
        .map_err(|e| e.to_string())?;

    let config = WireGuardConfig {
        client_private_key: STANDARD.encode(private_key.to_bytes()),
        server_public_key: STANDARD.encode(state.server_public_key.as_bytes()),
        client_ip: format!("{}/32", client_ip),
        server_endpoint: format!("{}:{}", server_ip, state.wg_manager.port),
        dns_servers: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
    };

    let config_file = format!(
        r#"[Interface]
PrivateKey = {}
Address = {}
DNS = {}

[Peer]
PublicKey = {}
AllowedIPs = 0.0.0.0/0
Endpoint = {}
PersistentKeepalive = 25"#,
        config.client_private_key,
        config.client_ip,
        config.dns_servers.join(","),
        config.server_public_key,
        config.server_endpoint
    );

    Ok(Json(ClientResponse {
        config,
        config_file,
    }))
}

pub async fn remove_client(
    State(state): State<AppState>,
    Json(req): Json<CreateClientRequest>,
) -> Result<Json<bool>, String> {
    let mut clients = state.clients.lock().await;
    
    if let Some(client) = clients.iter().find(|c| c.id == req.client_id) {
        let public_key_bytes = STANDARD.decode(&client.public_key)
            .map_err(|e| e.to_string())?;
            
        state.wg_manager.remove_peer(&public_key_bytes)
            .await
            .map_err(|e| e.to_string())?;
    }

    clients.retain(|c| c.id != req.client_id);
    Ok(Json(true))
} 