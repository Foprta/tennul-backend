use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::wireguard::WireguardManager;

#[derive(Clone)]
pub struct AppState {
    pub server_private_key: StaticSecret,
    pub server_public_key: PublicKey,
    pub clients: Arc<Mutex<Vec<Client>>>,
    pub wg_manager: Arc<WireguardManager>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Client {
    pub id: String,
    pub public_key: String,
    pub private_key: String,
    pub ip_address: String,
}

#[derive(Deserialize)]
pub struct CreateClientRequest {
    pub client_id: String,
}

#[derive(Serialize)]
pub struct WireGuardConfig {
    pub client_private_key: String,
    pub server_public_key: String,
    pub client_ip: String,
    pub server_endpoint: String,
    pub dns_servers: Vec<String>,
}

#[derive(Serialize)]
pub struct ClientResponse {
    pub config: WireGuardConfig,
    pub config_file: String,
} 