use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use x25519_dalek::{StaticSecret, PublicKey};
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub wireguard: WireguardConfig,
}

#[derive(Deserialize, Serialize)]
pub struct ServerConfig {
    pub private_key: String,
    pub listen_port: u16,
}

#[derive(Deserialize, Serialize)]
pub struct WireguardConfig {
    pub interface: String,
    pub subnet: String,
    pub port: u16,
}

impl Config {
    pub fn load_or_create() -> anyhow::Result<(Self, StaticSecret)> {
        let config_path = "/etc/tennul/config.toml";
        let config = if Path::new(config_path).exists() {
            let content = fs::read_to_string(config_path)?;
            toml::from_str(&content)?
        } else {
            // Generate new private key
            let private_key = StaticSecret::random_from_rng(rand::thread_rng());
            let key_b64 = STANDARD.encode(private_key.to_bytes());

            let config = Config {
                server: ServerConfig {
                    private_key: key_b64,
                    listen_port: 3000,
                },
                wireguard: WireguardConfig {
                    interface: "wg0".to_string(),
                    subnet: "10.0.0.0/24".to_string(),
                    port: 51820,
                },
            };

            // Create directory if it doesn't exist
            fs::create_dir_all("/etc/tennul")?;
            fs::write(config_path, toml::to_string_pretty(&config)?)?;
            config
        };

        // Convert private key from base64 to StaticSecret
        let key_bytes = STANDARD.decode(&config.server.private_key)?;
        let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid key length"))?;
        let private_key = StaticSecret::from(key_array);

        Ok((config, private_key))
    }
} 