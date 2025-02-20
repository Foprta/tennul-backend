use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::fs;
use x25519_dalek::{StaticSecret, PublicKey};
use rand::rngs::OsRng;
use rand::Rng;
use std::process::Command;
use log::{info, warn, error};
use std::fs::File;
use std::io::BufReader;
use rustls::{ServerConfig, Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

#[derive(Deserialize)]
struct OrderRequest {
    order_id: String,
}

#[derive(Serialize)]
struct ConfigResponse {
    peer_config: String,
}

// Production ready key pair generation for Wireguard using X25519
fn generate_keypair() -> (String, String) {
    let mut rng = OsRng::default();
    let private = StaticSecret::random_from_rng(&mut rng);
    let public = PublicKey::from(&private);
    (base64::encode(private.to_bytes()), base64::encode(public.as_bytes()))
}

/* Added helper functions to determine used ip and port, and generate unique ones */
fn get_used_ip_ports() -> Vec<(u8, u16)> {
    let mut used = Vec::new();
    if let Ok(entries) = fs::read_dir("/etc/wireguard") {
        for entry in entries.filter_map(Result::ok) {
            let fname = entry.file_name().to_string_lossy().to_string();
            // Only consider server config files (skip peer configs)
            if fname.contains("peer") { continue; }
            let parts: Vec<&str> = fname.split('-').collect();
            if parts.len() != 3 { continue; }
            // parts[0] is order suffix, parts[1] is ip octet, parts[2] is port with .conf suffix
            if let Some(port_part) = parts[2].strip_suffix(".conf") {
                if let (Ok(ip), Ok(port)) = (parts[1].parse::<u8>(), port_part.parse::<u16>()) {
                    used.push((ip, port));
                }
            }
        }
    }
    used
}

fn generate_unique_ip_port() -> (u8, u16) {
    let used = get_used_ip_ports();
    let mut rng = rand::thread_rng();
    loop {
        let ip_octet = rng.gen_range(1..=254);
        let port = rng.gen_range(1024..=65535);
        if !used.contains(&(ip_octet, port)) {
            return (ip_octet, port);
        }
    }
}

/* Add AppState to store global configuration */
struct AppState {
    server_host: String,
}

/* Add an async function to fetch the server host once */
async fn get_server_host() -> Result<String, reqwest::Error> {
    reqwest::get("https://eth0.me")
        .await?
        .text()
        .await
        .map(|s| s.trim().to_string())
}

/* Add systemd service management functions */
async fn manage_wg_service(config_name: &str, action: &str) -> std::io::Result<()> {
    let service_name = format!("wg-quick@{}", config_name.strip_suffix(".conf").unwrap_or(config_name));
    
    info!("Running systemctl {} for {}", action, service_name);
    Command::new("systemctl")
        .arg(action)
        .arg(&service_name)
        .output()?;

    Ok(())
}

// POST /config/wireguard
async fn create_wireguard_config(state: web::Data<AppState>, req: web::Json<OrderRequest>) -> impl Responder {
    let order_id = &req.order_id;
    info!("Creating new WireGuard config for order_id: {}", order_id);
    
    let config_dir = "/etc/wireguard";
    let order_suffix = if order_id.len() >= 4 { &order_id[order_id.len()-4..] } else { order_id };

    if let Ok(entries) = fs::read_dir(config_dir) {
        for entry in entries.filter_map(Result::ok) {
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();
            if fname_str.starts_with(order_suffix) && !fname_str.contains("peer") {
                warn!("Config already exists for order_id: {}", order_id);
                return HttpResponse::BadRequest().body("Config already exists for this order id");
            }
        }
    }

    let (ip_octet, port) = generate_unique_ip_port();
    info!("Generated unique IP octet {} and port {} for order_id: {}", ip_octet, port, order_id);
    
    let server_ip = format!("10.0.{}.1/24", ip_octet);
    let client_ip = format!("10.0.{}.2/24", ip_octet);

    let (server_priv, server_pub) = generate_keypair();
    let (client_priv, client_pub) = generate_keypair();
    info!("Generated key pairs for order_id: {}", order_id);

    let server_config = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}\nListenPort = {}\n\n[Peer]\nPublicKey = {}\nAllowedIPs = {}\n", 
        server_priv, server_ip, port, client_pub, client_ip
    );

    let config_filename = format!("{}-{}-{}.conf", order_suffix, ip_octet, port);
    let peer_filename = format!("{}-{}-{}.peer.conf", order_suffix, ip_octet, port);
    let config_path = format!("{}/{}", config_dir, config_filename);
    let peer_config_path = format!("{}/{}", config_dir, peer_filename);

    info!("Writing config files: {} and {}", config_filename, peer_filename);

    if let Err(e) = fs::write(&config_path, server_config) {
       error!("Failed to write server config for order_id {}: {}", order_id, e);
       return HttpResponse::InternalServerError().body(format!("Failed to write config: {}", e));
    }

    let server_host = state.server_host.clone();
    let peer_config = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}\nDNS = 1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4\n\n[Peer]\nPublicKey = {}\nEndpoint = {}:{}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n", 
        client_priv, client_ip, server_pub, server_host, port
    );

    if let Err(e) = fs::write(&peer_config_path, peer_config.clone()) {
       error!("Failed to write peer config for order_id {}: {}", order_id, e);
       return HttpResponse::InternalServerError().body(format!("Failed to write peer config: {}", e));
    }

    info!("Starting WireGuard interface for config: {}", config_filename);
    // Enable and start the service
    if let Err(e) = manage_wg_service(&config_filename, "enable").await {
        error!("Failed to enable WireGuard service for order_id {}: {}", order_id, e);
        return HttpResponse::InternalServerError().body(format!("Failed to enable WireGuard service: {}", e));
    }
    if let Err(e) = manage_wg_service(&config_filename, "start").await {
        error!("Failed to start WireGuard service for order_id {}: {}", order_id, e);
        return HttpResponse::InternalServerError().body(format!("Failed to start WireGuard service: {}", e));
    }

    info!("Successfully created WireGuard config for order_id: {}", order_id);
    HttpResponse::Ok().json(ConfigResponse { peer_config })
}

// GET /config/wireguard?order_id=...
async fn get_wireguard_config(query: web::Query<OrderRequest>) -> impl Responder {
    let order_id = &query.order_id;
    info!("Fetching WireGuard config for order_id: {}", order_id);
    
    let config_path = format!("/etc/wireguard/{}.peer.conf", order_id);
    match fs::read_to_string(&config_path) {
       Ok(content) => {
           info!("Successfully retrieved config for order_id: {}", order_id);
           HttpResponse::Ok().body(content)
       },
       Err(e) => {
           warn!("Config not found for order_id {}: {}", order_id, e);
           HttpResponse::NotFound().body(format!("Config not found: {}", e))
       },
    }
}

// DELETE /config/wireguard?order_id=...
async fn delete_wireguard_config(query: web::Query<OrderRequest>) -> impl Responder {
    let order_id = &query.order_id;
    info!("Deleting WireGuard config for order_id: {}", order_id);
    
    let server_config_path = format!("/etc/wireguard/{}.conf", order_id);
    let peer_config_path = format!("/etc/wireguard/{}.peer.conf", order_id);

    if !std::path::Path::new(&server_config_path).exists() && !std::path::Path::new(&peer_config_path).exists() {
         warn!("No configs found to delete for order_id: {}", order_id);
         return HttpResponse::NotFound().body("Config not found");
    }

    let mut error_messages = Vec::new();
    if std::path::Path::new(&server_config_path).exists() {
         if let Err(e) = fs::remove_file(&server_config_path) {
             error!("Failed to delete server config for order_id {}: {}", order_id, e);
             error_messages.push(format!("Failed to delete server config: {}", e));
         }
    }
    if std::path::Path::new(&peer_config_path).exists() {
         if let Err(e) = fs::remove_file(&peer_config_path) {
             error!("Failed to delete peer config for order_id {}: {}", order_id, e);
             error_messages.push(format!("Failed to delete peer config: {}", e));
         }
    }

    if !error_messages.is_empty() {
         return HttpResponse::InternalServerError().body(error_messages.join("; "));
    }

    info!("Stopping WireGuard interface for order_id: {}", order_id);
    let config_filename = std::path::Path::new(&server_config_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    
    // Stop and disable the service
    if let Err(e) = manage_wg_service(config_filename, "stop").await {
        error!("Failed to stop WireGuard service for order_id {}: {}", order_id, e);
        return HttpResponse::InternalServerError().body(format!("Failed to stop WireGuard service: {}", e));
    }
    if let Err(e) = manage_wg_service(config_filename, "disable").await {
        error!("Failed to disable WireGuard service for order_id {}: {}", order_id, e);
        return HttpResponse::InternalServerError().body(format!("Failed to disable WireGuard service: {}", e));
    }

    info!("Successfully deleted WireGuard config for order_id: {}", order_id);
    HttpResponse::Ok().body("Deleted")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    info!("Starting WireGuard VPN manager");

    info!("Creating WireGuard config directory");
    fs::create_dir_all("/etc/wireguard").ok();

    info!("Fetching server host");
    let server_host = match get_server_host().await {
        Ok(host) => {
            info!("Server host determined: {}", host);
            host
        },
        Err(e) => {
            warn!("Failed to fetch server host, using default: {}", e);
            "vpn.example.com".to_string()
        },
    };

    let app_state = web::Data::new(AppState { server_host });

    // Load TLS certificate and key for HTTPS on port 443
    let cert_path = "/etc/ssl/certs/tennul-backend.pem";
    let key_path = "/etc/ssl/private/tennul-backend.pem";
    let cert_file = &mut BufReader::new(File::open(cert_path).expect("Cannot open certificate"));
    let key_file = &mut BufReader::new(File::open(key_path).expect("Cannot open private key"));
    let cert_chain = certs(cert_file)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "failed to read certificate"))?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();
    let mut keys = pkcs8_private_keys(key_file)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "failed to read private key as PKCS8"))?
        .into_iter()
        .map(PrivateKey)
        .collect::<Vec<_>>();
    if keys.is_empty() {
        println!("PKCS8 keys not found, trying RSA keys...");
        let key_file = &mut BufReader::new(File::open(key_path).expect("Cannot open private key"));
        keys = rsa_private_keys(key_file)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "failed to read private key as RSA"))?
            .into_iter()
            .map(PrivateKey)
            .collect::<Vec<_>>();
    }
    if keys.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "no keys found"));
    }
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys.remove(0))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    info!("Starting HTTPS server on 0.0.0.0:443");
    HttpServer::new(move || {
         App::new()
         .app_data(app_state.clone())
         .route("/config/wireguard", web::post().to(create_wireguard_config))
         .route("/config/wireguard", web::get().to(get_wireguard_config))
         .route("/config/wireguard", web::delete().to(delete_wireguard_config))
    })
    .bind_rustls("0.0.0.0:443", tls_config)?
    .run()
    .await
} 