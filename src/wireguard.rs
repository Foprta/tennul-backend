use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;
use std::process::Command;
use wireguard_control::{Backend, DeviceUpdate, InterfaceName, Key};
use x25519_dalek::StaticSecret;

const SPEED_LIMIT_MBPS: u32 = 100;

#[derive(Clone)]
pub struct WireguardManager {
    pub(crate) interface: InterfaceName,
    pub(crate) subnet: Ipv4Network,
    pub(crate) port: u16,
}

impl WireguardManager {
    pub fn new(interface: &str, subnet: &str, port: u16) -> Result<Self> {
        Ok(Self {
            interface: interface.parse()?,
            subnet: subnet.parse()?,
            port,
        })
    }

    pub async fn init(&self, private_key: &StaticSecret) -> Result<()> {
        let backend = Backend::default();
        
        let key = Key::from_base64(&STANDARD.encode(private_key.to_bytes()))?;
        let device = DeviceUpdate::new()
            .set_private_key(key)
            .set_listen_port(self.port);

        device.apply(&self.interface, backend)?;
        self.setup_tc()?;
        Ok(())
    }

    pub async fn add_peer(&self, public_key: &[u8], allowed_ip: Ipv4Addr) -> Result<()> {
        let backend = Backend::default();
        let key = Key::from_base64(&STANDARD.encode(public_key))?;

        let device = DeviceUpdate::new()
            .add_peer_with(&key, |peer| {
                peer.add_allowed_ip(allowed_ip.into(), 32)
            });

        device.apply(&self.interface, backend)?;
        self.apply_speed_limit(allowed_ip)?;
        Ok(())
    }

    pub async fn remove_peer(&self, public_key: &[u8]) -> Result<()> {
        let backend = Backend::default();
        let key = Key::from_base64(&STANDARD.encode(public_key))?;

        let device = DeviceUpdate::new()
            .remove_peer_by_key(&key);

        device.apply(&self.interface, backend)?;
        Ok(())
    }

    fn setup_tc(&self) -> Result<()> {
        // Check if TC is already set up
        let check = Command::new("tc")
            .args(["qdisc", "show", "dev", &self.interface.to_string()])
            .output()?;
        
        if String::from_utf8_lossy(&check.stdout).contains("htb 1:") {
            return Ok(());
        }

        // Create root qdisc
        Command::new("tc")
            .args(["qdisc", "add", "dev", &self.interface.to_string(), "root", "handle", "1:", "htb", "default", "1"])
            .status()?;

        // Create default class
        Command::new("tc")
            .args([
                "class", "add", "dev", &self.interface.to_string(),
                "parent", "1:", "classid", "1:1", "htb",
                "rate", "1000mbit",
            ])
            .status()?;

        Ok(())
    }

    fn apply_speed_limit(&self, ip: Ipv4Addr) -> Result<()> {
        let ip_str = ip.to_string();
        let speed = format!("{}mbit", SPEED_LIMIT_MBPS);
        let class_id = format!("1:{}", ip.octets()[3]);

        // Check if class already exists
        let check = Command::new("tc")
            .args(["class", "show", "dev", &self.interface.to_string()])
            .output()?;
            
        if String::from_utf8_lossy(&check.stdout).contains(&class_id) {
            return Ok(());
        }

        // Create class for the IP
        Command::new("tc")
            .args([
                "class", "add", "dev", &self.interface.to_string(),
                "parent", "1:", "classid", &class_id, "htb",
                "rate", &speed, "ceil", &speed,
            ])
            .status()?;

        // Add filter to match IP
        Command::new("tc")
            .args([
                "filter", "add", "dev", &self.interface.to_string(),
                "protocol", "ip", "parent", "1:", "prio", "1",
                "u32", "match", "ip", "dst", &ip_str,
                "flowid", &class_id,
            ])
            .status()?;

        Ok(())
    }

    pub fn assign_ip(&self, existing_ips: &[Ipv4Addr]) -> Option<Ipv4Addr> {
        let network_addr = self.subnet.network();
        (2..=254)
            .map(|host| {
                let mut addr_bytes = network_addr.octets();
                addr_bytes[3] = host;
                Ipv4Addr::from(addr_bytes)
            })
            .find(|ip| !existing_ips.contains(ip))
    }
} 