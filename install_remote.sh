#!/bin/bash
set -e  # Exit on error

#
# Tennul Backend Installation Script
# This script installs and configures the Tennul VPN backend service
#
# Usage:
#   Quick install:
#     wget -O- https://raw.githubusercontent.com/foprta/tennul-backend/main/install_remote.sh | sudo bash
#
#   Manual install:
#     wget https://raw.githubusercontent.com/foprta/tennul-backend/main/install_remote.sh
#     chmod +x install_remote.sh
#     sudo ./install_remote.sh
#

# Configuration
REPO_URL="https://github.com/foprta/tennul-backend.git"
INSTALL_DIR="/opt/tennul"
SERVICE_NAME="tennul-backend"

# Install system dependencies
install_dependencies() {
    echo "Installing dependencies..."
    sudo apt update
    sudo apt install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        wireguard \
        iproute2 \
        git \
        curl
}

# Install Rust toolchain
install_rust() {
    if ! command -v rustc &> /dev/null; then
        echo "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    else
        echo "Rust is already installed"
    fi
}

# Clone and build the project
setup_application() {
    echo "Cloning repository..."
    sudo rm -rf "$INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    sudo mkdir -p /etc/tennul
    sudo chown -R "$USER:$USER" "$INSTALL_DIR"
    sudo chown -R "$USER:$USER" /etc/tennul
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"

    echo "Building release..."
    cargo build --release
}

# Create systemd service file
create_service_file() {
    echo "Creating service file..."
    cat > "$SERVICE_NAME.service" << 'EOL'
[Unit]
Description=Tennul VPN Backend Service
After=network.target

[Service]
Type=simple
User=root
ExecStartPre=/sbin/modprobe wireguard
ExecStart=/usr/local/bin/tennul-backend
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOL
}

# Install and configure the service
install_service() {
    echo "Installing service..."
    # Stop the service if it's running
    sudo systemctl stop "$SERVICE_NAME" || true
    
    sudo cp "target/release/$SERVICE_NAME" /usr/local/bin/
    sudo chmod +x "/usr/local/bin/$SERVICE_NAME"
    sudo cp "$SERVICE_NAME.service" /etc/systemd/system/
}

# Setup networking for VPN
setup_networking() {
    echo "Configuring networking..."
    
    # Get default interface
    DEFAULT_IFACE=$(ip -4 route show default | awk '{print $5}' | head -n1)
    if [ -z "$DEFAULT_IFACE" ]; then
        echo "Error: Could not detect default network interface"
        exit 1
    fi
    echo "Using network interface: $DEFAULT_IFACE"
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ip-forward.conf
    sudo sysctl -p /etc/sysctl.d/99-ip-forward.conf
    
    
    # Create WireGuard config file
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = 7U6qPsQzuIRFcsB1ATu25gwiR+DEqpcoG7RNonb5eC0=
Address = 10.0.0.1/24
ListenPort = 51820
EOF

    sudo chmod 600 /etc/wireguard/wg0.conf
    
}

# Start the service
start_service() {
    echo "Starting service..."
    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    sudo systemctl restart "$SERVICE_NAME"
}

# Main installation process
main() {
    install_dependencies
    install_rust
    setup_application
    create_service_file
    install_service
    setup_networking
    start_service

    echo "Installation complete!"
}

# Start installation
main 