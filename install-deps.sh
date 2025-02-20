#!/bin/bash
set -e  # Exit on any error

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

echo "Installing system dependencies..."
apt update
apt install -y \
    wireguard \
    wireguard-tools \
    curl \
    build-essential \
    pkg-config \
    libssl-dev

echo "System dependencies installed successfully!" 