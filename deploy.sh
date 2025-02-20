#!/bin/bash
set -e  # Exit on any error

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

echo "Creating application directory..."
mkdir -p /opt/tennul-backend

echo "Building application..."
cargo build --release
echo "Stopping tennul-backend service if running..."
systemctl stop tennul-backend || true
cp target/release/tennul-backend /opt/tennul-backend/

echo "Setting up systemd service..."
cp tennul-backend.service /etc/systemd/system/

echo "Setting permissions..."
chown -R root:root /opt/tennul-backend
chmod 755 /opt/tennul-backend
chmod 755 /opt/tennul-backend/tennul-backend

echo "Enabling and starting service..."
systemctl daemon-reload
systemctl enable tennul-backend
systemctl start tennul-backend

echo "Deployment complete!"
echo "You can check service status with: systemctl status tennul-backend"
echo "View logs with: journalctl -u tennul-backend -f" 