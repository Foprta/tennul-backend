#!/bin/bash
set -e

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

CERT_PATH="/etc/ssl/certs/tennul-backend.pem"
KEY_PATH="/etc/ssl/private/tennul-backend.pem"

# Check if keys already exist
if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
    echo "TLS certificate and key already exist."
    exit 0
fi

# Create directories if they don't exist
mkdir -p /etc/ssl/certs
mkdir -p /etc/ssl/private

# Generate TLS certificate and private key
echo "Generating self-signed TLS certificate and key..."
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$KEY_PATH" \
  -out "$CERT_PATH" \
  -days 365 \
  -subj "/CN=tennul-backend"

# Set appropriate permissions
chmod 600 "$KEY_PATH"
chmod 644 "$CERT_PATH"

echo "TLS keys generated successfully!" 