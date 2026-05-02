#!/bin/bash
# Guardian VPS Setup Script
# Run as root on a fresh Ubuntu 22.04 / 24.04 VPS
# Usage: sudo bash setup_vps.sh

set -e
echo "=== Guardian VPS Setup ==="

apt update && apt upgrade -y
apt install -y wireguard mosquitto mosquitto-clients python3 python3-pip python3-venv ufw curl openssl

echo "Setting up WireGuard..."
WG_DIR=/etc/wireguard
mkdir -p $WG_DIR
chmod 700 $WG_DIR

wg genkey | tee $WG_DIR/server_private.key | wg pubkey > $WG_DIR/server_public.key
chmod 600 $WG_DIR/server_private.key
SERVER_PRIV=$(cat $WG_DIR/server_private.key)
SERVER_PUB=$(cat $WG_DIR/server_public.key)

wg genkey | tee $WG_DIR/phone_private.key | wg pubkey > $WG_DIR/phone_public.key
wg genkey | tee $WG_DIR/laptop_private.key | wg pubkey > $WG_DIR/laptop_public.key

PHONE_PRIV=$(cat $WG_DIR/phone_private.key)
PHONE_PUB=$(cat $WG_DIR/phone_public.key)
LAPTOP_PRIV=$(cat $WG_DIR/laptop_private.key)
LAPTOP_PUB=$(cat $WG_DIR/laptop_public.key)

SERVER_IP=$(curl -s ifconfig.me)

cat > $WG_DIR/wg0.conf << EOF
[Interface]
Address = 10.99.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIV
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# PHONE
[Peer]
PublicKey = $PHONE_PUB
AllowedIPs = 10.99.0.2/32

# LAPTOP
[Peer]
PublicKey = $LAPTOP_PUB
AllowedIPs = 10.99.0.3/32
EOF

chmod 600 $WG_DIR/wg0.conf
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

echo "Setting up MQTT broker..."
MQTT_PASS=$(openssl rand -base64 16)
mosquitto_passwd -b -c /etc/mosquitto/passwd guardian $MQTT_PASS

cat > /etc/mosquitto/conf.d/guardian.conf << EOF
listener 1883 127.0.0.1
allow_anonymous false
password_file /etc/mosquitto/passwd
EOF

systemctl enable mosquitto
systemctl restart mosquitto

echo "Setting up Guardian relay..."
mkdir -p /opt/guardian
python3 -m venv /opt/guardian/venv
/opt/guardian/venv/bin/pip install fastapi uvicorn paho-mqtt pyotp python-jose[cryptography] passlib bcrypt websockets requests

echo "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 51820/udp
ufw allow 8443/tcp
ufw --force enable

cat > /root/guardian_credentials.txt << EOF
=== GUARDIAN CREDENTIALS — KEEP SAFE ===

SERVER PUBLIC IP: $SERVER_IP
SERVER WG PUBLIC KEY: $SERVER_PUB

MQTT PASSWORD: $MQTT_PASS
MQTT USER: guardian

--- PHONE CONFIG ---
Private Key: $PHONE_PRIV
Public Key:  $PHONE_PUB
WG IP:       10.99.0.2

--- LAPTOP CONFIG ---
Private Key: $LAPTOP_PRIV
Public Key:  $LAPTOP_PUB
WG IP:       10.99.0.3

--- ADD NEW DEVICE ---
Run: bash /opt/guardian/add_device.sh <device_name>
EOF

chmod 600 /root/guardian_credentials.txt
echo ""
echo "=== SETUP COMPLETE ==="
echo "Credentials saved to /root/guardian_credentials.txt"
echo "Read them with: cat /root/guardian_credentials.txt"