#!/bin/bash
# Guardian VPS Setup Script — v1
# Run as root on a fresh Ubuntu 22.04 / 24.04 VPS
# Usage: sudo bash setup_vps.sh

set -e
echo "=== Guardian VPS Setup v1 ==="

apt update && apt upgrade -y
apt install -y wireguard mosquitto mosquitto-clients python3 python3-pip python3-venv ufw curl openssl nginx

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

echo "Setting up systemd service for relay..."
cat > /etc/systemd/system/guardian.service << EOF
[Unit]
Description=Guardian Relay Server
After=network.target mosquitto.service
[Service]
ExecStart=/opt/guardian/venv/bin/python /opt/guardian/relay_server.py
WorkingDirectory=/opt/guardian
Restart=always
RestartSec=5
User=root
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable guardian

echo "Setting up nginx dashboard (WireGuard-only access)..."
mkdir -p /var/www/html/guardian

cat > /etc/nginx/sites-available/guardian << EOF
server {
    listen 80;
    server_name 10.99.0.1;

    # Only allow access from WireGuard subnet
    allow 10.99.0.0/24;
    deny all;

    location /guardian/ {
        alias /var/www/html/guardian/;
        index index.html;
    }
}
EOF

ln -sf /etc/nginx/sites-available/guardian /etc/nginx/sites-enabled/guardian
nginx -t && systemctl enable nginx && systemctl restart nginx

echo "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 51820/udp
ufw allow 8443/tcp
# Port 80 only accessible via WireGuard (nginx allow/deny handles this)
ufw allow from 10.99.0.0/24 to any port 80
ufw --force enable

cat > /root/guardian_credentials.txt << EOF
=== GUARDIAN CREDENTIALS v1 — KEEP SAFE — SAVE TO BITWARDEN ===

SERVER PUBLIC IP:    $SERVER_IP
SERVER WG PUBLIC KEY: $SERVER_PUB

MQTT PASSWORD: $MQTT_PASS
MQTT USER:     guardian

DASHBOARD URL: http://10.99.0.1/guardian  (WireGuard must be active)
RELAY API:     http://10.99.0.1:8443

--- PHONE CONFIG (10.99.0.2) ---
Private Key: $PHONE_PRIV
Public Key:  $PHONE_PUB
WG IP:       10.99.0.2

Full WireGuard config for phone:
[Interface]
PrivateKey = $PHONE_PRIV
Address = 10.99.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $SERVER_IP:51820
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25

--- LAPTOP CONFIG (10.99.0.3) ---
Private Key: $LAPTOP_PRIV
Public Key:  $LAPTOP_PUB
WG IP:       10.99.0.3

Full WireGuard config for laptop:
[Interface]
PrivateKey = $LAPTOP_PRIV
Address = 10.99.0.3/32
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $SERVER_IP:51820
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25

--- NEXT STEPS ---
1. Copy relay_server.py to /opt/guardian/
2. Edit MASTER_PASSWORD, TOTP_SECRET, MQTT_PASS in relay_server.py
3. Copy dashboard.html to /var/www/html/guardian/index.html
4. Run: systemctl start guardian
5. Add TOTP_SECRET to Authy manually
6. Save this entire file to Bitwarden

--- ADD NEW DEVICE ---
Run: bash /opt/guardian/add_device.sh <device_name>
EOF

chmod 600 /root/guardian_credentials.txt
echo ""
echo "================================================================"
echo " GUARDIAN VPS SETUP COMPLETE"
echo "================================================================"
echo " Credentials: cat /root/guardian_credentials.txt"
echo " SAVE THIS FILE TO BITWARDEN IMMEDIATELY"
echo "================================================================"