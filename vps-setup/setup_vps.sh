#!/bin/bash
# Guardian VPS Setup Script — v1
# Run as root on a fresh Ubuntu 22.04 / 24.04 VPS
# Usage: sudo bash setup_vps.sh

set -e
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
echo "=== Guardian VPS Setup v2 ==="

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
MQTT_PASS=$(openssl rand -hex 24)
MASTER_PASSWORD=$(openssl rand -hex 32)
TOTP_SECRET=$(python3 -c 'import base64,secrets; print(base64.b32encode(secrets.token_bytes(20)).decode("ascii"))')
NUKE_PASSPHRASE=$(openssl rand -hex 24)
COMMAND_SIGNING_KEY=$(openssl rand -hex 32)
NTFY_TOPIC="guardian-$(openssl rand -hex 12)"

# Avoid putting the MQTT password in process arguments. The plaintext
# temporary file lives in /run (tmpfs) and is mode 600 before hashing.
umask 077
MQTT_PASS_FILE=$(mktemp /run/guardian-mqtt-pass.XXXXXX)
printf 'guardian:%s\n' "$MQTT_PASS" > "$MQTT_PASS_FILE"
mosquitto_passwd -U "$MQTT_PASS_FILE"
install -o root -g root -m 600 "$MQTT_PASS_FILE" /etc/mosquitto/passwd
rm -f "$MQTT_PASS_FILE"

cat > /etc/mosquitto/conf.d/guardian.conf << EOF
listener 1883 127.0.0.1
allow_anonymous false
password_file /etc/mosquitto/passwd
EOF

systemctl enable mosquitto
systemctl restart mosquitto

echo "Setting up Guardian relay..."
install -d -o root -g root -m 700 /opt/guardian /etc/guardian /var/lib/guardian
cp "$SCRIPT_DIR/relay_server.py" "$SCRIPT_DIR/command_auth.py" /opt/guardian/
chmod 600 /opt/guardian/relay_server.py /opt/guardian/command_auth.py
python3 -m venv /opt/guardian/venv
/opt/guardian/venv/bin/pip install -r "$SCRIPT_DIR/requirements.txt"

# Generate a locked-down environment file consumed by systemd.
cat > /etc/guardian/guardian.env << EOF
MQTT_BROKER=127.0.0.1
MQTT_PORT=1883
MQTT_TLS=false
MQTT_USER=guardian
MQTT_PASS=$MQTT_PASS
MASTER_PASSWORD=$MASTER_PASSWORD
TOTP_SECRET=$TOTP_SECRET
NUKE_PASSPHRASE=$NUKE_PASSPHRASE
COMMAND_SIGNING_KEY=$COMMAND_SIGNING_KEY
NTFY_TOPIC=$NTFY_TOPIC
COMMAND_TTL=300
NUKE_COUNTDOWN=600
GUARDIAN_DB=/var/lib/guardian/guardian.db
EOF
chown root:root /etc/guardian/guardian.env
chmod 600 /etc/guardian/guardian.env

echo "Setting up systemd service for relay..."
cat > /etc/systemd/system/guardian.service << EOF
[Unit]
Description=Guardian Relay Server
After=network.target mosquitto.service
[Service]
EnvironmentFile=/etc/guardian/guardian.env
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
=== GUARDIAN CREDENTIALS v2 — KEEP SAFE — SAVE TO BITWARDEN ===

SERVER PUBLIC IP:    $SERVER_IP
SERVER WG PUBLIC KEY: $SERVER_PUB

MQTT USER:     guardian
MQTT PASSWORD: $MQTT_PASS
MASTER PASSWORD: $MASTER_PASSWORD
TOTP SECRET (Base32): $TOTP_SECRET
NUKE PASSPHRASE: $NUKE_PASSPHRASE
COMMAND SIGNING KEY (64 hex): $COMMAND_SIGNING_KEY
NTFY TOPIC: $NTFY_TOPIC

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
1. Copy dashboard/dashboard.html to /var/www/html/guardian/index.html
2. Import TOTP SECRET into your authenticator using Base32 / SHA1 / 6 digits / 30 seconds
3. Provision the COMMAND SIGNING KEY to each agent during installation
4. Configure each device's unique MQTT credentials and device ID before enrollment
5. Start the relay: systemctl start guardian
6. Save /root/guardian_credentials.txt in Bitwarden; do not share it

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