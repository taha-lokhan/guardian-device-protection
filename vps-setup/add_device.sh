#!/bin/bash
# Usage: sudo bash add_device.sh <device_name>

if [ -z "$1" ]; then
  echo "Usage: bash add_device.sh <device_name>"
  exit 1
fi

DEVICE_NAME=$1
WG_DIR=/etc/wireguard
SERVER_PUB=$(cat $WG_DIR/server_public.key)
SERVER_IP=$(curl -s ifconfig.me)

LAST_IP=$(grep -o '10\.99\.0\.[0-9]*' $WG_DIR/wg0.conf | sort -t. -k4 -n | tail -1 | cut -d. -f4)
NEXT_IP=$((LAST_IP + 1))
DEVICE_IP="10.99.0.$NEXT_IP"

wg genkey | tee $WG_DIR/${DEVICE_NAME}_private.key | wg pubkey > $WG_DIR/${DEVICE_NAME}_public.key
DEVICE_PRIV=$(cat $WG_DIR/${DEVICE_NAME}_private.key)
DEVICE_PUB=$(cat $WG_DIR/${DEVICE_NAME}_public.key)

cat >> $WG_DIR/wg0.conf << EOF

# $DEVICE_NAME
[Peer]
PublicKey = $DEVICE_PUB
AllowedIPs = $DEVICE_IP/32
EOF

wg set wg0 peer $DEVICE_PUB allowed-ips $DEVICE_IP/32

echo ""
echo "=== NEW DEVICE: $DEVICE_NAME ==="
echo "WireGuard IP: $DEVICE_IP"
echo ""
echo "--- WireGuard config for $DEVICE_NAME ---"
cat << WGCONF
[Interface]
PrivateKey = $DEVICE_PRIV
Address = $DEVICE_IP/32
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $SERVER_IP:51820
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25
WGCONF