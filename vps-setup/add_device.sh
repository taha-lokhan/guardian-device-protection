#!/usr/bin/env bash
# Add a WireGuard peer. Run as root: sudo bash add_device.sh <device_name>
set -Eeuo pipefail
umask 077

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi
if [[ $# -ne 1 ]]; then
  echo "Usage: sudo bash add_device.sh <device_name>" >&2
  exit 2
fi

DEVICE_NAME="$1"
if [[ ! "$DEVICE_NAME" =~ ^[A-Za-z0-9_-]{1,48}$ ]]; then
  echo "Invalid device name: use 1-48 letters, digits, hyphens or underscores." >&2
  exit 2
fi

WG_DIR=/etc/wireguard
CONFIG="$WG_DIR/wg0.conf"
LOCK="$WG_DIR/.add-device.lock"
[[ -f "$CONFIG" && ! -L "$CONFIG" ]] || { echo "Missing or unsafe $CONFIG" >&2; exit 1; }
[[ -f "$WG_DIR/server_public.key" && ! -L "$WG_DIR/server_public.key" ]] || {
  echo "Missing server public key." >&2; exit 1;
}
command -v wg >/dev/null || { echo "wireguard-tools is required." >&2; exit 1; }
command -v flock >/dev/null || { echo "flock is required." >&2; exit 1; }
systemctl is-active --quiet wg-quick@wg0 || {
  echo "wg0 is not active; refusing to create a peer that cannot be applied." >&2; exit 1;
}

exec 9>"$LOCK"
flock -x 9

if grep -Eq "^[[:space:]]*# DEVICE:$DEVICE_NAME([[:space:]]|$)" "$CONFIG"; then
  echo "A peer with this device name already exists." >&2
  exit 1
fi

LAST_IP=$(awk '
  /^AllowedIPs[[:space:]]*=/ {
    value=$0
    sub(/^[^=]*=[[:space:]]*/, "", value)
    split(value, entries, ",")
    for (i in entries) {
      gsub(/[[:space:]]/, "", entries[i])
      if (entries[i] ~ /^10[.]99[.]0[.][0-9]+\/32$/) {
        split(entries[i], octets, /[.\/]/)
        if (octets[4] > max) max=octets[4]
      }
    }
  }
  END { print max+0 }
' "$CONFIG")
NEXT_IP=$((LAST_IP + 1))
if (( NEXT_IP < 4 || NEXT_IP > 254 )); then
  echo "No free address remains in 10.99.0.0/24." >&2
  exit 1
fi
DEVICE_IP="10.99.0.$NEXT_IP"

SERVER_PUB=$(<"$WG_DIR/server_public.key")
SERVER_IP=$(curl --fail --silent --show-error --max-time 10 https://api.ipify.org)
if [[ ! "$SERVER_IP" =~ ^([0-9]{1,3}[.]){3}[0-9]{1,3}$ ]]; then
  echo "Could not determine a valid public IPv4 address." >&2
  exit 1
fi

PRIVATE_FILE="$WG_DIR/${DEVICE_NAME}_private.key"
PUBLIC_FILE="$WG_DIR/${DEVICE_NAME}_public.key"
[[ ! -e "$PRIVATE_FILE" && ! -e "$PUBLIC_FILE" ]] || {
  echo "Key file already exists for this device; refusing to overwrite." >&2; exit 1;
}
TMP_CONFIG=$(mktemp "$WG_DIR/wg0.conf.XXXXXX")
TMP_PRIVATE=$(mktemp "$WG_DIR/.peer-private.XXXXXX")
TMP_PUBLIC=$(mktemp "$WG_DIR/.peer-public.XXXXXX")
BACKUP_CONFIG=$(mktemp "$WG_DIR/.wg0-backup.XXXXXX")
cleanup() {
  rm -f "$TMP_CONFIG" "$TMP_PRIVATE" "$TMP_PUBLIC" "$BACKUP_CONFIG"
}
trap cleanup EXIT

wg genkey > "$TMP_PRIVATE"
wg pubkey < "$TMP_PRIVATE" > "$TMP_PUBLIC"
chmod 600 "$TMP_PRIVATE"
chmod 644 "$TMP_PUBLIC"
DEVICE_PRIV=$(<"$TMP_PRIVATE")
DEVICE_PUB=$(<"$TMP_PUBLIC")

cp -p "$CONFIG" "$BACKUP_CONFIG"
cat "$CONFIG" > "$TMP_CONFIG"
cat >> "$TMP_CONFIG" <<EOF

# DEVICE:$DEVICE_NAME
[Peer]
PublicKey = $DEVICE_PUB
AllowedIPs = $DEVICE_IP/32
EOF
chmod 600 "$TMP_CONFIG"

install -m 600 "$TMP_PRIVATE" "$PRIVATE_FILE"
install -m 644 "$TMP_PUBLIC" "$PUBLIC_FILE"
if ! install -m 600 "$TMP_CONFIG" "$CONFIG"; then
  rm -f "$PRIVATE_FILE" "$PUBLIC_FILE"
  exit 1
fi
if ! wg set wg0 peer "$DEVICE_PUB" allowed-ips "$DEVICE_IP/32"; then
  install -m 600 "$BACKUP_CONFIG" "$CONFIG"
  rm -f "$PRIVATE_FILE" "$PUBLIC_FILE"
  echo "Could not apply peer; configuration was rolled back." >&2
  exit 1
fi

echo
echo "=== NEW DEVICE: $DEVICE_NAME ==="
echo "WireGuard IP: $DEVICE_IP"
echo
echo "--- WireGuard config for $DEVICE_NAME ---"
cat <<WGCONF
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
echo
echo "Store this client config securely; its private key is shown only once."
