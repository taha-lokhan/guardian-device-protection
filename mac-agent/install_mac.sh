#!/bin/bash
# Guardian Mac Agent v2.3.0 — Installer
# Run as root: sudo bash install_mac.sh
set -e

AGENT_DIR="/opt/guardian"
PLIST="/Library/LaunchDaemons/com.guardian.agent.plist"
AGENT_SCRIPT="$AGENT_DIR/guardian_mac_agent.py"
LOG_FILE="/var/log/guardian_mac.log"

[ "$EUID" -ne 0 ] && echo "[!] Run as root: sudo bash install_mac.sh" && exit 1

echo ""
echo "=== Guardian Mac Agent v2.3.0 Setup ==="
echo ""
read -p "VPS IP/hostname: " BROKER
read -p "MQTT port [1883]: " MQTT_PORT
MQTT_PORT=${MQTT_PORT:-1883}
if [[ ! "$MQTT_PORT" =~ ^[0-9]{1,5}$ ]] || (( MQTT_PORT < 1 || MQTT_PORT > 65535 )); then echo "[!] Invalid MQTT port."; exit 1; fi
read -p "MQTT username [guardian]: " MQTT_USER
MQTT_USER=${MQTT_USER:-guardian}
read -s -p "MQTT password: " MQTT_PASS; echo ""
read -p "Device command key ID: " COMMAND_KEY_ID
read -p "Device Ed25519 public key (base64): " COMMAND_PUBLIC_KEY
if [[ ! "$COMMAND_KEY_ID" =~ ^[A-Za-z0-9_-]{1,64}$ || ! "$COMMAND_PUBLIC_KEY" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    echo "[!] A valid device key ID and 32-byte base64 Ed25519 public key are required."
    exit 1
fi
read -p "Device ID (e.g. mac-home): " DEVICE_ID
read -p "WireGuard IP for this device (e.g. 10.99.0.2) [leave blank to skip]: " WG_IP

xml_escape() {
    local value="$1"
    value="${value//&/\&amp;}"
    value="${value//</\&lt;}"
    value="${value//>/\&gt;}"
    value="${value//\"/\&quot;}"
    value="${value//\'/\&apos;}"
    printf "%s" "$value"
}
BROKER_XML="$(xml_escape "$BROKER")"
MQTT_USER_XML="$(xml_escape "$MQTT_USER")"
MQTT_PASS_XML="$(xml_escape "$MQTT_PASS")"
COMMAND_KEY_ID_XML="$(xml_escape "$COMMAND_KEY_ID")"
COMMAND_PUBLIC_KEY_XML="$(xml_escape "$COMMAND_PUBLIC_KEY")"
DEVICE_ID_XML="$(xml_escape "$DEVICE_ID")"
WG_IP_XML="$(xml_escape "$WG_IP")"

echo "[*] Installing paho-mqtt..."
pip3 install --quiet paho-mqtt cryptography

mkdir -p "$AGENT_DIR"
cp guardian_mac_agent.py "$AGENT_SCRIPT"
cp command_auth.py "$AGENT_DIR/command_auth.py"
chmod 700 "$AGENT_SCRIPT"
chown root:wheel "$AGENT_DIR" "$AGENT_SCRIPT" "$AGENT_DIR/command_auth.py"
chmod 600 "$AGENT_DIR/command_auth.py"
touch "$LOG_FILE"
chown root:wheel "$LOG_FILE"
chmod 600 "$LOG_FILE"

PYTHON3_PATH=$(which python3)
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.guardian.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON3_PATH</string>
        <string>$AGENT_SCRIPT</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>GUARDIAN_BROKER</key>      <string>$BROKER_XML</string>
        <key>GUARDIAN_PORT</key>        <string>$MQTT_PORT</string>
        <key>GUARDIAN_MQTT_USER</key>   <string>$MQTT_USER_XML</string>
        <key>GUARDIAN_MQTT_PASS</key>   <string>$MQTT_PASS_XML</string>
        <key>GUARDIAN_COMMAND_KEY_ID</key>       <string>$COMMAND_KEY_ID_XML</string>
        <key>GUARDIAN_COMMAND_PUBLIC_KEY</key>  <string>$COMMAND_PUBLIC_KEY_XML</string>
        <key>GUARDIAN_DEVICE_ID</key>   <string>$DEVICE_ID_XML</string>
        <key>GUARDIAN_ABORT_WINDOW</key><string>30</string>
        <key>GUARDIAN_WG_IP</key>       <string>$WG_IP_XML</string>
    </dict>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
    <key>StandardOutPath</key>   <string>$LOG_FILE</string>
    <key>StandardErrorPath</key> <string>$LOG_FILE</string>
    <key>ThrottleInterval</key>  <integer>10</integer>
</dict>
</plist>
EOF

# The LaunchDaemon plist contains MQTT and command-signing credentials.
chmod 600 "$PLIST"
chown root:wheel "$PLIST"
plutil -lint "$PLIST"

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load -w "$PLIST"

echo ""
echo "=== Guardian Mac Agent v2.3.0 installed ==="
echo "  Device     : $DEVICE_ID"
echo "  Broker     : $BROKER"
echo "  WireGuard  : ${WG_IP:-not set}"
echo "  Log        : tail -f $LOG_FILE"
echo "To uninstall : sudo launchctl unload $PLIST && sudo rm -rf $AGENT_DIR $PLIST"
