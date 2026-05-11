#!/bin/bash
# Guardian Mac Agent v2.2.1 — Installer
# Run as root: sudo bash install_mac.sh
set -e

AGENT_DIR="/opt/guardian"
PLIST="/Library/LaunchDaemons/com.guardian.agent.plist"
AGENT_SCRIPT="$AGENT_DIR/guardian_mac_agent.py"
LOG_FILE="/var/log/guardian_mac.log"

[ "$EUID" -ne 0 ] && echo "[!] Run as root: sudo bash install_mac.sh" && exit 1

echo ""
echo "=== Guardian Mac Agent v2.2.1 Setup ==="
echo ""
read -p "VPS IP/hostname: " BROKER
read -p "MQTT username [guardian]: " MQTT_USER
MQTT_USER=${MQTT_USER:-guardian}
read -s -p "MQTT password: " MQTT_PASS; echo ""
read -p "Device ID (e.g. mac-home): " DEVICE_ID
read -p "WireGuard IP for this device (e.g. 10.99.0.2) [leave blank to skip]: " WG_IP

echo "[*] Installing paho-mqtt..."
pip3 install --quiet paho-mqtt

mkdir -p "$AGENT_DIR"
cp guardian_mac_agent.py "$AGENT_SCRIPT"
chmod 700 "$AGENT_SCRIPT"
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

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
        <key>GUARDIAN_BROKER</key>      <string>$BROKER</string>
        <key>GUARDIAN_PORT</key>        <string>1883</string>
        <key>GUARDIAN_MQTT_USER</key>   <string>$MQTT_USER</string>
        <key>GUARDIAN_MQTT_PASS</key>   <string>$MQTT_PASS</string>
        <key>GUARDIAN_DEVICE_ID</key>   <string>$DEVICE_ID</string>
        <key>GUARDIAN_ABORT_WINDOW</key><string>30</string>
        <key>GUARDIAN_WG_IP</key>       <string>$WG_IP</string>
    </dict>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
    <key>StandardOutPath</key>   <string>$LOG_FILE</string>
    <key>StandardErrorPath</key> <string>$LOG_FILE</string>
    <key>ThrottleInterval</key>  <integer>10</integer>
</dict>
</plist>
EOF

chmod 644 "$PLIST"
chown root:wheel "$PLIST"

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load -w "$PLIST"

echo ""
echo "=== Guardian Mac Agent v2.2.1 installed ==="
echo "  Device     : $DEVICE_ID"
echo "  Broker     : $BROKER"
echo "  WireGuard  : ${WG_IP:-not set}"
echo "  Log        : tail -f $LOG_FILE"
echo "To uninstall : sudo launchctl unload $PLIST && sudo rm -rf $AGENT_DIR $PLIST"
