# 🛡️ Guardian — Personal Device Protection System

> **Private, self-hosted anti-theft system for Android and Windows.**
> Remote wipe · Remote lock · Real-time GPS · Backup before wipe · No cloud. No third-party services.

---

## ✨ Features

| Feature | Android | Windows |
|---------|---------|----------|
| Real-time GPS location | ✅ | ✅ (IP-based) |
| Remote factory wipe | ✅ | ✅ |
| Remote screen lock | ✅ | ✅ |
| Backup before wipe | ✅ | ✅ |
| Survives device reboot | ✅ | ✅ |
| Add unlimited devices | ✅ | ✅ |

---

## 🏗️ Architecture

```
[Android APK] ──WireGuard──┐
                            ├──► [Private VPS Relay] ◄── [Dashboard]
[Windows Agent] ─WireGuard──┘     (MQTT + FastAPI)
```

- **No data stored in cloud** — VPS only routes encrypted commands
- **WireGuard tunnel** — cryptographically authenticated, invisible to public internet
- **MQTT broker** — lightweight real-time command delivery
- **Dashboard** — browser-based control panel, accessible only over WireGuard tunnel

---

## 🔐 Security Layers

Every destructive command (wipe/lock/backup) requires **all 4** to pass:

1. ✅ Exact confirmation phrase typed correctly
2. ✅ Live 6-digit TOTP code from authenticator app
3. ✅ Final confirmation popup in dashboard
4. ✅ 10-second abort window on the device itself

Additional protections:
- Commands expire after 60 seconds (anti-replay)
- One-time nonces prevent command replay attacks
- Max 5 failed login attempts before relay lockout
- Dashboard only accessible through WireGuard tunnel

---

## 📁 Project Structure

```
guardian-device-protection/
├── vps-setup/
│   ├── setup_vps.sh          # One-time VPS setup
│   ├── add_device.sh         # Add any new device anytime
│   ├── relay_server.py       # FastAPI + MQTT relay server
│   └── requirements.txt
├── windows-agent/
│   ├── guardian_agent.py     # Background Windows agent
│   ├── install_startup.bat   # Auto-start at Windows login
│   └── requirements.txt
├── dashboard/
│   └── dashboard.html        # Browser control panel
└── android-app/
    └── app/src/main/
        └── java/com/guardian/agent/
            ├── GuardianService.kt
            ├── SetupActivity.kt
            ├── BootReceiver.kt
            └── GuardianAdminReceiver.kt
```

---

## 🚀 Quick Start

### 1. Get a Free VPS
- Sign up at [Oracle Cloud](https://cloud.oracle.com) — Always Free tier
- Create Ubuntu 22.04 instance
- Open ports: `51820/UDP` and `8443/TCP`

### 2. Setup VPS
```bash
ssh ubuntu@YOUR_VPS_IP
sudo bash setup_vps.sh
cat /root/guardian_credentials.txt
```

### 3. Start Relay
```bash
# Edit relay_server.py — set MASTER_PASSWORD and MQTT_PASS
/opt/guardian/venv/bin/python /opt/guardian/relay_server.py
# Add printed TOTP secret to Google Authenticator
```

### 4. Windows Agent
```bash
pip install -r windows-agent/requirements.txt
# Edit guardian_agent.py → set MQTT_PASS
python guardian_agent.py
# Run install_startup.bat as Administrator for auto-start
```

### 5. Android App
```
Open android-app/ in Android Studio → Build APK → Install → Grant Device Admin
```

### 6. Dashboard
```
Open dashboard/dashboard.html in Chrome → Enter 10.99.0.1:8443 → Login
```

---

## ➕ Adding New Devices

```bash
sudo bash add_device.sh <device_name>
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| VPN Tunnel | WireGuard |
| Message Broker | Mosquitto MQTT |
| Relay Server | Python · FastAPI · Uvicorn |
| Auth | JWT · TOTP · bcrypt |
| Android Agent | Kotlin · Device Admin API · FusedLocationProvider |
| Windows Agent | Python · psutil · PowerShell |
| Dashboard | HTML · JavaScript · Leaflet.js · WebSocket |

---

## ⚠️ Important

- Windows wipe uses `-WhatIf` (dry run) by default — remove only after testing on spare device
- Android wipe is real and immediate — test on spare phone first
- Never commit `guardian_credentials.txt` or `.key` files

---

## 📄 License

Personal use only. Unauthorized use or distribution prohibited.

---
*No data leaves your own infrastructure.*