# 🛡️ Guardian — Personal Device Protection System v1

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
| Dashboard on any device | ✅ | ✅ |
| TOTP backup codes | ✅ | ✅ |

---

## 🏗️ Architecture

```
[Android APK] ──WireGuard──┐
                            ├──► [Private VPS Relay] ◄── [Dashboard — any device]
[Windows Agent] ─WireGuard──┘     (MQTT + FastAPI + nginx)
```

- **No data stored in cloud** — VPS only routes encrypted commands
- **WireGuard tunnel** — cryptographically authenticated, invisible to public internet
- **Dashboard hosted on VPS** — accessible from any device on the tunnel (phone, tablet, borrowed device)
- **MQTT broker** — lightweight real-time command delivery

---

## 🔐 Security Layers

Every destructive command (wipe/lock/backup) requires **all 4** to pass:

1. ✅ Master password login
2. ✅ Exact confirmation phrase typed correctly
3. ✅ Live TOTP code (Authy) **or** one-time backup code
4. ✅ 10-second abort window on the device itself

Additional protections:
- Commands expire after 60 seconds (anti-replay)
- One-time nonces prevent command replay attacks
- Max 5 failed login attempts before relay lockout
- Dashboard only accessible through WireGuard tunnel (nginx allow/deny)

---

## 📁 Project Structure

```
guardian-device-protection/
├── vps-setup/
│   ├── setup_vps.sh          # One-time VPS setup (WireGuard + MQTT + relay + nginx)
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

## 🚀 Deployment Guide

### Before You Start
- Install **Bitwarden** (free) at bitwarden.com — you will save all credentials here
- Install **Authy** on your phone — enable multi-device in Authy settings
- Install **Authy desktop** on your laptop as backup

### 1. Get a Free VPS
- Sign up at [Oracle Cloud](https://cloud.oracle.com) — Always Free tier (Ubuntu 22.04)
- Open ports in Oracle Security List: `51820/UDP` and `8443/TCP`

### 2. Run VPS Setup
```bash
ssh ubuntu@YOUR_VPS_IP
sudo bash setup_vps.sh
cat /root/guardian_credentials.txt
# SAVE EVERYTHING IN THIS FILE TO BITWARDEN IMMEDIATELY
```

### 3. Generate Permanent TOTP Secret
```bash
python3 -c "import pyotp; print(pyotp.random_base32())"
# Copy the output — this is your TOTP_SECRET
# Add it to Authy: Add Account → Enter key manually
# Save it to Bitwarden
```

### 4. Configure relay_server.py
```python
MASTER_PASSWORD = "your_strong_password"        # save to Bitwarden
TOTP_SECRET     = "your_generated_secret"        # from step 3
MQTT_PASS       = "paste from credentials file"  # from step 2
BACKUP_CODES    = ["code1", "code2", ...]        # generate below, save to Bitwarden
```

Generate backup codes:
```bash
python3 -c "import secrets; [print('guardian-'+secrets.token_hex(4)) for _ in range(5)]"
```

### 5. Deploy Relay to VPS
```bash
scp relay_server.py ubuntu@YOUR_VPS_IP:/opt/guardian/
scp dashboard/dashboard.html ubuntu@YOUR_VPS_IP:/var/www/html/guardian/index.html
ssh ubuntu@YOUR_VPS_IP
systemctl start guardian
```

### 6. Connect Windows Laptop
```bash
# 1. Install WireGuard → paste LAPTOP config from credentials file → activate tunnel
# 2. pip install -r windows-agent/requirements.txt
# 3. Edit guardian_agent.py → set MQTT_PASS
# 4. python guardian_agent.py  (test it works)
# 5. Run install_startup.bat as Administrator
```

### 7. Connect Android Phone
```
1. Install WireGuard from Play Store → paste PHONE config → activate
2. Open android-app/ in Android Studio → Build APK
3. Install APK on phone → grant Device Admin + Location (Always)
```

### 8. Open Dashboard
```
WireGuard active on any device
→ Browser → http://10.99.0.1/guardian
→ Login with master password
```

---

## 📱 Access From Any Device (Theft Scenario)

If both phone and laptop are stolen:
1. Borrow any device
2. Install WireGuard → import your saved tunnel config from Bitwarden
3. Open `http://10.99.0.1/guardian` in browser
4. Login → use a backup code (saved in Bitwarden) if Authy unavailable
5. Wipe both devices

---

## 💾 What to Save in Bitwarden

Create a secure note called **Guardian System** containing:

```
VPS IP:
VPS SSH key/password:
MQTT Password:
Master Password:
TOTP Secret:
Backup Codes (5x, cross out used ones):
Dashboard URL: http://10.99.0.1/guardian
WireGuard — Phone config: (paste full config block)
WireGuard — Laptop config: (paste full config block)
```

---

## ➕ Adding New Devices

```bash
# On VPS
sudo bash add_device.sh <device_name>
# Copy printed WireGuard config to new device, install agent
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| VPN Tunnel | WireGuard |
| Message Broker | Mosquitto MQTT |
| Relay Server | Python · FastAPI · Uvicorn |
| Auth | JWT · TOTP (pyotp) · bcrypt · backup codes |
| Dashboard Hosting | nginx (WireGuard-restricted) |
| Android Agent | Kotlin · Device Admin API · FusedLocationProvider |
| Windows Agent | Python · psutil · PowerShell |
| Dashboard UI | HTML · JavaScript · Leaflet.js · WebSocket |

---

## ⚠️ Important Warnings

- Windows wipe uses `-WhatIf` (dry run) by default — remove only after testing on spare device
- Android wipe is real and immediate — test on spare phone first
- Never commit `guardian_credentials.txt`, `.key` files, or `wg0.conf` (covered by .gitignore)
- Each backup code works **once only** — cross it off in Bitwarden after use

---

## 📄 License

Personal use only. Unauthorized use or distribution prohibited.

---
*No data leaves your own infrastructure.*