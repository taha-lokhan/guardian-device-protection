# 🛡️ Guardian Device Protection v2.0

Private anti-theft system — remote wipe, lock, GPS tracking and backup for **Android**, **Windows**, and **macOS** over a self-hosted WireGuard relay. No cloud. No third-party. Fully private.

## What's New in v2.0

- ✅ **Mac Agent** — Full macOS support with Option A wipe (eraseinstall + reinstall macOS)
- ✅ **Nuke System** — 10-minute silent countdown, visible only on dashboard
- ✅ **3-Step Confirmation** — Passphrase → type NUKE → TOTP before arming
- ✅ **ntfy.sh Alerts** — Push notifications to secondary device on nuke arm/abort/execute
- ✅ **Location Burst** — 5 location pings sent before wipe executes
- ✅ **Command TTL** — Stale commands (older than 5 min) are ignored
- ✅ **Abort Window** — Native OS dialog on device during countdown
- ✅ **Dashboard v2** — Live countdown timer, abort button, per-device nuke panel

## Architecture

```
[Android / Windows / Mac] ──MQTT──▶ [VPS Relay (FastAPI)]
                                            │
                          ┌─────────────────┼─────────────────┐
                          │                 │                 │
                     [Dashboard]       [ntfy.sh]        [MQTT Broker]
                    (WireGuard VPN)
```

## Repository Structure

```
guardian-device-protection/
├── vps-setup/
│   ├── relay_server.py       # FastAPI relay server
│   ├── requirements.txt
│   └── .env.template         # Copy to .env before deploy
├── mac-agent/
│   ├── guardian_mac_agent.py # macOS agent (LaunchDaemon)
│   ├── install_mac.sh        # Installer script
│   └── requirements.txt
├── windows-agent/
│   └── guardian_windows_agent.py
├── android-app/
│   └── (Kotlin source)
└── dashboard/
    └── dashboard.html        # Self-contained dashboard
```

## Quick Start

### 1. VPS Setup

```bash
git clone https://github.com/taha-lokhan/guardian-device-protection
cd guardian-device-protection/vps-setup
cp .env.template .env
nano .env   # Fill in all values
pip install -r requirements.txt
uvicorn relay_server:app --host 0.0.0.0 --port 8000
```

### 2. Mac Agent

```bash
cd mac-agent
sudo bash install_mac.sh
```

> ⚠️ For Option A wipe to work, you need a macOS installer app in `/Applications`.
> Download via: App Store → search "macOS Sequoia" (or current version)

### 3. Windows Agent

```bash
cd windows-agent
pip install paho-mqtt
# Set env vars then:
python guardian_windows_agent.py
```

## Nuke System — How It Works

1. Dashboard: click **🔥 Nuke** on a device
2. **Step 1** — Enter nuke passphrase (`NUKE_PASSPHRASE` in .env)
3. **Step 2** — Type `NUKE` exactly
4. **Step 3** — Enter current TOTP code
5. Server arms a **10-minute countdown**, sends ntfy.sh alert
6. Device shows a **30-second abort window** (native OS dialog)
7. If not aborted → **location burst** (5 pings) → **wipe executes**
8. ntfy.sh alert sent on completion

## Environment Variables

| Variable | Description |
|---|---|
| `MQTT_BROKER` | MQTT broker host |
| `MQTT_USER` / `MQTT_PASS` | MQTT credentials |
| `TOTP_SECRET` | Base32 TOTP secret |
| `MASTER_PASSWORD` | Dashboard login password |
| `NUKE_PASSPHRASE` | Step 1 of nuke confirmation |
| `NTFY_TOPIC` | ntfy.sh topic (treat as password) |
| `COMMAND_TTL` | Seconds before command expires (default: 300) |
| `NUKE_COUNTDOWN` | Seconds before wipe executes (default: 600) |

## Security Notes

- Dashboard is only accessible over **WireGuard VPN**
- All API endpoints require `Authorization: Bearer password:totp`
- TOTP is validated server-side with ±1 window drift
- `NTFY_TOPIC` is secret — treat it like a password
- Commands include TTL — replayed/stale commands are ignored
- Nuke sessions expire after 2 minutes if not completed

---

> **Private repo. Do not share credentials or topic names.**
