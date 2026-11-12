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
│   ├── command_auth.py       # Protocol-v1 signing helper
│   ├── requirements.txt
│   └── .env.template         # Copy to .env before deploy
├── mac-agent/
│   ├── guardian_mac_agent.py # macOS agent (LaunchDaemon)
│   ├── command_auth.py       # Protocol-v2 Ed25519 verification helper
│   ├── install_mac.sh        # Installer script
│   └── requirements.txt
├── windows-agent/
│   ├── guardian_windows_agent.py
│   └── command_auth.py
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

Before installing an agent, provision a key on the relay host:
```bash
sudo /opt/guardian/venv/bin/python /opt/guardian/provision_device_key.py mac-home
``
Copy only the printed `key_id` and `public_key` into the Mac installer prompts. The Ed25519 private key stays on the relay host. Never copy it to an endpoint.

> ⚠️ For Option A wipe to work, you need a macOS installer app in `/Applications`.
> Download via: App Store → search "macOS Sequoia" (or current version)

### 3. Windows Agent

Place `guardian_windows_agent.py` and `command_auth.py` in the same directory and install dependencies from `windows-agent/requirements.txt`. Provision a unique key on the relay host:
```bash
sudo /opt/guardian/venv/bin/python /opt/guardian/provision_device_key.py win-office
``
Configure the endpoint with the printed values (the public key is not secret):
```powershell
[Environment]::SetEnvironmentVariable("GUARDIAN_COMMAND_KEY_ID", "<key_id>", "Machine")
[Environment]::SetEnvironmentVariable("GUARDIAN_COMMAND_PUBLIC_KEY", "<base64-public-key>", "Machine")
```
Also configure the device ID to exactly match the provisioned ID. Open a new elevated terminal or restart the agent. It refuses to connect without a valid device-specific key ID and public key.

### 4. Android Agent

Build the app from `android-app`. During setup, enter the device ID plus the matching device-specific `key_id` and base64 Ed25519 public key generated on the relay. The Android app stores only the public verification key; the relay private key must never be installed on an endpoint.

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
| `COMMAND_KEY_DIR` | Root-owned directory holding per-device Ed25519 private keys (default `/etc/guardian/command-keys`) |
| `NTFY_TOPIC` | ntfy.sh topic (treat as password) |
| `COMMAND_TTL` | Seconds before command expires (default: 300) |
| `NUKE_COUNTDOWN` | Seconds before wipe executes (default: 600) |

## Security Notes

- Dashboard is only accessible over **WireGuard VPN**
- Protected API endpoints require a login-issued session token
- TOTP is validated server-side with ±1 window drift
- `NTFY_TOPIC` is secret — treat it like a password
- Protocol-v2 command envelopes use Ed25519 signatures over a canonical envelope binding protocol version, key ID, command ID, target device, command, params, issue time, TTL and a unique nonce.
- Protocol-v1 command params use canonical JSON with null, booleans, strings, safe integers, arrays and objects; floating-point values and non-ASCII object keys are rejected to keep Python/Kotlin byte serialization consistent.
- Windows, macOS and Android agents verify the Ed25519 signature against the device-specific pinned public key before dispatch and fail closed on unknown key IDs, altered fields, wrong targets, expired/future commands and replayed command IDs.
- The relay holds a separate private key per device under a root-only key directory. Provision with `provision_device_key.py <device_id>`; rotate with `--rotate` and reconfigure that agent with the new public key; revoke with `revoke_device_key.py <device_id> <key_id>` and update the endpoint trust configuration. Rotation/revocation require coordinated agent reconfiguration; no automatic enrollment or remote rotation API is implemented. Protocol v2 intentionally has no fallback to the old shared-key protocol: upgrade the relay and all agents together, and provision each device before sending it commands.
- Nuke sessions expire after 2 minutes if not completed

---

> **Private repo. Do not share credentials or topic names.**
