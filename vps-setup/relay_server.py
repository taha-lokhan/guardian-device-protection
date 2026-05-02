"""
Guardian Relay Server — v1
Runs on VPS. Handles device heartbeats, location, commands.

SETUP:
  1. Fill in MASTER_PASSWORD, TOTP_SECRET, MQTT_PASS below
  2. Copy to VPS: scp relay_server.py ubuntu@YOUR_VPS:/opt/guardian/
  3. Start: systemctl start guardian
  4. Add TOTP_SECRET to Authy manually
"""

import asyncio, json, time, secrets
import pyotp, paho.mqtt.client as mqtt
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from passlib.context import CryptContext
import uvicorn

# ── CONFIG — FILL ALL THESE IN BEFORE DEPLOYING ────────────────────────────────
MASTER_PASSWORD   = "CHANGE_THIS_STRONG_PASSWORD"

# Generate your permanent TOTP secret ONCE:
#   python3 -c "import pyotp; print(pyotp.random_base32())"
# Paste result here, then add it to Authy manually.
TOTP_SECRET       = "REPLACE_WITH_YOUR_PERMANENT_TOTP_SECRET"

JWT_SECRET        = secrets.token_hex(32)
MQTT_USER         = "guardian"
MQTT_PASS         = "REPLACE_WITH_MQTT_PASS_FROM_CREDENTIALS_FILE"
MQTT_HOST         = "127.0.0.1"
MQTT_PORT         = 1883
COMMAND_EXPIRY_S  = 60
MAX_FAILED_LOGINS = 5
NONCE_TTL_S       = 120   # nonces older than this are purged

# ── BACKUP CODES — save these to Bitwarden, each works once only ───────────────
# Regenerate: python3 -c "import secrets; [print('guardian-'+secrets.token_hex(4)) for _ in range(5)]"
BACKUP_CODES = [
    "REPLACE_WITH_CODE_1",
    "REPLACE_WITH_CODE_2",
    "REPLACE_WITH_CODE_3",
    "REPLACE_WITH_CODE_4",
    "REPLACE_WITH_CODE_5",
]
used_backup_codes = set()

# ── STATE ───────────────────────────────────────────────────────────────────────
devices              = {}
command_log          = []
used_nonces          = {}   # nonce -> timestamp (TTL-based, not infinite set)
failed_logins        = 0
dashboard_ws_clients = []
_event_loop          = None

app = FastAPI(title="Guardian Relay v1")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
pwd_context = CryptContext(schemes=["bcrypt"])

print(f"\n{'='*55}")
print(f"GUARDIAN RELAY v1 STARTING")
print(f"TOTP Secret in use: {TOTP_SECRET}")
print(f"Add to Authy: otpauth://totp/Guardian?secret={TOTP_SECRET}&issuer=Guardian")
print(f"{'='*55}\n")

# ── AUTH ────────────────────────────────────────────────────────────────────────
def verify_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Unauthorized")
    try:
        jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(401, "Invalid token")

def purge_old_nonces():
    now = time.time()
    expired = [k for k, v in used_nonces.items() if now - v > NONCE_TTL_S]
    for k in expired:
        del used_nonces[k]

def verify_destructive_command(cmd: dict):
    errors = []
    PHRASES = {
        "wipe":   "CONFIRM-WIPE-ALL-DATA",
        "lock":   "CONFIRM-DEVICE-LOCK",
        "backup": "CONFIRM-BACKUP-NOW",
    }
    required_phrase = PHRASES.get(cmd.get("action"))
    if not required_phrase or cmd.get("phrase") != required_phrase:
        errors.append(f"Wrong confirmation phrase. Required: '{required_phrase}'")

    # TOTP check — accepts live code OR a valid backup code
    totp        = pyotp.TOTP(TOTP_SECRET)
    totp_valid  = totp.verify(str(cmd.get("totp", "")), valid_window=1)
    backup_code = cmd.get("backup_code", "").strip()
    backup_valid = (
        backup_code in BACKUP_CODES and
        backup_code not in used_backup_codes and
        backup_code != "" and
        not backup_code.startswith("REPLACE_")
    )

    if not totp_valid and not backup_valid:
        errors.append("Invalid TOTP code and no valid backup code provided")
    elif backup_valid:
        used_backup_codes.add(backup_code)
        log_event(cmd.get("device_id", "unknown"), "backup_code_used", backup_code[:8] + "...")

    cmd_time = cmd.get("timestamp", 0)
    if abs(time.time() - cmd_time) > COMMAND_EXPIRY_S:
        errors.append(f"Command expired (must be within {COMMAND_EXPIRY_S}s)")

    purge_old_nonces()
    nonce = cmd.get("nonce")
    if not nonce or nonce in used_nonces:
        errors.append("Invalid or replayed nonce")
    else:
        used_nonces[nonce] = time.time()

    if errors:
        raise HTTPException(400, {"errors": errors})

# ── MQTT ────────────────────────────────────────────────────────────────────────
mqtt_client = mqtt.Client(clean_session=False, client_id="guardian-relay")
mqtt_client.username_pw_set(MQTT_USER, MQTT_PASS)

def on_mqtt_message(client, userdata, msg):
    """Runs in MQTT thread — must not call asyncio directly."""
    try:
        payload   = json.loads(msg.payload.decode())
        device_id = payload.get("device_id")
        if not device_id:
            return
        if msg.topic == "guardian/heartbeat":
            devices[device_id] = {
                **devices.get(device_id, {}),
                "device_id": device_id,
                "name":      payload.get("name", device_id),
                "type":      payload.get("type", "unknown"),
                "last_seen": time.time(),
                "status":    "online",
                "battery":   payload.get("battery"),
                "ip":        payload.get("wg_ip"),
            }
        elif msg.topic == "guardian/location":
            if device_id in devices:
                devices[device_id]["location"] = {
                    "lat":       payload.get("lat"),
                    "lon":       payload.get("lon"),
                    "accuracy":  payload.get("accuracy"),
                    "timestamp": time.time(),
                }
        elif msg.topic == "guardian/backup_complete":
            log_event(device_id, "backup_complete", payload.get("backup_id"))

        # FIX: schedule coroutine safely from MQTT thread
        if _event_loop and not _event_loop.is_closed():
            _event_loop.call_soon_threadsafe(
                _event_loop.create_task,
                broadcast_to_dashboard({"event": "device_update", "devices": get_devices_safe()})
            )
    except Exception as e:
        print(f"MQTT error: {e}")

mqtt_client.on_message = on_mqtt_message
mqtt_client.connect(MQTT_HOST, MQTT_PORT, 60)
mqtt_client.subscribe([
    ("guardian/heartbeat", 1),
    ("guardian/location", 1),
    ("guardian/backup_complete", 1)
])
mqtt_client.loop_start()

# ── BACKGROUND TASKS ────────────────────────────────────────────────────────────
async def offline_checker():
    """Runs every 60s — marks devices offline and pushes update to dashboard."""
    while True:
        await asyncio.sleep(60)
        changed = False
        for d in devices.values():
            was_online = d.get("status") == "online"
            is_online  = (time.time() - d.get("last_seen", 0)) < 90
            d["status"] = "online" if is_online else "offline"
            if was_online and not is_online:
                changed = True
                log_event(d["device_id"], "device_offline", "no heartbeat for 90s")
        if changed:
            await broadcast_to_dashboard({"event": "device_update", "devices": get_devices_safe()})

@app.on_event("startup")
async def startup():
    global _event_loop
    _event_loop = asyncio.get_event_loop()
    asyncio.create_task(offline_checker())

# ── HELPERS ─────────────────────────────────────────────────────────────────────
def get_devices_safe():
    result = {}
    for k, v in devices.items():
        d = dict(v)
        d["status"] = "online" if (time.time() - d.get("last_seen", 0)) < 90 else "offline"
        result[k] = d
    return result

def log_event(device_id, action, detail=""):
    entry = {"timestamp": time.time(), "device_id": device_id, "action": action, "detail": str(detail)}
    command_log.append(entry)
    print(f"[AUDIT] {entry}")

async def broadcast_to_dashboard(data: dict):
    dead = []
    for ws in dashboard_ws_clients:
        try:
            await ws.send_json(data)
        except:
            dead.append(ws)
    for ws in dead:
        dashboard_ws_clients.remove(ws)

def send_command(device_id: str, action: str, payload: dict = {}):
    msg = json.dumps({"action": action, "timestamp": time.time(), **payload})
    mqtt_client.publish(f"guardian/cmd/{device_id}", msg, qos=1)
    log_event(device_id, action, payload)

# ── ROUTES ───────────────────────────────────────────────────────────────────────
@app.post("/auth/login")
async def login(body: dict):
    global failed_logins
    if failed_logins >= MAX_FAILED_LOGINS:
        raise HTTPException(429, "Too many failed attempts. Restart relay to unlock.")
    if body.get("password") != MASTER_PASSWORD:
        failed_logins += 1
        raise HTTPException(401, f"Wrong password. {MAX_FAILED_LOGINS - failed_logins} attempts remaining.")
    failed_logins = 0
    token = jwt.encode({"sub": "guardian", "exp": time.time() + 3600}, JWT_SECRET, algorithm="HS256")
    return {"token": token}

@app.get("/devices", dependencies=[Depends(verify_token)])
async def list_devices():
    return get_devices_safe()

@app.get("/log", dependencies=[Depends(verify_token)])
async def get_log():
    return command_log[-100:]

@app.post("/cmd/lock", dependencies=[Depends(verify_token)])
async def cmd_lock(body: dict):
    verify_destructive_command({**body, "action": "lock"})
    send_command(body["device_id"], "lock")
    return {"status": "sent"}

@app.post("/cmd/wipe", dependencies=[Depends(verify_token)])
async def cmd_wipe(body: dict):
    verify_destructive_command({**body, "action": "wipe"})
    if not body.get("backup_confirmed") and not body.get("skip_backup"):
        raise HTTPException(400, {"error": "backup_not_confirmed"})
    send_command(body["device_id"], "wipe")
    return {"status": "sent", "warning": "IRREVERSIBLE — device has 30s abort window"}

@app.post("/cmd/abort_wipe", dependencies=[Depends(verify_token)])
async def cmd_abort_wipe(body: dict):
    send_command(body["device_id"], "abort_wipe")
    log_event(body["device_id"], "abort_wipe", "abort sent from dashboard")
    return {"status": "abort_sent"}

@app.post("/cmd/backup", dependencies=[Depends(verify_token)])
async def cmd_backup(body: dict):
    verify_destructive_command({**body, "action": "backup"})
    send_command(body["device_id"], "backup", {"backup_target": body.get("backup_target")})
    return {"status": "sent"}

@app.post("/cmd/locate", dependencies=[Depends(verify_token)])
async def cmd_locate(body: dict):
    send_command(body["device_id"], "locate")
    return {"status": "sent"}

# ── WEBSOCKET — FIX: token via query param (browser WS doesn't support headers) ─
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    token = ws.query_params.get("token", "")
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except JWTError:
        await ws.close(code=1008)
        return
    await ws.accept()
    dashboard_ws_clients.append(ws)
    try:
        await ws.send_json({"event": "init", "devices": get_devices_safe()})
        while True:
            await asyncio.sleep(30)
            await ws.send_json({"event": "ping"})
    except WebSocketDisconnect:
        if ws in dashboard_ws_clients:
            dashboard_ws_clients.remove(ws)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8443)