#!/usr/bin/env python3
"""
Guardian Relay Server v2.0
FastAPI + MQTT relay with nuke system, TOTP auth, ntfy.sh alerts, command TTL
"""
import asyncio
import json
import os
import time
import hashlib
import hmac
import base64
import struct
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict
import paho.mqtt.client as mqtt
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import httpx

# ─── CONFIG ────────────────────────────────────────────────────────────────────
MQTT_BROKER    = os.getenv("MQTT_BROKER", "localhost")
MQTT_PORT      = int(os.getenv("MQTT_PORT", 1883))
MQTT_USER      = os.getenv("MQTT_USER", "guardian")
MQTT_PASS      = os.getenv("MQTT_PASS", "changeme")
TOTP_SECRET    = os.getenv("TOTP_SECRET", "YOUR_BASE32_SECRET_HERE")
MASTER_PASSWORD = os.getenv("MASTER_PASSWORD", "changeme")
NUKE_PASSPHRASE = os.getenv("NUKE_PASSPHRASE", "changeme-nuke-phrase")
NTFY_TOPIC     = os.getenv("NTFY_TOPIC", "guardian-changeme")
NTFY_URL       = f"https://ntfy.sh/{NTFY_TOPIC}"
COMMAND_TTL    = int(os.getenv("COMMAND_TTL", 300))   # seconds
NUKE_COUNTDOWN = int(os.getenv("NUKE_COUNTDOWN", 600)) # 10 minutes

# CORS: restrict to your dashboard origin.
# Set DASHBOARD_ORIGIN env var to your actual URL, e.g. https://dashboard.yourdomain.com
# Leave empty only during local development.
DASHBOARD_ORIGIN = os.getenv("DASHBOARD_ORIGIN", "")
CORS_ORIGINS = [DASHBOARD_ORIGIN] if DASHBOARD_ORIGIN else []

# ─── STATE ─────────────────────────────────────────────────────────────────────
device_status: Dict[str, dict]   = {}
pending_commands: Dict[str, list] = {}
nuke_state: Dict[str, dict]      = {}  # device_id -> {active, started_at, aborted}
location_log: Dict[str, list]    = {}

# ─── TOTP ───────────────────────────────────────────────────────────────────────
def verify_totp(secret: str, token: str, window: int = 1) -> bool:
    try:
        key = base64.b32decode(secret.upper())
    except Exception:
        return False
    ts = int(time.time()) // 30
    for offset in range(-window, window + 1):
        t = struct.pack(">Q", ts + offset)
        h = hmac.new(key, t, hashlib.sha1).digest()
        o = h[-1] & 0x0F
        code = struct.unpack(">I", h[o:o+4])[0] & 0x7FFFFFFF
        if str(code % 1_000_000).zfill(6) == str(token).zfill(6):
            return True
    return False

# ─── AUTH ───────────────────────────────────────────────────────────────────────
security = HTTPBearer()

def require_auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    parts = token.split(":")
    if len(parts) != 2:
        raise HTTPException(status_code=401, detail="Invalid token format")
    password, totp_code = parts
    if password != MASTER_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid password")
    if not verify_totp(TOTP_SECRET, totp_code):
        raise HTTPException(status_code=401, detail="Invalid TOTP")
    return True

# ─── MQTT ───────────────────────────────────────────────────────────────────────
mqtt_client = mqtt.Client(client_id="relay-server", clean_session=False)
mqtt_client.username_pw_set(MQTT_USER, MQTT_PASS)

def on_connect(client, userdata, flags, rc):
    print(f"[MQTT] Connected: rc={rc}")
    client.subscribe("guardian/+/status")
    client.subscribe("guardian/+/location")
    client.subscribe("guardian/+/ack")

def on_message(client, userdata, msg):
    topic = msg.topic
    try:
        payload = json.loads(msg.payload.decode())
    except Exception:
        return
    parts = topic.split("/")
    if len(parts) < 3:
        return
    device_id = parts[1]
    msg_type  = parts[2]
    if msg_type == "status":
        device_status[device_id] = {
            **payload,
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "device_id": device_id,
        }
    elif msg_type == "location":
        if device_id not in location_log:
            location_log[device_id] = []
        location_log[device_id].append({
            **payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        location_log[device_id] = location_log[device_id][-50:]
    elif msg_type == "ack":
        cmd    = payload.get("command")
        status = payload.get("status")
        if cmd == "wipe_complete":
            if device_id in nuke_state:
                nuke_state[device_id]["completed"] = True
        print(f"[ACK] {device_id} -> {cmd}: {status}")

mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message

def mqtt_connect():
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    mqtt_client.loop_start()

# ─── NTFY ───────────────────────────────────────────────────────────────────────
async def ntfy_alert(title: str, message: str, priority: str = "urgent", tags: str = "warning"):
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                NTFY_URL,
                content=message,
                headers={"Title": title, "Priority": priority, "Tags": tags},
                timeout=5,
            )
    except Exception as e:
        print(f"[NTFY] Failed: {e}")

# ─── NUKE COUNTDOWN TASK ────────────────────────────────────────────────────────
async def nuke_countdown_task(device_id: str):
    started_at = nuke_state[device_id]["started_at"]
    while True:
        await asyncio.sleep(5)
        state = nuke_state.get(device_id, {})
        if state.get("aborted"):
            print(f"[NUKE] Aborted for {device_id}")
            return
        elapsed = time.time() - started_at
        if elapsed >= NUKE_COUNTDOWN:
            print(f"[NUKE] Executing wipe for {device_id}")
            mqtt_client.publish(
                f"guardian/{device_id}/command",
                json.dumps({"command": "location_burst", "issued_at": time.time(), "ttl": 60}),
                qos=1,
            )
            await asyncio.sleep(3)
            mqtt_client.publish(
                f"guardian/{device_id}/command",
                json.dumps({"command": "wipe", "issued_at": time.time(), "ttl": COMMAND_TTL}),
                qos=1,
            )
            nuke_state[device_id]["executed"] = True
            await ntfy_alert(
                title=f"WIPE EXECUTED -- {device_id}",
                message=f"Guardian wiped {device_id} at {datetime.now(timezone.utc).isoformat()}",
                priority="urgent", tags="fire,skull",
            )
            return

# ─── FASTAPI ────────────────────────────────────────────────────────────────────
app = FastAPI(title="Guardian Relay v2", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.on_event("startup")
async def startup():
    mqtt_connect()

# ─── MODELS ─────────────────────────────────────────────────────────────────────
class CommandRequest(BaseModel):
    device_id: str
    command:   str
    params:    Optional[dict] = {}

class NukeInitRequest(BaseModel):
    device_id: str
    step:      int
    value:     str

class NukeAbortRequest(BaseModel):
    device_id: str

# ─── ROUTES ─────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0", "time": datetime.now(timezone.utc).isoformat()}

@app.get("/devices", dependencies=[Depends(require_auth)])
async def get_devices():
    return {"devices": list(device_status.values())}

@app.get("/devices/{device_id}/location", dependencies=[Depends(require_auth)])
async def get_location(device_id: str):
    return {"locations": location_log.get(device_id, [])}

@app.post("/command", dependencies=[Depends(require_auth)])
async def send_command(req: CommandRequest):
    payload = {
        "command": req.command, "params": req.params,
        "issued_at": time.time(), "ttl": COMMAND_TTL, "id": str(uuid.uuid4()),
    }
    mqtt_client.publish(f"guardian/{req.device_id}/command", json.dumps(payload), qos=1)
    return {"status": "sent", "command_id": payload["id"]}

# ─── NUKE (3-STEP) ──────────────────────────────────────────────────────────────
nuke_sessions: Dict[str, dict] = {}

@app.post("/nuke/init", dependencies=[Depends(require_auth)])
async def nuke_init(req: NukeInitRequest):
    device_id = req.device_id
    if req.step == 1:
        if req.value != NUKE_PASSPHRASE:
            raise HTTPException(status_code=403, detail="Invalid nuke passphrase")
        nuke_sessions[device_id] = {"step_completed": 1, "expires_at": time.time() + 120}
        return {"status": "step_1_ok", "next": "Type NUKE to confirm"}
    elif req.step == 2:
        session = nuke_sessions.get(device_id)
        if not session or session["step_completed"] < 1 or time.time() > session["expires_at"]:
            raise HTTPException(status_code=403, detail="Session expired or invalid")
        if req.value.strip().upper() != "NUKE":
            raise HTTPException(status_code=403, detail="Type exactly: NUKE")
        session["step_completed"] = 2
        return {"status": "step_2_ok", "next": "Enter your TOTP code"}
    elif req.step == 3:
        session = nuke_sessions.get(device_id)
        if not session or session["step_completed"] < 2 or time.time() > session["expires_at"]:
            raise HTTPException(status_code=403, detail="Session expired or invalid")
        if not verify_totp(TOTP_SECRET, req.value):
            raise HTTPException(status_code=403, detail="Invalid TOTP")
        nuke_state[device_id] = {
            "active": True, "started_at": time.time(),
            "aborted": False, "executed": False, "countdown_seconds": NUKE_COUNTDOWN,
        }
        nuke_sessions.pop(device_id, None)
        asyncio.create_task(nuke_countdown_task(device_id))
        await ntfy_alert(
            title=f"NUKE ARMED -- {device_id}",
            message=f"10-minute countdown started for {device_id}. Abort from dashboard if needed.",
            priority="urgent", tags="rotating_light,bomb",
        )
        return {"status": "nuke_armed", "countdown_seconds": NUKE_COUNTDOWN,
                "message": "Wipe will execute in 10 minutes. Abort from dashboard."}
    raise HTTPException(status_code=400, detail="Invalid step")

@app.post("/nuke/abort", dependencies=[Depends(require_auth)])
async def nuke_abort(req: NukeAbortRequest):
    state = nuke_state.get(req.device_id)
    if not state or not state.get("active"):
        raise HTTPException(status_code=404, detail="No active nuke for this device")
    if state.get("executed"):
        raise HTTPException(status_code=409, detail="Wipe already executed")
    nuke_state[req.device_id]["aborted"] = True
    await ntfy_alert(
        title=f"NUKE ABORTED -- {req.device_id}",
        message=f"Wipe countdown aborted for {req.device_id}.",
        priority="default", tags="white_check_mark",
    )
    return {"status": "aborted"}

@app.get("/nuke/status/{device_id}", dependencies=[Depends(require_auth)])
async def nuke_status(device_id: str):
    state = nuke_state.get(device_id)
    if not state:
        return {"active": False}
    elapsed   = time.time() - state["started_at"]
    remaining = max(0, NUKE_COUNTDOWN - elapsed)
    return {
        "active":           state["active"],
        "aborted":          state["aborted"],
        "executed":         state.get("executed", False),
        "remaining_seconds": int(remaining),
        "countdown_seconds": NUKE_COUNTDOWN,
    }
