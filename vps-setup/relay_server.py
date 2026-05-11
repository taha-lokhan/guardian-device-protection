#!/usr/bin/env python3
"""
Guardian Relay Server v2.1
FastAPI + MQTT relay with nuke system, TOTP auth, ntfy.sh alerts, command TTL

Changes in v2.1:
- SQLite persistence for device_status, location_log, nuke_state
- Nuke init rate limiting: 5 failed attempts per device locks out for 5 minutes
- Stale nuke_state cleanup: executed/aborted states purged after NUKE_STATE_TTL seconds
- Fixed nuke session expiry not clearing stale nuke_state entries
- Windows agent wipe note added in comments
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
import sqlite3
import contextlib
from datetime import datetime, timezone
from typing import Optional, Dict
import paho.mqtt.client as mqtt
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import httpx

# ─── CONFIG ────────────────────────────────────────────────────────────────────
MQTT_BROKER     = os.getenv("MQTT_BROKER",     "localhost")
MQTT_PORT       = int(os.getenv("MQTT_PORT",   1883))
MQTT_USER       = os.getenv("MQTT_USER",       "guardian")
MQTT_PASS       = os.getenv("MQTT_PASS",       "changeme")
TOTP_SECRET     = os.getenv("TOTP_SECRET",     "YOUR_BASE32_SECRET_HERE")
MASTER_PASSWORD = os.getenv("MASTER_PASSWORD", "changeme")
NUKE_PASSPHRASE = os.getenv("NUKE_PASSPHRASE", "changeme-nuke-phrase")
NTFY_TOPIC      = os.getenv("NTFY_TOPIC",      "guardian-changeme")
NTFY_URL        = f"https://ntfy.sh/{NTFY_TOPIC}"
COMMAND_TTL     = int(os.getenv("COMMAND_TTL",    300))   # seconds
NUKE_COUNTDOWN  = int(os.getenv("NUKE_COUNTDOWN", 600))   # 10 minutes
NUKE_STATE_TTL  = int(os.getenv("NUKE_STATE_TTL", 3600))  # purge executed/aborted after 1h
DB_PATH         = os.getenv("GUARDIAN_DB",     "guardian.db")

# Rate limiting: max failed nuke init attempts before lockout
NUKE_MAX_FAILS    = int(os.getenv("NUKE_MAX_FAILS",    5))
NUKE_LOCKOUT_SECS = int(os.getenv("NUKE_LOCKOUT_SECS", 300))  # 5 minutes

# CORS: restrict to your dashboard origin.
DASHBOARD_ORIGIN = os.getenv("DASHBOARD_ORIGIN", "")
CORS_ORIGINS     = [DASHBOARD_ORIGIN] if DASHBOARD_ORIGIN else []

# ─── DATABASE ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

_db_lock = threading.Lock()

@contextlib.contextmanager
def db_conn():
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with db_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_status (
                device_id   TEXT PRIMARY KEY,
                payload     TEXT NOT NULL,
                last_seen   TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS location_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id   TEXT NOT NULL,
                payload     TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_loc_device ON location_log(device_id)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nuke_state (
                device_id        TEXT PRIMARY KEY,
                active           INTEGER NOT NULL DEFAULT 1,
                started_at       REAL NOT NULL,
                aborted          INTEGER NOT NULL DEFAULT 0,
                executed         INTEGER NOT NULL DEFAULT 0,
                countdown_secs   INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nuke_sessions (
                device_id        TEXT PRIMARY KEY,
                step_completed   INTEGER NOT NULL DEFAULT 0,
                expires_at       REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nuke_fails (
                device_id    TEXT PRIMARY KEY,
                fail_count   INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0
            )
        """)

# ─── DB HELPERS ────────────────────────────────────────────────────────────────
def db_upsert_device(device_id: str, payload: dict):
    now = datetime.now(timezone.utc).isoformat()
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO device_status(device_id, payload, last_seen) VALUES(?,?,?) "
            "ON CONFLICT(device_id) DO UPDATE SET payload=excluded.payload, last_seen=excluded.last_seen",
            (device_id, json.dumps(payload), now),
        )

def db_get_all_devices() -> list:
    with db_conn() as conn:
        rows = conn.execute("SELECT payload FROM device_status").fetchall()
    return [json.loads(r["payload"]) for r in rows]

def db_append_location(device_id: str, payload: dict):
    now = datetime.now(timezone.utc).isoformat()
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO location_log(device_id, payload, recorded_at) VALUES(?,?,?)",
            (device_id, json.dumps(payload), now),
        )
        # Keep only the last 50 entries per device
        conn.execute(
            "DELETE FROM location_log WHERE device_id=? AND id NOT IN "
            "(SELECT id FROM location_log WHERE device_id=? ORDER BY id DESC LIMIT 50)",
            (device_id, device_id),
        )

def db_get_locations(device_id: str) -> list:
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT payload FROM location_log WHERE device_id=? ORDER BY id DESC LIMIT 50",
            (device_id,),
        ).fetchall()
    return [json.loads(r["payload"]) for r in rows]

def db_upsert_nuke_state(device_id: str, state: dict):
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO nuke_state(device_id, active, started_at, aborted, executed, countdown_secs) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET "
            "active=excluded.active, started_at=excluded.started_at, "
            "aborted=excluded.aborted, executed=excluded.executed, countdown_secs=excluded.countdown_secs",
            (
                device_id,
                1 if state.get("active") else 0,
                state.get("started_at", time.time()),
                1 if state.get("aborted") else 0,
                1 if state.get("executed") else 0,
                state.get("countdown_seconds", NUKE_COUNTDOWN),
            ),
        )

def db_get_nuke_state(device_id: str) -> Optional[dict]:
    with db_conn() as conn:
        row = conn.execute(
            "SELECT * FROM nuke_state WHERE device_id=?", (device_id,)
        ).fetchone()
    if not row:
        return None
    return {
        "active":            bool(row["active"]),
        "started_at":        row["started_at"],
        "aborted":           bool(row["aborted"]),
        "executed":          bool(row["executed"]),
        "countdown_seconds": row["countdown_secs"],
    }

def db_purge_stale_nuke_states():
    """Remove nuke states that are completed/aborted and older than NUKE_STATE_TTL."""
    cutoff = time.time() - NUKE_STATE_TTL
    with db_conn() as conn:
        conn.execute(
            "DELETE FROM nuke_state WHERE (aborted=1 OR executed=1) AND started_at < ?",
            (cutoff,),
        )

def db_upsert_nuke_session(device_id: str, step: int, expires_at: float):
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO nuke_sessions(device_id, step_completed, expires_at) VALUES(?,?,?) "
            "ON CONFLICT(device_id) DO UPDATE SET step_completed=excluded.step_completed, expires_at=excluded.expires_at",
            (device_id, step, expires_at),
        )

def db_get_nuke_session(device_id: str) -> Optional[dict]:
    with db_conn() as conn:
        row = conn.execute(
            "SELECT * FROM nuke_sessions WHERE device_id=?", (device_id,)
        ).fetchone()
    if not row:
        return None
    return {"step_completed": row["step_completed"], "expires_at": row["expires_at"]}

def db_delete_nuke_session(device_id: str):
    with db_conn() as conn:
        conn.execute("DELETE FROM nuke_sessions WHERE device_id=?", (device_id,))

# ─── RATE LIMITING ─────────────────────────────────────────────────────────────
def check_nuke_ratelimit(device_id: str):
    """Raise HTTPException if device is locked out. Returns current fail count."""
    with db_conn() as conn:
        row = conn.execute(
            "SELECT fail_count, locked_until FROM nuke_fails WHERE device_id=?", (device_id,)
        ).fetchone()
    if not row:
        return 0
    if time.time() < row["locked_until"]:
        remaining = int(row["locked_until"] - time.time())
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Locked for {remaining}s.",
        )
    return row["fail_count"]

def record_nuke_fail(device_id: str):
    """Increment fail counter. Lock out after NUKE_MAX_FAILS."""
    with db_conn() as conn:
        row = conn.execute(
            "SELECT fail_count FROM nuke_fails WHERE device_id=?", (device_id,)
        ).fetchone()
        new_count = (row["fail_count"] + 1) if row else 1
        locked_until = (time.time() + NUKE_LOCKOUT_SECS) if new_count >= NUKE_MAX_FAILS else 0.0
        conn.execute(
            "INSERT INTO nuke_fails(device_id, fail_count, locked_until) VALUES(?,?,?) "
            "ON CONFLICT(device_id) DO UPDATE SET fail_count=excluded.fail_count, locked_until=excluded.locked_until",
            (device_id, new_count, locked_until),
        )

def reset_nuke_fails(device_id: str):
    """Clear fail counter after successful nuke step."""
    with db_conn() as conn:
        conn.execute("DELETE FROM nuke_fails WHERE device_id=?", (device_id,))

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
        enriched = {
            **payload,
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "device_id": device_id,
        }
        db_upsert_device(device_id, enriched)

    elif msg_type == "location":
        db_append_location(device_id, {
            **payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    elif msg_type == "ack":
        cmd    = payload.get("command")
        status = payload.get("status")
        if cmd == "wipe_complete":
            state = db_get_nuke_state(device_id)
            if state:
                state["executed"] = True
                db_upsert_nuke_state(device_id, state)
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
    started_at = time.time()
    while True:
        await asyncio.sleep(5)
        state = db_get_nuke_state(device_id)
        if not state:
            return
        if state.get("aborted"):
            print(f"[NUKE] Aborted for {device_id}")
            return
        elapsed = time.time() - state["started_at"]
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
            state["executed"] = True
            db_upsert_nuke_state(device_id, state)
            await ntfy_alert(
                title=f"WIPE EXECUTED -- {device_id}",
                message=f"Guardian wiped {device_id} at {datetime.now(timezone.utc).isoformat()}",
                priority="urgent", tags="fire,skull",
            )
            return

# ─── FASTAPI ────────────────────────────────────────────────────────────────────
app = FastAPI(title="Guardian Relay v2.1", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.on_event("startup")
async def startup():
    init_db()
    db_purge_stale_nuke_states()
    mqtt_connect()
    # Resume any nuke countdowns that were active before restart
    _resume_nuke_countdowns()

def _resume_nuke_countdowns():
    """On startup, restart countdown tasks for any nukes that were active when server was killed."""
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT device_id, started_at, countdown_secs FROM nuke_state "
            "WHERE active=1 AND aborted=0 AND executed=0"
        ).fetchall()
    for row in rows:
        elapsed  = time.time() - row["started_at"]
        remaining = row["countdown_secs"] - elapsed
        if remaining > 0:
            print(f"[NUKE] Resuming countdown for {row['device_id']} — {remaining:.0f}s remaining")
            asyncio.get_event_loop().create_task(nuke_countdown_task(row["device_id"]))
        else:
            # Countdown already expired — fire immediately
            print(f"[NUKE] Countdown expired during downtime for {row['device_id']} — executing")
            asyncio.get_event_loop().create_task(nuke_countdown_task(row["device_id"]))

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
    return {"status": "ok", "version": "2.1.0", "time": datetime.now(timezone.utc).isoformat()}

@app.get("/devices", dependencies=[Depends(require_auth)])
async def get_devices():
    return {"devices": db_get_all_devices()}

@app.get("/devices/{device_id}/location", dependencies=[Depends(require_auth)])
async def get_location(device_id: str):
    return {"locations": db_get_locations(device_id)}

@app.post("/command", dependencies=[Depends(require_auth)])
async def send_command(req: CommandRequest):
    payload = {
        "command": req.command, "params": req.params,
        "issued_at": time.time(), "ttl": COMMAND_TTL, "id": str(uuid.uuid4()),
    }
    mqtt_client.publish(f"guardian/{req.device_id}/command", json.dumps(payload), qos=1)
    return {"status": "sent", "command_id": payload["id"]}

# ─── NUKE (3-STEP) ──────────────────────────────────────────────────────────────
@app.post("/nuke/init", dependencies=[Depends(require_auth)])
async def nuke_init(req: NukeInitRequest):
    device_id = req.device_id

    # Rate limit check before any validation
    check_nuke_ratelimit(device_id)

    if req.step == 1:
        if req.value != NUKE_PASSPHRASE:
            record_nuke_fail(device_id)
            raise HTTPException(status_code=403, detail="Invalid nuke passphrase")
        reset_nuke_fails(device_id)
        db_upsert_nuke_session(device_id, 1, time.time() + 120)
        return {"status": "step_1_ok", "next": "Type NUKE to confirm"}

    elif req.step == 2:
        session = db_get_nuke_session(device_id)
        if not session or session["step_completed"] < 1 or time.time() > session["expires_at"]:
            record_nuke_fail(device_id)
            raise HTTPException(status_code=403, detail="Session expired or invalid")
        if req.value.strip().upper() != "NUKE":
            record_nuke_fail(device_id)
            raise HTTPException(status_code=403, detail="Type exactly: NUKE")
        reset_nuke_fails(device_id)
        db_upsert_nuke_session(device_id, 2, session["expires_at"])
        return {"status": "step_2_ok", "next": "Enter your TOTP code"}

    elif req.step == 3:
        session = db_get_nuke_session(device_id)
        if not session or session["step_completed"] < 2 or time.time() > session["expires_at"]:
            record_nuke_fail(device_id)
            raise HTTPException(status_code=403, detail="Session expired or invalid")
        if not verify_totp(TOTP_SECRET, req.value):
            record_nuke_fail(device_id)
            raise HTTPException(status_code=403, detail="Invalid TOTP")
        reset_nuke_fails(device_id)
        db_delete_nuke_session(device_id)
        state = {
            "active":            True,
            "started_at":        time.time(),
            "aborted":           False,
            "executed":          False,
            "countdown_seconds": NUKE_COUNTDOWN,
        }
        db_upsert_nuke_state(device_id, state)
        asyncio.create_task(nuke_countdown_task(device_id))
        await ntfy_alert(
            title=f"NUKE ARMED -- {device_id}",
            message=f"10-minute countdown started for {device_id}. Abort from dashboard if needed.",
            priority="urgent", tags="rotating_light,bomb",
        )
        return {
            "status": "nuke_armed",
            "countdown_seconds": NUKE_COUNTDOWN,
            "message": "Wipe will execute in 10 minutes. Abort from dashboard.",
        }

    raise HTTPException(status_code=400, detail="Invalid step")

@app.post("/nuke/abort", dependencies=[Depends(require_auth)])
async def nuke_abort(req: NukeAbortRequest):
    state = db_get_nuke_state(req.device_id)
    if not state or not state.get("active"):
        raise HTTPException(status_code=404, detail="No active nuke for this device")
    if state.get("executed"):
        raise HTTPException(status_code=409, detail="Wipe already executed")
    state["aborted"] = True
    db_upsert_nuke_state(req.device_id, state)
    await ntfy_alert(
        title=f"NUKE ABORTED -- {req.device_id}",
        message=f"Wipe countdown aborted for {req.device_id}.",
        priority="default", tags="white_check_mark",
    )
    return {"status": "aborted"}

@app.get("/nuke/status/{device_id}", dependencies=[Depends(require_auth)])
async def nuke_status(device_id: str):
    state = db_get_nuke_state(device_id)
    if not state:
        return {"active": False}
    elapsed   = time.time() - state["started_at"]
    remaining = max(0, state["countdown_seconds"] - elapsed)
    return {
        "active":            state["active"],
        "aborted":           state["aborted"],
        "executed":          state.get("executed", False),
        "remaining_seconds": int(remaining),
        "countdown_seconds": state["countdown_seconds"],
    }
