#!/usr/bin/env python3
"""
Guardian Relay Server v2.6.0
FastAPI + MQTT relay with nuke system, TOTP auth, ntfy.sh alerts, command TTL

Changes in v2.6.0:
- MQTT TLS: set MQTT_TLS=true to connect to the broker over TLS.
  MQTT_CA_CERT, MQTT_CLIENT_CERT, MQTT_CLIENT_KEY control the cert paths.
  MQTT_PORT defaults to 8883 when TLS is enabled (override with MQTT_PORT).
  Mutual TLS (client certs) is optional — set the cert+key vars only if your
  Mosquitto config requires client certificate auth.
- Audit log: every auth event (login, logout, failed attempt, lockout),
  nuke arm/abort/execute, and command sent is written to the audit_log table.
  GET /audit returns the last 200 entries (requires auth). Events include
  timestamp, event type, actor IP, device_id (where relevant), and detail.
- GET /ping: unauthenticated liveness probe for uptime monitors (UptimeRobot,
  BetterStack, etc.). Returns {"ok": true} only — no version, no metadata.

Changes in v2.5.0:
- Signed MQTT commands (HMAC-SHA256) and session token auth.

Changes in v2.4.0:
- Auth rate-limiting per IP, /health and /agents/latest locked down.

Changes in v2.3.0:
- Dead-man's switch watchdog, per-device command log, agent version endpoint.

Changes in v2.2.0:
- TOTP replay protection, lifespan migration, device_id injection guard,
  CORS hardening.
"""
import asyncio
import json
import os
import re
import time
import hashlib
import hmac
import base64
import struct
import uuid
import sqlite3
import contextlib
import ssl
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
import paho.mqtt.client as mqtt
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import httpx

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
MQTT_BROKER      = os.getenv("MQTT_BROKER",      "localhost")
MQTT_TLS         = os.getenv("MQTT_TLS",         "false").lower() == "true"
MQTT_PORT        = int(os.getenv("MQTT_PORT",     8883 if MQTT_TLS else 1883))
MQTT_USER        = os.getenv("MQTT_USER",         "guardian")
MQTT_PASS        = os.getenv("MQTT_PASS",         "changeme")
# TLS cert paths (only needed when MQTT_TLS=true)
MQTT_CA_CERT     = os.getenv("MQTT_CA_CERT",      "/etc/guardian/certs/ca.crt")
MQTT_CLIENT_CERT = os.getenv("MQTT_CLIENT_CERT",  "")  # optional: mutual TLS
MQTT_CLIENT_KEY  = os.getenv("MQTT_CLIENT_KEY",   "")  # optional: mutual TLS

TOTP_SECRET      = os.getenv("TOTP_SECRET",      "YOUR_BASE32_SECRET_HERE")
MASTER_PASSWORD  = os.getenv("MASTER_PASSWORD",  "changeme")
NUKE_PASSPHRASE  = os.getenv("NUKE_PASSPHRASE",  "changeme-nuke-phrase")
NTFY_TOPIC       = os.getenv("NTFY_TOPIC",       "guardian-changeme")
NTFY_URL         = f"https://ntfy.sh/{NTFY_TOPIC}"
COMMAND_TTL      = int(os.getenv("COMMAND_TTL",    300))
NUKE_COUNTDOWN   = int(os.getenv("NUKE_COUNTDOWN", 600))
NUKE_STATE_TTL   = int(os.getenv("NUKE_STATE_TTL", 3600))
DB_PATH          = os.getenv("GUARDIAN_DB",       "guardian.db")

# HMAC signing key for MQTT commands.
# Set this env var and copy the same value into every agent.
COMMAND_SIGNING_KEY = os.getenv("COMMAND_SIGNING_KEY", "")
if not COMMAND_SIGNING_KEY:
    import secrets as _secrets
    COMMAND_SIGNING_KEY = _secrets.token_hex(32)
    print("[WARN] COMMAND_SIGNING_KEY not set — generated a random key. "
          "Agents cannot verify commands until you set a stable shared key in .env")

SESSION_TTL_SECS  = int(os.getenv("SESSION_TTL_SECS",  1800))
NUKE_MAX_FAILS    = int(os.getenv("NUKE_MAX_FAILS",    5))
NUKE_LOCKOUT_SECS = int(os.getenv("NUKE_LOCKOUT_SECS", 300))

DASHBOARD_ORIGIN = os.getenv("DASHBOARD_ORIGIN", "")
CORS_ORIGINS     = [DASHBOARD_ORIGIN] if DASHBOARD_ORIGIN else []

WATCHDOG_TIMEOUT_SECS = int(os.getenv("WATCHDOG_TIMEOUT_SECS", 300))
WATCHDOG_INTERVAL     = int(os.getenv("WATCHDOG_INTERVAL",     60))

AUTH_MAX_FAILS    = int(os.getenv("AUTH_MAX_FAILS",    10))
AUTH_WINDOW_SECS  = int(os.getenv("AUTH_WINDOW_SECS",  60))
AUTH_LOCKOUT_SECS = int(os.getenv("AUTH_LOCKOUT_SECS", 300))

AGENT_VERSIONS = {
    "windows": "2.2.1",
    "mac":     "2.2.0",
    "android": "2.2.0",
}

# ---------------------------------------------------------------------------
# INPUT VALIDATION
# ---------------------------------------------------------------------------
_SAFE_DEVICE_ID = re.compile(r'^[A-Za-z0-9_-]{1,64}$')

def _validate_device_id(device_id: str) -> str:
    if not _SAFE_DEVICE_ID.match(device_id):
        raise HTTPException(
            status_code=400,
            detail="device_id must be 1-64 characters: letters, digits, hyphens, underscores only",
        )
    return device_id

# ---------------------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS totp_used (
                token_hash TEXT NOT NULL,
                window_ts  INTEGER NOT NULL,
                used_at    REAL NOT NULL,
                PRIMARY KEY (token_hash, window_ts)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS command_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                command_id  TEXT NOT NULL UNIQUE,
                device_id   TEXT NOT NULL,
                command     TEXT NOT NULL,
                params      TEXT NOT NULL DEFAULT '{}',
                status      TEXT NOT NULL DEFAULT 'sent',
                issued_at   REAL NOT NULL,
                ack_at      REAL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cmdlog_device ON command_log(device_id)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS watchdog_alerts (
                device_id   TEXT PRIMARY KEY,
                alerted_at  REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_fails (
                ip           TEXT PRIMARY KEY,
                fail_count   INTEGER NOT NULL DEFAULT 0,
                window_start REAL NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_fails(ip)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
        # Audit log — append-only record of security-relevant events
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         REAL NOT NULL,
                event      TEXT NOT NULL,
                actor_ip   TEXT,
                device_id  TEXT,
                detail     TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event)")

# ---------------------------------------------------------------------------
# DB HELPERS — audit log
# ---------------------------------------------------------------------------
def audit(event: str, actor_ip: str = None, device_id: str = None, detail: str = None):
    """
    Write an audit entry. Call this for every security-relevant event.
    Events:
      auth.login          — successful login (session token issued)
      auth.logout         — explicit logout
      auth.fail           — failed auth attempt
      auth.lockout        — IP locked out after too many failures
      command.sent        — command dispatched to a device
      nuke.armed          — nuke countdown started
      nuke.aborted        — nuke countdown aborted
      nuke.executed       — wipe command sent after countdown
      watchdog.alert      — device silence alert fired
    """
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO audit_log(ts, event, actor_ip, device_id, detail) VALUES(?,?,?,?,?)",
            (time.time(), event, actor_ip, device_id, detail),
        )
        # Keep only last 1000 entries to bound DB growth
        conn.execute(
            "DELETE FROM audit_log WHERE id NOT IN "
            "(SELECT id FROM audit_log ORDER BY id DESC LIMIT 1000)"
        )

def db_get_audit_log(limit: int = 200) -> list:
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT ts, event, actor_ip, device_id, detail FROM audit_log "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            "ts":        r["ts"],
            "time":      datetime.fromtimestamp(r["ts"], tz=timezone.utc).isoformat(),
            "event":     r["event"],
            "actor_ip":  r["actor_ip"],
            "device_id": r["device_id"],
            "detail":    r["detail"],
        }
        for r in rows
    ]

# ---------------------------------------------------------------------------
# DB HELPERS — devices / locations
# ---------------------------------------------------------------------------
def db_upsert_device(device_id: str, payload: dict):
    now = datetime.now(timezone.utc).isoformat()
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO device_status(device_id, payload, last_seen) VALUES(?,?,?) "
            "ON CONFLICT(device_id) DO UPDATE SET payload=excluded.payload, last_seen=excluded.last_seen",
            (device_id, json.dumps(payload), now),
        )
        conn.execute("DELETE FROM watchdog_alerts WHERE device_id=?", (device_id,))

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

# ---------------------------------------------------------------------------
# DB HELPERS — command log
# ---------------------------------------------------------------------------
def db_log_command(command_id: str, device_id: str, command: str,
                   params: dict, issued_at: float):
    with db_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO command_log"
            "(command_id, device_id, command, params, status, issued_at)"
            " VALUES(?,?,?,?,?,?)",
            (command_id, device_id, command, json.dumps(params), "sent", issued_at),
        )
        conn.execute(
            "DELETE FROM command_log WHERE device_id=? AND id NOT IN "
            "(SELECT id FROM command_log WHERE device_id=? ORDER BY id DESC LIMIT 200)",
            (device_id, device_id),
        )

def db_ack_command(device_id: str, command: str, status: str):
    with db_conn() as conn:
        conn.execute(
            "UPDATE command_log SET status=?, ack_at=? "
            "WHERE device_id=? AND command=? AND status='sent' "
            "ORDER BY issued_at DESC LIMIT 1",
            (status, time.time(), device_id, command),
        )

def db_get_command_log(device_id: str) -> list:
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT command_id, command, params, status, issued_at, ack_at "
            "FROM command_log WHERE device_id=? ORDER BY issued_at DESC LIMIT 100",
            (device_id,),
        ).fetchall()
    return [
        {
            "command_id": r["command_id"],
            "command":    r["command"],
            "params":     json.loads(r["params"]),
            "status":     r["status"],
            "issued_at":  r["issued_at"],
            "ack_at":     r["ack_at"],
        }
        for r in rows
    ]

# ---------------------------------------------------------------------------
# DB HELPERS — session tokens
# ---------------------------------------------------------------------------
def db_create_session() -> str:
    token      = str(uuid.uuid4())
    now        = time.time()
    expires_at = now + SESSION_TTL_SECS
    with db_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute(
            "INSERT INTO sessions(token, created_at, expires_at) VALUES(?,?,?)",
            (token, now, expires_at),
        )
    return token

def db_validate_session(token: str) -> bool:
    now = time.time()
    with db_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM sessions WHERE token=? AND expires_at > ?",
            (token, now),
        ).fetchone()
    return row is not None

def db_delete_session(token: str):
    with db_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))

# ---------------------------------------------------------------------------
# DB HELPERS — nuke
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# RATE LIMITING — nuke
# ---------------------------------------------------------------------------
def check_nuke_ratelimit(device_id: str):
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
    with db_conn() as conn:
        row = conn.execute(
            "SELECT fail_count FROM nuke_fails WHERE device_id=?", (device_id,)
        ).fetchone()
        new_count    = (row["fail_count"] + 1) if row else 1
        locked_until = (time.time() + NUKE_LOCKOUT_SECS) if new_count >= NUKE_MAX_FAILS else 0.0
        conn.execute(
            "INSERT INTO nuke_fails(device_id, fail_count, locked_until) VALUES(?,?,?) "
            "ON CONFLICT(device_id) DO UPDATE SET fail_count=excluded.fail_count, locked_until=excluded.locked_until",
            (device_id, new_count, locked_until),
        )

def reset_nuke_fails(device_id: str):
    with db_conn() as conn:
        conn.execute("DELETE FROM nuke_fails WHERE device_id=?", (device_id,))

# ---------------------------------------------------------------------------
# RATE LIMITING — global auth (per IP)
# ---------------------------------------------------------------------------
def _get_client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def check_auth_ratelimit(ip: str):
    with db_conn() as conn:
        row = conn.execute(
            "SELECT fail_count, window_start, locked_until FROM auth_fails WHERE ip=?", (ip,)
        ).fetchone()
    if not row:
        return
    now = time.time()
    if now < row["locked_until"]:
        remaining = int(row["locked_until"] - now)
        audit("auth.lockout", actor_ip=ip, detail=f"Locked for {remaining}s")
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed auth attempts. Try again in {remaining}s.",
        )

def record_auth_fail(ip: str):
    now = time.time()
    with db_conn() as conn:
        row = conn.execute(
            "SELECT fail_count, window_start, locked_until FROM auth_fails WHERE ip=?", (ip,)
        ).fetchone()
        if row:
            window_start = row["window_start"]
            if now - window_start > AUTH_WINDOW_SECS:
                new_count    = 1
                window_start = now
            else:
                new_count = row["fail_count"] + 1
        else:
            new_count    = 1
            window_start = now
        locked_until = (now + AUTH_LOCKOUT_SECS) if new_count >= AUTH_MAX_FAILS else 0.0
        conn.execute(
            "INSERT INTO auth_fails(ip, fail_count, window_start, locked_until) VALUES(?,?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET "
            "fail_count=excluded.fail_count, window_start=excluded.window_start, locked_until=excluded.locked_until",
            (ip, new_count, window_start, locked_until),
        )
    audit("auth.fail", actor_ip=ip, detail=f"fail #{new_count}")

def reset_auth_fails(ip: str):
    with db_conn() as conn:
        conn.execute("DELETE FROM auth_fails WHERE ip=?", (ip,))

# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------
def verify_totp(secret: str, token: str, window: int = 1) -> bool:
    try:
        key = base64.b32decode(secret.upper())
    except Exception:
        return False
    ts        = int(time.time()) // 30
    token_str = str(token).zfill(6)
    for offset in range(-window, window + 1):
        t    = struct.pack(">Q", ts + offset)
        h    = hmac.new(key, t, hashlib.sha1).digest()
        o    = h[-1] & 0x0F
        code = struct.unpack(">I", h[o:o+4])[0] & 0x7FFFFFFF
        if str(code % 1_000_000).zfill(6) == token_str:
            window_ts  = ts + offset
            entry_hash = hashlib.sha256(f"{token_str}:{window_ts}".encode()).hexdigest()
            with db_conn() as conn:
                existing = conn.execute(
                    "SELECT 1 FROM totp_used WHERE token_hash=? AND window_ts=?",
                    (entry_hash, window_ts),
                ).fetchone()
                if existing:
                    return False
                conn.execute(
                    "INSERT INTO totp_used(token_hash, window_ts, used_at) VALUES(?,?,?)",
                    (entry_hash, window_ts, time.time()),
                )
                conn.execute(
                    "DELETE FROM totp_used WHERE used_at < ?",
                    (time.time() - 120,),
                )
            return True
    return False

# ---------------------------------------------------------------------------
# COMMAND SIGNING (HMAC-SHA256)
# ---------------------------------------------------------------------------
def sign_command(command_id: str, command: str, issued_at: float) -> str:
    msg = f"{command_id}:{command}:{issued_at}".encode()
    return hmac.new(
        COMMAND_SIGNING_KEY.encode(),
        msg,
        hashlib.sha256,
    ).hexdigest()

def verify_command_signature(command_id: str, command: str,
                              issued_at: float, signature: str) -> bool:
    expected = sign_command(command_id, command, issued_at)
    return hmac.compare_digest(expected, signature)

# ---------------------------------------------------------------------------
# AUTH
# ---------------------------------------------------------------------------
security = HTTPBearer()

def _verify_legacy_token(token: str) -> bool:
    parts = token.split(":")
    if len(parts) != 2:
        return False
    password, totp_code = parts
    if password != MASTER_PASSWORD:
        return False
    if not verify_totp(TOTP_SECRET, totp_code):
        return False
    return True

def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    ip = _get_client_ip(request)
    check_auth_ratelimit(ip)

    token = credentials.credentials

    # Session token path (UUID)
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', token):
        if db_validate_session(token):
            reset_auth_fails(ip)
            return True
        record_auth_fail(ip)
        raise HTTPException(status_code=401, detail="Authentication failed")

    # Legacy password:totp path
    if _verify_legacy_token(token):
        reset_auth_fails(ip)
        return True

    record_auth_fail(ip)
    raise HTTPException(status_code=401, detail="Authentication failed")

# ---------------------------------------------------------------------------
# MQTT
# ---------------------------------------------------------------------------
mqtt_client = mqtt.Client(client_id="relay-server", clean_session=False)
mqtt_client.username_pw_set(MQTT_USER, MQTT_PASS)

def _configure_mqtt_tls():
    """
    Configure TLS on the MQTT client when MQTT_TLS=true.

    Mosquitto server setup (on VPS):
      1. Generate CA + server cert:
           openssl req -new -x509 -days 3650 -keyout ca.key -out ca.crt -subj "/CN=GuardianCA"
           openssl req -new -keyout server.key -out server.csr -subj "/CN=localhost"
           openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
                        -out server.crt -days 3650

      2. Add to /etc/mosquitto/mosquitto.conf:
           listener 8883
           cafile   /etc/guardian/certs/ca.crt
           certfile /etc/guardian/certs/server.crt
           keyfile  /etc/guardian/certs/server.key
           # Optional mutual TLS (require client certs):
           # require_certificate true

      3. Restart: sudo systemctl restart mosquitto

    Relay server .env:
           MQTT_TLS=true
           MQTT_PORT=8883
           MQTT_CA_CERT=/etc/guardian/certs/ca.crt
           # For mutual TLS only:
           # MQTT_CLIENT_CERT=/etc/guardian/certs/client.crt
           # MQTT_CLIENT_KEY=/etc/guardian/certs/client.key

    Agents: set MQTT_TLS=true + MQTT_CA_CERT path in each agent's .env.
    """
    certfile = MQTT_CLIENT_CERT if MQTT_CLIENT_CERT else None
    keyfile  = MQTT_CLIENT_KEY  if MQTT_CLIENT_KEY  else None
    mqtt_client.tls_set(
        ca_certs=MQTT_CA_CERT,
        certfile=certfile,
        keyfile=keyfile,
        tls_version=ssl.PROTOCOL_TLS_CLIENT,
    )
    # Enforce hostname verification
    mqtt_client.tls_insecure_set(False)
    print(f"[MQTT] TLS enabled — CA: {MQTT_CA_CERT}, mutual: {bool(certfile)}")

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

    if not _SAFE_DEVICE_ID.match(device_id):
        print(f"[MQTT] Dropping message from unsafe device_id: {device_id!r}")
        return

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
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        })

    elif msg_type == "ack":
        cmd    = payload.get("command", "")
        status = payload.get("status", "ack")
        db_ack_command(device_id, cmd, status)
        if cmd == "wipe_complete":
            state = db_get_nuke_state(device_id)
            if state and not state.get("aborted"):
                state["executed"] = True
                db_upsert_nuke_state(device_id, state)
        print(f"[ACK] {device_id} -> {cmd}: {status}")

mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message

def mqtt_connect():
    if MQTT_TLS:
        _configure_mqtt_tls()
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    mqtt_client.loop_start()
    print(f"[MQTT] Connecting to {MQTT_BROKER}:{MQTT_PORT} (TLS={'on' if MQTT_TLS else 'off'})")

def _publish_command(device_id: str, command: str, params: dict,
                     command_id: str, issued_at: float, ttl: int):
    signature = sign_command(command_id, command, issued_at)
    payload   = {
        "command":   command,
        "params":    params,
        "issued_at": issued_at,
        "ttl":       ttl,
        "id":        command_id,
        "sig":       signature,
    }
    mqtt_client.publish(f"guardian/{device_id}/command", json.dumps(payload), qos=1)

# ---------------------------------------------------------------------------
# NTFY
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# DEAD-MAN'S SWITCH WATCHDOG
# ---------------------------------------------------------------------------
async def watchdog_task():
    await asyncio.sleep(WATCHDOG_INTERVAL)
    while True:
        try:
            devices = db_get_all_devices()
            now     = time.time()
            for d in devices:
                device_id = d.get("device_id", "")
                if not device_id:
                    continue
                last_seen_str = d.get("last_seen", "")
                if not last_seen_str:
                    continue
                try:
                    last_seen_dt = datetime.fromisoformat(last_seen_str)
                    last_seen_ts = last_seen_dt.timestamp()
                except Exception:
                    continue
                silent_secs = now - last_seen_ts
                if silent_secs < WATCHDOG_TIMEOUT_SECS:
                    continue
                with db_conn() as conn:
                    already = conn.execute(
                        "SELECT 1 FROM watchdog_alerts WHERE device_id=?", (device_id,)
                    ).fetchone()
                    if already:
                        continue
                    conn.execute(
                        "INSERT OR REPLACE INTO watchdog_alerts(device_id, alerted_at) VALUES(?,?)",
                        (device_id, now),
                    )
                platform = d.get("platform", "unknown")
                print(f"[WATCHDOG] {device_id} silent for {int(silent_secs)}s — alerting")
                audit("watchdog.alert", device_id=device_id,
                      detail=f"Silent {int(silent_secs)}s, platform={platform}")
                await ntfy_alert(
                    title=f"DEVICE SILENT — {device_id}",
                    message=(
                        f"{device_id} ({platform}) has not sent a heartbeat for "
                        f"{int(silent_secs // 60)} min {int(silent_secs % 60)}s.\n"
                        f"Last seen: {last_seen_str}\n"
                        "Possible theft or agent crash. Check dashboard."
                    ),
                    priority="high",
                    tags="rotating_light,no_mobile_phones",
                )
        except Exception as e:
            print(f"[WATCHDOG] Error: {e}")
        await asyncio.sleep(WATCHDOG_INTERVAL)

# ---------------------------------------------------------------------------
# NUKE COUNTDOWN TASK
# ---------------------------------------------------------------------------
async def nuke_countdown_task(device_id: str):
    while True:
        await asyncio.sleep(5)
        state = db_get_nuke_state(device_id)
        if not state:
            return
        if state.get("aborted"):
            print(f"[NUKE] Aborted for {device_id}")
            return
        elapsed = time.time() - state["started_at"]
        if elapsed >= state["countdown_seconds"]:
            print(f"[NUKE] Executing wipe for {device_id}")
            burst_id = str(uuid.uuid4())
            burst_ts = time.time()
            _publish_command(device_id, "location_burst", {}, burst_id, burst_ts, 60)
            await asyncio.sleep(3)
            wipe_id = str(uuid.uuid4())
            wipe_ts = time.time()
            _publish_command(device_id, "wipe", {}, wipe_id, wipe_ts, COMMAND_TTL)
            state["executed"] = True
            db_upsert_nuke_state(device_id, state)
            audit("nuke.executed", device_id=device_id)
            await ntfy_alert(
                title=f"WIPE EXECUTED — {device_id}",
                message=f"Guardian wiped {device_id} at {datetime.now(timezone.utc).isoformat()}",
                priority="urgent", tags="fire,skull",
            )
            return

# ---------------------------------------------------------------------------
# LIFESPAN
# ---------------------------------------------------------------------------
def _resume_nuke_countdowns(loop: asyncio.AbstractEventLoop):
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT device_id, started_at, countdown_secs FROM nuke_state "
            "WHERE active=1 AND aborted=0 AND executed=0"
        ).fetchall()
    for row in rows:
        elapsed   = time.time() - row["started_at"]
        remaining = row["countdown_secs"] - elapsed
        if remaining > 0:
            print(f"[NUKE] Resuming countdown for {row['device_id']} — {remaining:.0f}s remaining")
        else:
            print(f"[NUKE] Countdown expired during downtime for {row['device_id']} — executing immediately")
        loop.create_task(nuke_countdown_task(row["device_id"]))

@asynccontextmanager
async def lifespan(app: FastAPI):
    if not DASHBOARD_ORIGIN:
        print("[WARN] DASHBOARD_ORIGIN is not set — CORS will block all browser requests.")
    init_db()
    db_purge_stale_nuke_states()
    mqtt_connect()
    loop = asyncio.get_running_loop()
    _resume_nuke_countdowns(loop)
    loop.create_task(watchdog_task())
    yield
    mqtt_client.loop_stop()
    mqtt_client.disconnect()
    print("[MQTT] Disconnected cleanly on shutdown")

# ---------------------------------------------------------------------------
# FASTAPI
# ---------------------------------------------------------------------------
app = FastAPI(title="Guardian Relay", version="2.6.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# ---------------------------------------------------------------------------
# MODELS
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    password: str
    totp:     str

class LogoutRequest(BaseModel):
    token: str

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

# ---------------------------------------------------------------------------
# ROUTES — public (no auth)
# ---------------------------------------------------------------------------
@app.get("/ping")
async def ping():
    """
    Unauthenticated liveness probe for uptime monitors.
    Point UptimeRobot / BetterStack at GET /ping.
    Returns {"ok": true} only — no version, no metadata.
    """
    return {"ok": True}

# ---------------------------------------------------------------------------
# ROUTES — auth
# ---------------------------------------------------------------------------
@app.post("/auth/login")
async def login(req: LoginRequest, request: Request):
    ip = _get_client_ip(request)
    check_auth_ratelimit(ip)

    if req.password != MASTER_PASSWORD:
        record_auth_fail(ip)
        raise HTTPException(status_code=401, detail="Authentication failed")

    if not verify_totp(TOTP_SECRET, req.totp):
        record_auth_fail(ip)
        raise HTTPException(status_code=401, detail="Authentication failed")

    reset_auth_fails(ip)
    token = db_create_session()
    audit("auth.login", actor_ip=ip, detail=f"Session issued, expires in {SESSION_TTL_SECS}s")
    return {"token": token, "expires_in": SESSION_TTL_SECS}

@app.post("/auth/logout")
async def logout(req: LogoutRequest, request: Request, _: bool = Depends(require_auth)):
    ip = _get_client_ip(request)
    db_delete_session(req.token)
    audit("auth.logout", actor_ip=ip)
    return {"status": "logged_out"}

# ---------------------------------------------------------------------------
# ROUTES — general
# ---------------------------------------------------------------------------
@app.get("/health", dependencies=[Depends(require_auth)])
async def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}

@app.get("/agents/latest", dependencies=[Depends(require_auth)])
async def agents_latest():
    return {"versions": AGENT_VERSIONS}

@app.get("/devices", dependencies=[Depends(require_auth)])
async def get_devices():
    return {"devices": db_get_all_devices()}

@app.get("/devices/{device_id}/location", dependencies=[Depends(require_auth)])
async def get_location(device_id: str):
    _validate_device_id(device_id)
    return {"locations": db_get_locations(device_id)}

@app.get("/devices/{device_id}/log", dependencies=[Depends(require_auth)])
async def get_device_log(device_id: str):
    _validate_device_id(device_id)
    return {"log": db_get_command_log(device_id)}

@app.post("/command", dependencies=[Depends(require_auth)])
async def send_command(req: CommandRequest, request: Request):
    _validate_device_id(req.device_id)
    command_id = str(uuid.uuid4())
    issued_at  = time.time()
    _publish_command(req.device_id, req.command, req.params or {},
                     command_id, issued_at, COMMAND_TTL)
    db_log_command(command_id, req.device_id, req.command, req.params or {}, issued_at)
    ip = _get_client_ip(request)
    audit("command.sent", actor_ip=ip, device_id=req.device_id,
          detail=f"cmd={req.command} id={command_id}")
    return {"status": "sent", "command_id": command_id}

@app.get("/audit", dependencies=[Depends(require_auth)])
async def get_audit_log():
    """
    Return the last 200 audit log entries, newest first.
    Covers: logins, logouts, auth failures, lockouts,
            commands sent, nuke events, watchdog alerts.
    """
    return {"audit": db_get_audit_log(200)}

# ---------------------------------------------------------------------------
# ROUTES — nuke (3-step)
# ---------------------------------------------------------------------------
@app.post("/nuke/init", dependencies=[Depends(require_auth)])
async def nuke_init(req: NukeInitRequest, request: Request):
    device_id = req.device_id
    _validate_device_id(device_id)
    check_nuke_ratelimit(device_id)
    ip = _get_client_ip(request)

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
        audit("nuke.armed", actor_ip=ip, device_id=device_id,
              detail=f"countdown={NUKE_COUNTDOWN}s")
        await ntfy_alert(
            title=f"NUKE ARMED — {device_id}",
            message=f"10-minute countdown started for {device_id}. Abort from dashboard if needed.",
            priority="urgent", tags="rotating_light,bomb",
        )
        return {
            "status":            "nuke_armed",
            "countdown_seconds": NUKE_COUNTDOWN,
            "message":           "Wipe will execute in 10 minutes. Abort from dashboard.",
        }

    raise HTTPException(status_code=400, detail="Invalid step")

@app.post("/nuke/abort", dependencies=[Depends(require_auth)])
async def nuke_abort(req: NukeAbortRequest, request: Request):
    _validate_device_id(req.device_id)
    state = db_get_nuke_state(req.device_id)
    if not state or not state.get("active"):
        raise HTTPException(status_code=404, detail="No active nuke for this device")
    if state.get("executed"):
        raise HTTPException(status_code=409, detail="Wipe already executed — cannot abort")
    if state.get("aborted"):
        return {"status": "already_aborted"}
    state["aborted"] = True
    db_upsert_nuke_state(req.device_id, state)
    ip = _get_client_ip(request)
    audit("nuke.aborted", actor_ip=ip, device_id=req.device_id)
    await ntfy_alert(
        title=f"NUKE ABORTED — {req.device_id}",
        message=f"Wipe countdown aborted for {req.device_id}.",
        priority="default", tags="white_check_mark",
    )
    return {"status": "aborted"}

@app.get("/nuke/status/{device_id}", dependencies=[Depends(require_auth)])
async def nuke_status(device_id: str):
    _validate_device_id(device_id)
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
