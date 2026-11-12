"""Version 1 Guardian signed-command envelope helpers.

The wire format is deliberately strict so Python and Android clients can
canonicalize the same JSON before calculating HMAC-SHA256.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
from typing import Any

PROTOCOL_VERSION = 1
MAX_COMMAND_TTL_SECONDS = 3600
MAX_CLOCK_SKEW_SECONDS = 60
REPLAY_RETENTION_SECONDS = 7 * 24 * 60 * 60
MAX_CANONICAL_BYTES = 64 * 1024

SIGNED_FIELDS = (
    "version",
    "id",
    "device_id",
    "command",
    "params",
    "issued_at",
    "ttl",
)
ENVELOPE_FIELDS = frozenset((*SIGNED_FIELDS, "sig"))
ALLOWED_COMMANDS = frozenset({
    "ping", "status", "location", "location_burst",
    "lock", "backup", "abort_wipe", "wipe",
})
_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_SIG_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_PARAM_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_MAX_SAFE_INTEGER = 9007199254740991


class CommandEnvelopeError(ValueError):
    """Raised when a command cannot be represented canonically."""


def _validate_json_value(value: Any, depth: int = 0) -> None:
    if depth > 16:
        raise CommandEnvelopeError("JSON nesting exceeds protocol limit")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise CommandEnvelopeError("integer is outside the interoperable range")
        return
    if isinstance(value, float):
        raise CommandEnvelopeError("floating-point values are not supported in protocol v1")
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not _PARAM_KEY_RE.fullmatch(key):
                raise CommandEnvelopeError("object keys must be short ASCII identifiers")
            _validate_json_value(item, depth + 1)
        return
    raise CommandEnvelopeError(f"unsupported JSON value type: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return the protocol's UTF-8 canonical JSON representation."""
    _validate_json_value(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CommandEnvelopeError("value cannot be canonically encoded") from exc
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise CommandEnvelopeError("canonical command exceeds size limit")
    return encoded


def _key_bytes(signing_key: str) -> bytes:
    if not isinstance(signing_key, str) or not _HEX_KEY_RE.fullmatch(signing_key):
        raise CommandEnvelopeError("signing key must be 32 bytes encoded as 64 hex characters")
    return bytes.fromhex(signing_key)


def create_signed_envelope(
    *,
    signing_key: str,
    device_id: str,
    command_id: str,
    command: str,
    issued_at: int,
    ttl: int,
    params: dict,
) -> dict:
    if not isinstance(device_id, str) or not _DEVICE_ID_RE.fullmatch(device_id):
        raise CommandEnvelopeError("invalid target device")
    if not isinstance(command_id, str) or not _ID_RE.fullmatch(command_id):
        raise CommandEnvelopeError("command id must be a canonical UUID")
    if command not in ALLOWED_COMMANDS:
        raise CommandEnvelopeError("command is not supported by protocol v1")
    if type(issued_at) is not int:
        raise CommandEnvelopeError("issued_at must be an integer epoch timestamp")
    if type(ttl) is not int or not 1 <= ttl <= MAX_COMMAND_TTL_SECONDS:
        raise CommandEnvelopeError("ttl is outside the protocol v1 range")
    if not isinstance(params, dict):
        raise CommandEnvelopeError("params must be an object")

    unsigned = {
        "version": PROTOCOL_VERSION,
        "id": command_id,
        "device_id": device_id,
        "command": command,
        "params": params,
        "issued_at": issued_at,
        "ttl": ttl,
    }
    message = canonical_json(unsigned)
    signature = hmac.new(_key_bytes(signing_key), message, hashlib.sha256).hexdigest()
    return {**unsigned, "sig": signature}


def verify_signature(
    payload: Any,
    *,
    signing_key: str,
    expected_device_id: str,
    now_seconds: int | None = None,
) -> bool:
    try:
        if not isinstance(payload, dict) or set(payload.keys()) != ENVELOPE_FIELDS:
            return False
        if type(payload["version"]) is not int or payload["version"] != PROTOCOL_VERSION:
            return False
        if payload["device_id"] != expected_device_id:
            return False
        if payload["command"] not in ALLOWED_COMMANDS:
            return False
        if not isinstance(payload["id"], str) or not _ID_RE.fullmatch(payload["id"]):
            return False
        if type(payload["issued_at"]) is not int:
            return False
        if type(payload["ttl"]) is not int or not 1 <= payload["ttl"] <= MAX_COMMAND_TTL_SECONDS:
            return False
        if not isinstance(payload["params"], dict):
            return False
        supplied = payload["sig"]
        if not isinstance(supplied, str) or not _HEX_SIG_RE.fullmatch(supplied):
            return False

        now = int(time.time()) if now_seconds is None else int(now_seconds)
        age = now - payload["issued_at"]
        if payload["issued_at"] > now + MAX_CLOCK_SKEW_SECONDS:
            return False
        if age > payload["ttl"] or age < -MAX_CLOCK_SKEW_SECONDS:
            return False

        unsigned = {field: payload[field] for field in SIGNED_FIELDS}
        expected = hmac.new(
            _key_bytes(signing_key),
            canonical_json(unsigned),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, supplied.lower())
    except (CommandEnvelopeError, KeyError, TypeError, ValueError, OverflowError):
        return False


def claim_command_id(command_id: str, replay_db_path: str, now_seconds: int | None = None) -> bool:
    """Persist a command ID before execution; duplicate IDs fail closed."""
    now = int(time.time()) if now_seconds is None else int(now_seconds)
    parent = os.path.dirname(os.path.abspath(replay_db_path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        with sqlite3.connect(replay_db_path, timeout=5) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS processed_commands ("
                "command_id TEXT PRIMARY KEY, received_at INTEGER NOT NULL)"
            )
            conn.execute(
                "DELETE FROM processed_commands WHERE received_at < ?",
                (now - REPLAY_RETENTION_SECONDS,),
            )
            cursor = conn.execute(
                "INSERT OR IGNORE INTO processed_commands(command_id, received_at) VALUES(?, ?)",
                (command_id, now),
            )
            inserted = cursor.rowcount == 1
            conn.commit()
        try:
            os.chmod(replay_db_path, 0o600)
        except OSError:
            pass
        return inserted
    except (OSError, sqlite3.Error):
        return False


def verify_and_claim(
    payload: Any,
    *,
    signing_key: str,
    expected_device_id: str,
    replay_db_path: str,
    now_seconds: int | None = None,
) -> bool:
    if not verify_signature(
        payload,
        signing_key=signing_key,
        expected_device_id=expected_device_id,
        now_seconds=now_seconds,
    ):
        return False
    now = int(time.time()) if now_seconds is None else int(now_seconds)
    return claim_command_id(payload["id"], replay_db_path, now)
