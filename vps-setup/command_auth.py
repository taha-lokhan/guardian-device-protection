"""Ed25519-authenticated Guardian command envelope protocol v2.

The relay signs with a device-scoped private key. Agents receive only the
matching public key. Keys are raw 32-byte Ed25519 keys encoded as base64.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import time
import uuid
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL_VERSION = 2
MAX_COMMAND_TTL_SECONDS = 3600
MAX_CLOCK_SKEW_SECONDS = 60
REPLAY_RETENTION_SECONDS = 7 * 24 * 60 * 60
MAX_CANONICAL_BYTES = 64 * 1024
SIGNED_FIELDS = (
    "version", "key_id", "id", "device_id", "command", "params",
    "issued_at", "ttl", "nonce",
)
ENVELOPE_FIELDS = frozenset((*SIGNED_FIELDS, "sig"))
ALLOWED_COMMANDS = frozenset({
    "ping", "status", "location", "location_burst",
    "lock", "backup", "abort_wipe", "wipe",
})
_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
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
        raise CommandEnvelopeError("floating-point values are not supported in protocol v2")
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
    _validate_json_value(value)
    try:
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CommandEnvelopeError("value cannot be canonically encoded") from exc
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise CommandEnvelopeError("canonical command exceeds size limit")
    return encoded


def _decode_key(encoded: str, expected_size: int) -> bytes:
    if not isinstance(encoded, str):
        raise CommandEnvelopeError("key must be base64 text")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise CommandEnvelopeError("key is not valid base64") from exc
    if len(raw) != expected_size:
        raise CommandEnvelopeError(f"key must contain exactly {expected_size} bytes")
    return raw


def create_signed_envelope(
    *, signing_key: str, key_id: str, device_id: str, command_id: str,
    command: str, issued_at: int, ttl: int, params: dict, nonce: str | None = None,
) -> dict:
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise CommandEnvelopeError("invalid signing key ID")
    if not isinstance(device_id, str) or not _DEVICE_ID_RE.fullmatch(device_id):
        raise CommandEnvelopeError("invalid target device")
    if not isinstance(command_id, str) or not _ID_RE.fullmatch(command_id):
        raise CommandEnvelopeError("command ID must be a canonical UUID")
    if command not in ALLOWED_COMMANDS:
        raise CommandEnvelopeError("command is not supported by protocol v2")
    if type(issued_at) is not int:
        raise CommandEnvelopeError("issued_at must be an integer epoch timestamp")
    if type(ttl) is not int or not 1 <= ttl <= MAX_COMMAND_TTL_SECONDS:
        raise CommandEnvelopeError("ttl is outside the protocol v2 range")
    if not isinstance(params, dict):
        raise CommandEnvelopeError("params must be an object")
    nonce = str(uuid.uuid4()) if nonce is None else nonce
    if not isinstance(nonce, str) or not _ID_RE.fullmatch(nonce):
        raise CommandEnvelopeError("nonce must be a canonical UUID")

    unsigned = {
        "version": PROTOCOL_VERSION, "key_id": key_id, "id": command_id,
        "device_id": device_id, "command": command, "params": params,
        "issued_at": issued_at, "ttl": ttl, "nonce": nonce,
    }
    private_key = Ed25519PrivateKey.from_private_bytes(_decode_key(signing_key, 32))
    signature = private_key.sign(b"guardian-command-envelope-v2\x00" + canonical_json(unsigned))
    return {**unsigned, "sig": base64.b64encode(signature).decode("ascii")}


def verify_signature(
    payload: Any, *, public_key: str, expected_device_id: str,
    expected_key_id: str, now_seconds: int | None = None,
) -> bool:
    try:
        if not isinstance(payload, dict) or set(payload) != ENVELOPE_FIELDS:
            return False
        if type(payload["version"]) is not int or payload["version"] != PROTOCOL_VERSION:
            return False
        if payload["device_id"] != expected_device_id:
            return False
        if payload["key_id"] != expected_key_id or not _KEY_ID_RE.fullmatch(expected_key_id):
            return False
        if payload["command"] not in ALLOWED_COMMANDS:
            return False
        if not isinstance(payload["id"], str) or not _ID_RE.fullmatch(payload["id"]):
            return False
        if not isinstance(payload["nonce"], str) or not _ID_RE.fullmatch(payload["nonce"]):
            return False
        if type(payload["issued_at"]) is not int:
            return False
        if type(payload["ttl"]) is not int or not 1 <= payload["ttl"] <= MAX_COMMAND_TTL_SECONDS:
            return False
        if not isinstance(payload["params"], dict):
            return False
        signature_text = payload["sig"]
        if not isinstance(signature_text, str):
            return False
        signature = base64.b64decode(signature_text, validate=True)
        if len(signature) != 64:
            return False

        now = int(time.time()) if now_seconds is None else int(now_seconds)
        age = now - payload["issued_at"]
        if payload["issued_at"] > now + MAX_CLOCK_SKEW_SECONDS:
            return False
        if age > payload["ttl"] or age < -MAX_CLOCK_SKEW_SECONDS:
            return False

        unsigned = {field: payload[field] for field in SIGNED_FIELDS}
        Ed25519PublicKey.from_public_bytes(_decode_key(public_key, 32)).verify(
            signature, b"guardian-command-envelope-v2\x00" + canonical_json(unsigned)
        )
        return True
    except (CommandEnvelopeError, InvalidSignature, KeyError, TypeError, ValueError, OverflowError):
        return False


def claim_command_id(command_id: str, nonce: str, device_id: str,
                     replay_db_path: str, now_seconds: int | None = None) -> bool:
    now = int(time.time()) if now_seconds is None else int(now_seconds)
    parent = os.path.dirname(os.path.abspath(replay_db_path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        with sqlite3.connect(replay_db_path, timeout=5) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS processed_commands_v2 ("
                "device_id TEXT NOT NULL, command_id TEXT NOT NULL, nonce TEXT NOT NULL, "
                "received_at INTEGER NOT NULL, PRIMARY KEY(device_id, command_id), "
                "UNIQUE(device_id, nonce))"
            )
            conn.execute(
                "DELETE FROM processed_commands_v2 WHERE received_at < ?",
                (now - REPLAY_RETENTION_SECONDS,),
            )
            cursor = conn.execute(
                "INSERT OR IGNORE INTO processed_commands_v2"
                "(device_id, command_id, nonce, received_at) VALUES(?,?,?,?)",
                (device_id, command_id, nonce, now),
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
    payload: Any, *, public_key: str, expected_device_id: str,
    expected_key_id: str, replay_db_path: str, now_seconds: int | None = None,
) -> bool:
    if not verify_signature(
        payload, public_key=public_key, expected_device_id=expected_device_id,
        expected_key_id=expected_key_id, now_seconds=now_seconds,
    ):
        return False
    return claim_command_id(
        payload["id"], payload["nonce"], expected_device_id,
        replay_db_path, now_seconds,
    )
