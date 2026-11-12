"""Synthetic-only regression tests for per-device Ed25519 command authentication."""
import base64
import json
import os
import sys
import time
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vps-setup"))
import command_auth
import relay_server as relay

DEVICE_ID = "synthetic-device-01"
OTHER_DEVICE = "synthetic-device-02"
COMMAND_ID = "11111111-1111-4111-8111-111111111111"
NONCE = "22222222-2222-4222-8222-222222222222"
NOW = 1_800_000_000


def keypair(seed: bytes = b"\x01" * 32):
    private = Ed25519PrivateKey.from_private_bytes(seed)
    private_raw = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_raw).decode(), base64.b64encode(public_raw).decode()


def make_envelope(**overrides):
    private, _ = keypair()
    values = {
        "signing_key": private,
        "key_id": "test-key-01",
        "device_id": DEVICE_ID,
        "command_id": COMMAND_ID,
        "command": "ping",
        "issued_at": NOW,
        "ttl": 300,
        "params": {"nested": {"count": 2, "label": "synthetic"}, "enabled": True},
        "nonce": NONCE,
    }
    values.update(overrides)
    return command_auth.create_signed_envelope(**values)


def verify(payload, public=None, device=DEVICE_ID, kid="test-key-01", now=NOW + 1):
    if public is None:
        _, public = keypair()
    return command_auth.verify_signature(
        payload, public_key=public, expected_device_id=device,
        expected_key_id=kid, now_seconds=now,
    )


def test_protocol_v2_known_ed25519_vector():
    payload = {
        "version": 2,
        "key_id": "test-key-01",
        "id": COMMAND_ID,
        "device_id": DEVICE_ID,
        "command": "ping",
        "params": {"nested": {"count": 2, "label": "synthetic"}, "enabled": True},
        "issued_at": NOW,
        "ttl": 300,
        "nonce": NONCE,
        "sig": "IvMM8qubRvw+TT9dsph3V6iTcH+b/IGWmxY5ADojhzSWMOkZDhzpJHoYryRZceQnshtmgaZpEOl8EsQIBOPaBQ==",
    }
    assert verify(payload, public="iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=")


@pytest.mark.parametrize("field,replacement", [
    ("id", str(uuid.uuid4())),
    ("key_id", "other-key"),
    ("device_id", OTHER_DEVICE),
    ("command", "lock"),
    ("params", {"nested": {"count": 3}, "enabled": True}),
    ("issued_at", NOW + 1),
    ("ttl", 301),
    ("nonce", str(uuid.uuid4())),
    ("version", 3),
])
def test_tampering_any_signed_field_is_rejected(field, replacement):
    payload = make_envelope()
    payload[field] = replacement
    assert not verify(payload)


def test_wrong_device_key_and_unknown_fields_are_rejected():
    payload = make_envelope()
    _, other_public = keypair(b"\x02" * 32)
    assert not verify(payload, public=other_public)
    assert not verify(payload, device=OTHER_DEVICE)
    assert not verify(payload, kid="unknown-key")
    payload["extra"] = "unsigned"
    assert not verify(payload)


def test_invalid_signature_expiry_future_clock_and_ttl_are_rejected():
    payload = make_envelope()
    payload["sig"] = base64.b64encode(b"\x00" * 64).decode()
    assert not verify(payload)
    assert not verify(make_envelope(issued_at=NOW - 301), now=NOW)
    assert not verify(make_envelope(issued_at=NOW + 61), now=NOW)
    zero_ttl = make_envelope()
    zero_ttl["ttl"] = 0
    assert not verify(zero_ttl)
    excessive_ttl = make_envelope()
    excessive_ttl["ttl"] = 3601
    assert not verify(excessive_ttl)


def test_replay_claim_is_durable_and_nonce_is_unique(tmp_path):
    db = str(tmp_path / "replay.sqlite3")
    payload = make_envelope()
    args = dict(
        public_key=keypair()[1], expected_device_id=DEVICE_ID,
        expected_key_id="test-key-01", replay_db_path=db, now_seconds=NOW + 1,
    )
    assert command_auth.verify_and_claim(payload, **args)
    assert not command_auth.verify_and_claim(payload, **args)
    second_id_same_nonce = make_envelope(command_id=str(uuid.uuid4()))
    assert not command_auth.verify_and_claim(second_id_same_nonce, **args)


def test_invalid_signature_does_not_consume_replay_identity(tmp_path):
    db = str(tmp_path / "replay.sqlite3")
    invalid = make_envelope()
    invalid["params"]["enabled"] = False
    args = dict(
        public_key=keypair()[1], expected_device_id=DEVICE_ID,
        expected_key_id="test-key-01", replay_db_path=db, now_seconds=NOW + 1,
    )
    assert not command_auth.verify_and_claim(invalid, **args)
    assert command_auth.verify_and_claim(make_envelope(), **args)


def provision_fixture(root: Path, device: str, kid: str, seed: bytes):
    private, public = keypair(seed)
    directory = root / device
    directory.mkdir(mode=0o700, parents=True)
    (directory / "active").write_text(kid + "\n", encoding="ascii")
    (directory / f"{kid}.private").write_text(private + "\n", encoding="ascii")
    (directory / f"{kid}.public").write_text(public + "\n", encoding="ascii")
    os.chmod(directory, 0o700)
    os.chmod(directory / f"{kid}.private", 0o600)
    return private, public


def test_relay_signs_with_only_the_target_devices_active_key(tmp_path, monkeypatch):
    private, public = provision_fixture(tmp_path, DEVICE_ID, "device-key-a", b"\x03" * 32)
    monkeypatch.setattr(relay, "COMMAND_KEY_DIR", str(tmp_path))
    payload = relay._build_command_payload(
        DEVICE_ID, COMMAND_ID, "ping", NOW, 300, {"ok": True}
    )
    assert payload["key_id"] == "device-key-a"
    assert command_auth.verify_signature(
        payload, public_key=public, expected_device_id=DEVICE_ID,
        expected_key_id="device-key-a", now_seconds=NOW + 1,
    )
    assert not command_auth.verify_signature(
        payload, public_key=public, expected_device_id=OTHER_DEVICE,
        expected_key_id="device-key-a", now_seconds=NOW + 1,
    )


def test_relay_fails_closed_when_device_key_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(relay, "COMMAND_KEY_DIR", str(tmp_path))
    with pytest.raises(command_auth.CommandEnvelopeError):
        relay._build_command_payload(DEVICE_ID, COMMAND_ID, "ping", NOW, 300, {})


def test_relay_private_key_permissions_are_enforced(tmp_path, monkeypatch):
    provision_fixture(tmp_path, DEVICE_ID, "device-key-a", b"\x04" * 32)
    os.chmod(tmp_path / DEVICE_ID / "device-key-a.private", 0o644)
    monkeypatch.setattr(relay, "COMMAND_KEY_DIR", str(tmp_path))
    with pytest.raises(command_auth.CommandEnvelopeError):
        relay._build_command_payload(DEVICE_ID, COMMAND_ID, "ping", NOW, 300, {})


def test_relay_active_key_rotation_switches_trust_to_new_key(tmp_path, monkeypatch):
    old_private, old_public = provision_fixture(
        tmp_path, DEVICE_ID, "old-key", b"\x05" * 32
    )
    directory = tmp_path / DEVICE_ID
    new_private, new_public = keypair(b"\x06" * 32)
    (directory / "new-key.private").write_text(new_private + "\n", encoding="ascii")
    (directory / "new-key.public").write_text(new_public + "\n", encoding="ascii")
    os.chmod(directory / "new-key.private", 0o600)
    (directory / "active").write_text("new-key\n", encoding="ascii")
    monkeypatch.setattr(relay, "COMMAND_KEY_DIR", str(tmp_path))

    payload = relay._build_command_payload(
        DEVICE_ID, str(uuid.uuid4()), "ping", NOW, 300, {}
    )
    assert payload["key_id"] == "new-key"
    assert command_auth.verify_signature(
        payload, public_key=new_public, expected_device_id=DEVICE_ID,
        expected_key_id="new-key", now_seconds=NOW + 1,
    )
    assert not command_auth.verify_signature(
        payload, public_key=old_public, expected_device_id=DEVICE_ID,
        expected_key_id="old-key", now_seconds=NOW + 1,
    )


def test_relay_rejects_symlinked_private_key(tmp_path, monkeypatch):
    private, _ = provision_fixture(tmp_path, DEVICE_ID, "device-key-link", b"\x07" * 32)
    directory = tmp_path / DEVICE_ID
    real_key = directory / "real.private"
    real_key.write_text(private + "\n", encoding="ascii")
    os.chmod(real_key, 0o600)
    (directory / "device-key-link.private").symlink_to(real_key)
    monkeypatch.setattr(relay, "COMMAND_KEY_DIR", str(tmp_path))
    with pytest.raises(command_auth.CommandEnvelopeError):
        relay._build_command_payload(DEVICE_ID, COMMAND_ID, "ping", NOW, 300, {})


def test_relay_rejects_insecure_active_pointer_permissions(tmp_path, monkeypatch):
    provision_fixture(tmp_path, DEVICE_ID, "device-key-mode", b"\x08" * 32)
    os.chmod(tmp_path / DEVICE_ID / "active", 0o644)
    monkeypatch.setattr(relay, "COMMAND_KEY_DIR", str(tmp_path))
    with pytest.raises(command_auth.CommandEnvelopeError):
        relay._build_command_payload(DEVICE_ID, COMMAND_ID, "ping", NOW, 300, {})