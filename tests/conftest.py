"""Shared synthetic per-device keys for isolated, non-production tests."""
import base64
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vps-setup"))
import relay_server as relay


@pytest.fixture(autouse=True)
def isolated_device_command_keys(monkeypatch, tmp_path):
    key_root = tmp_path / "command-keys"
    key_root.mkdir(mode=0o700)
    for device_id, seed in (
        ("device-1", b"\x11" * 32),
        ("test-device", b"\x12" * 32),
    ):
        directory = key_root / device_id
        directory.mkdir(mode=0o700)
        private = Ed25519PrivateKey.from_private_bytes(seed)
        private_raw = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_raw = private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        key_id = "synthetic-test-key"
        (directory / "active").write_text(key_id + "\n", encoding="ascii")
        (directory / f"{key_id}.private").write_text(
            base64.b64encode(private_raw).decode("ascii") + "\n", encoding="ascii"
        )
        (directory / f"{key_id}.public").write_text(
            base64.b64encode(public_raw).decode("ascii") + "\n", encoding="ascii"
        )
        os.chmod(directory, 0o700)
        os.chmod(directory / f"{key_id}.private", 0o600)
        os.chmod(directory / f"{key_id}.public", 0o644)
    monkeypatch.setattr(relay, "COMMAND_KEY_DIR", str(key_root))
