#!/usr/bin/env python3
"""Provision a device-scoped Ed25519 command-verification key pair.

Run locally on the relay host as the service administrator. The private key
never leaves the host; only the base64 public key is printed for agent setup.
"""
import argparse
import base64
import os
import re
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEVICE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    temp = path.with_name(path.name + ".tmp-" + secrets.token_hex(6))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        os.chmod(path, mode)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("device_id")
    parser.add_argument("--key-dir", default="/etc/guardian/command-keys")
    parser.add_argument("--rotate", action="store_true")
    args = parser.parse_args()
    if not DEVICE_RE.fullmatch(args.device_id):
        parser.error("invalid device ID")
    root = Path(args.key_dir)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    device_dir = root / args.device_id
    device_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(device_dir, 0o700)
    active = device_dir / "active"
    if active.exists() and not args.rotate:
        parser.error("device already has an active key; use --rotate after preparing agent reconfiguration")

    key_id = f"k{int(time.time())}-{secrets.token_hex(4)}"
    if not KEY_ID_RE.fullmatch(key_id):
        raise RuntimeError("generated key ID is invalid")
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    private_path = device_dir / f"{key_id}.private"
    public_path = device_dir / f"{key_id}.public"
    atomic_write(private_path, base64.b64encode(private_raw) + b"\n", 0o600)
    atomic_write(public_path, base64.b64encode(public_raw) + b"\n", 0o644)
    atomic_write(active, (key_id + "\n").encode(), 0o600)
    print("Provisioning complete. Keep the private key on the relay host.")
    print(f"device_id={args.device_id}")
    print(f"key_id={key_id}")
    print(f"public_key={base64.b64encode(public_raw).decode('ascii')}")
    print(f"public_key_file={public_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
