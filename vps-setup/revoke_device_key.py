#!/usr/bin/env python3
"""Revoke a device command key. This stops new relay signatures immediately."""
import argparse
import os
import re
from pathlib import Path

DEVICE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("device_id")
    parser.add_argument("key_id")
    parser.add_argument("--key-dir", default="/etc/guardian/command-keys")
    args = parser.parse_args()
    if not DEVICE_RE.fullmatch(args.device_id) or not KEY_ID_RE.fullmatch(args.key_id):
        parser.error("invalid device ID or key ID")
    directory = Path(args.key_dir) / args.device_id
    active = directory / "active"
    if active.exists() and active.read_text(encoding="ascii").strip() == args.key_id:
        active.unlink()
    for suffix in ("private", "public"):
        path = directory / f"{args.key_id}.{suffix}"
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    print(f"Revoked key {args.key_id} for {args.device_id}; agent trust config must also be updated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
