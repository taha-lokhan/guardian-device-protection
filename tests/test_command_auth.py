"""Regression tests for the versioned signed command envelope.

These tests use synthetic command IDs, device IDs and temporary replay databases.
They never connect to MQTT or execute a device command.
"""
import importlib.util
import sys
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VPS = ROOT / "vps-setup"
sys.path.insert(0, str(VPS))
import command_auth as relay_auth  # noqa: E402
import relay_server as relay  # noqa: E402

TEST_KEY = "0123456789abcdef" * 4
DEVICE_ID = "synthetic-device-01"
COMMAND_ID = "11111111-1111-4111-8111-111111111111"
NOW = 1_800_000_000


def make_envelope(**overrides):
    values = {
        "signing_key": TEST_KEY,
        "device_id": DEVICE_ID,
        "command_id": COMMAND_ID,
        "command": "ping",
        "issued_at": NOW,
        "ttl": 300,
        "params": {"nested": {"count": 2, "label": "synthetic"}, "enabled": True},
    }
    values.update(overrides)
    return relay_auth.create_signed_envelope(**values)


def load_helper(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_relay_requires_a_valid_configured_signing_key(monkeypatch):
    monkeypatch.setattr(relay, "COMMAND_SIGNING_KEY", "")
    with pytest.raises(RuntimeError):
        relay._validate_command_signing_key()

    monkeypatch.setattr(relay, "COMMAND_SIGNING_KEY", "invalid")
    with pytest.raises(RuntimeError):
        relay._validate_command_signing_key()

    monkeypatch.setattr(relay, "COMMAND_SIGNING_KEY", TEST_KEY)
    relay._validate_command_signing_key()


def test_relay_builder_emits_target_bound_v1_envelope():
    payload = relay._build_command_payload(
        DEVICE_ID,
        COMMAND_ID,
        "ping",
        int(time.time()),
        300,
        {"nested": {"count": 2, "label": "synthetic"}, "enabled": True},
    )
    assert payload["device_id"] == DEVICE_ID
    assert payload["version"] == 1
    assert relay.verify_command_signature(payload, DEVICE_ID)
    assert not relay.verify_command_signature(payload, "another-synthetic-device")


def test_protocol_v1_matches_cross_platform_known_answer_vector():
    payload = make_envelope(
        issued_at=1_800_000_000,
        ttl=300,
        params={"nested": {"count": 2, "label": "synthetic"}, "enabled": True},
    )
    assert payload["sig"] == (
        "dbdf8209050af0b8bf753f038bc035d44a2873ca8760eadaddd34c8a9b54194e"
    )


def test_relay_envelope_binds_all_required_fields():
    payload = make_envelope()
    assert set(payload) == {
        "version", "id", "device_id", "command", "params",
        "issued_at", "ttl", "sig",
    }
    assert payload["version"] == 1
    assert payload["device_id"] == DEVICE_ID
    assert relay_auth.verify_signature(
        payload, signing_key=TEST_KEY, expected_device_id=DEVICE_ID, now_seconds=NOW + 1
    )


@pytest.mark.parametrize(
    ("field", "replacement", "expected_device"),
    [
        ("id", str(uuid.uuid4()), DEVICE_ID),
        ("device_id", "synthetic-device-02", "synthetic-device-02"),
        ("command", "lock", DEVICE_ID),
        ("params", {"nested": {"count": 3, "label": "synthetic"}, "enabled": True}, DEVICE_ID),
        ("issued_at", NOW + 1, DEVICE_ID),
        ("ttl", 301, DEVICE_ID),
        ("version", 2, DEVICE_ID),
    ],
)
def test_tampering_any_signed_field_is_rejected(field, replacement, expected_device):
    payload = make_envelope()
    payload[field] = replacement
    assert not relay_auth.verify_signature(
        payload,
        signing_key=TEST_KEY,
        expected_device_id=expected_device,
        now_seconds=NOW + 2,
    )


def test_signature_tampering_and_unknown_fields_are_rejected():
    payload = make_envelope()
    payload["sig"] = "0" * 64
    assert not relay_auth.verify_signature(
        payload, signing_key=TEST_KEY, expected_device_id=DEVICE_ID, now_seconds=NOW + 1
    )

    payload = make_envelope()
    payload["extra"] = "not-signed"
    assert not relay_auth.verify_signature(
        payload, signing_key=TEST_KEY, expected_device_id=DEVICE_ID, now_seconds=NOW + 1
    )


def test_stale_future_or_invalid_ttl_is_rejected():
    expired = make_envelope()
    expired["issued_at"] = NOW - 301
    assert not relay_auth.verify_signature(
        expired, signing_key=TEST_KEY, expected_device_id=DEVICE_ID, now_seconds=NOW
    )

    future = make_envelope()
    future["issued_at"] = NOW + 61
    assert not relay_auth.verify_signature(
        future, signing_key=TEST_KEY, expected_device_id=DEVICE_ID, now_seconds=NOW
    )

    zero_ttl = make_envelope()
    zero_ttl["ttl"] = 0
    assert not relay_auth.verify_signature(
        zero_ttl, signing_key=TEST_KEY, expected_device_id=DEVICE_ID, now_seconds=NOW
    )

    excessive_ttl = make_envelope()
    excessive_ttl["ttl"] = 3601
    assert not relay_auth.verify_signature(
        excessive_ttl, signing_key=TEST_KEY, expected_device_id=DEVICE_ID, now_seconds=NOW
    )


def test_replay_claim_survives_a_second_verification(tmp_path):
    replay_db = str(tmp_path / "replay.sqlite3")
    payload = make_envelope()

    assert relay_auth.verify_and_claim(
        payload,
        signing_key=TEST_KEY,
        expected_device_id=DEVICE_ID,
        replay_db_path=replay_db,
        now_seconds=NOW + 1,
    )
    assert not relay_auth.verify_and_claim(
        payload,
        signing_key=TEST_KEY,
        expected_device_id=DEVICE_ID,
        replay_db_path=replay_db,
        now_seconds=NOW + 2,
    )


def test_invalid_signature_does_not_consume_command_id(tmp_path):
    replay_db = str(tmp_path / "replay.sqlite3")
    payload = make_envelope()
    payload["params"]["enabled"] = False

    assert not relay_auth.verify_and_claim(
        payload,
        signing_key=TEST_KEY,
        expected_device_id=DEVICE_ID,
        replay_db_path=replay_db,
        now_seconds=NOW + 1,
    )

    valid = make_envelope()
    assert relay_auth.verify_and_claim(
        valid,
        signing_key=TEST_KEY,
        expected_device_id=DEVICE_ID,
        replay_db_path=replay_db,
        now_seconds=NOW + 1,
    )


def test_protocol_rejects_unsafe_target_device_ids():
    for device_id in ("../device", "device/other", "device with spaces", "x" * 65):
        with pytest.raises(relay_auth.CommandEnvelopeError):
            make_envelope(device_id=device_id)


def test_v1_rejects_floats_and_non_ascii_object_keys():
    with pytest.raises(relay_auth.CommandEnvelopeError):
        make_envelope(params={"value": 1.5})

    with pytest.raises(relay_auth.CommandEnvelopeError):
        make_envelope(params={"näme": "value"})


def test_all_python_platform_helpers_are_identical():
    helpers = [
        VPS / "command_auth.py",
        ROOT / "windows-agent" / "command_auth.py",
        ROOT / "mac-agent" / "command_auth.py",
    ]
    source = helpers[0].read_bytes()
    assert all(path.read_bytes() == source for path in helpers[1:])

    windows = load_helper("windows_command_auth", helpers[1])
    mac = load_helper("mac_command_auth", helpers[2])
    relay_payload = make_envelope()
    for module in (windows, mac):
        assert module.verify_signature(
            relay_payload,
            signing_key=TEST_KEY,
            expected_device_id=DEVICE_ID,
            now_seconds=NOW + 1,
        )


def test_python_agents_verify_before_dispatch_and_fail_closed_without_key():
    for relative in (
        "windows-agent/guardian_windows_agent.py",
        "mac-agent/guardian_mac_agent.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        handler = source.split("def handle_command(payload: dict):", 1)[1]
        assert handler.index("verify_and_claim(") < handler.index('payload.get("command")')
        assert "GUARDIAN_COMMAND_SIGNING_KEY must be configured" in source


def test_android_agent_verifies_before_command_dispatch_and_persists_replays():
    service = (
        ROOT / "android-app/app/src/main/java/com/guardian/agent/GuardianService.kt"
    ).read_text(encoding="utf-8")
    auth = (
        ROOT / "android-app/app/src/main/java/com/guardian/agent/GuardianCommandAuth.kt"
    ).read_text(encoding="utf-8")

    handler = service.split("private fun handleCommand(cmd: JSONObject)", 1)[1]
    assert handler.index("GuardianCommandAuth.verifyAndClaim") < handler.index("when (command)")
    assert "Mac.getInstance(\"HmacSHA256\")" in auth
    assert "MessageDigest.isEqual" in auth
    assert "GuardianCommandAuth.verifyAndClaim" in service
    assert "GuardianReplayDatabase" in auth
    assert "command_id TEXT PRIMARY KEY NOT NULL" in auth
    assert "guardian-command-replay.db" in auth


def test_android_setup_requires_and_persists_signing_key():
    setup = (
        ROOT / "android-app/app/src/main/java/com/guardian/agent/SetupActivity.kt"
    ).read_text(encoding="utf-8")
    layout = (
        ROOT / "android-app/app/src/main/res/layout/activity_setup.xml"
    ).read_text(encoding="utf-8")
    assert "et_command_signing_key" in setup
    assert 'putString("command_signing_key", commandSigningKey)' in setup
    assert 'android:id="@+id/et_command_signing_key"' in layout
