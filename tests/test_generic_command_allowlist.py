"""Regression tests for the generic command-dispatch security boundary.

These tests mock all MQTT and persistence side effects. They never contact a
broker or execute commands on a device.
"""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vps-setup"))
import relay_server as relay  # noqa: E402


@pytest.fixture
def harness(monkeypatch, tmp_path):
    published = []
    audit_events = []

    relay.app.dependency_overrides[relay.require_auth] = lambda: True
    monkeypatch.setattr(relay, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(relay, "mqtt_connect", lambda: None)
    monkeypatch.setattr(
        relay, "_publish_command",
        lambda *args, **kwargs: published.append((args, kwargs)),
    )
    monkeypatch.setattr(relay, "db_log_command", lambda *args, **kwargs: None)
    monkeypatch.setattr(relay, "db_enqueue_outbox_command", lambda *args, **kwargs: published.append((args, kwargs)))
    monkeypatch.setattr(
        relay, "audit",
        lambda *args, **kwargs: audit_events.append((args, kwargs)),
    )

    yield TestClient(relay.app), published, audit_events

    relay.app.dependency_overrides.clear()


@pytest.mark.parametrize(
    "command",
    ["wipe", "abort_wipe", "NUKE", "unknown", "", "Wipe"],
)
def test_generic_endpoint_rejects_non_allowlisted_commands(harness, command):
    client, published, audit_events = harness

    response = client.post(
        "/command",
        json={"device_id": "test-device", "command": command, "params": {}},
    )

    assert response.status_code == 403
    assert published == []
    assert any(
        event[1].get("detail", "").startswith("cmd=")
        for event in audit_events
    )


@pytest.mark.parametrize(
    "command",
    ["ping", "status", "location", "location_burst", "lock", "backup"],
)
def test_generic_endpoint_dispatches_allowlisted_commands(harness, command):
    client, published, audit_events = harness

    response = client.post(
        "/command",
        json={"device_id": "test-device", "command": command, "params": {}},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    assert len(published) == 1
    assert published[0][0][0:2] == ("test-device", command)
    assert any(event[0][0] == "command.queued" for event in audit_events)


def test_invalid_device_id_is_rejected_before_dispatch(harness):
    client, published, _ = harness

    response = client.post(
        "/command",
        json={"device_id": "../other-device", "command": "ping", "params": {}},
    )

    assert response.status_code == 400
    assert published == []
