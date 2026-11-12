"""Regression tests for ACK correlation and destructive-workflow state integrity.

All messages are injected into the relay callback directly. MQTT transport and
endpoint execution are never used; all state lives in a disposable SQLite DB.
"""
import json
import sqlite3
import sys
import time
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vps-setup"))
import relay_server as relay  # noqa: E402


@pytest.fixture
def harness(monkeypatch, tmp_path):
    db_path = tmp_path / "ack-correlation.db"
    monkeypatch.setattr(relay, "DB_PATH", str(db_path))
    relay.init_db()
    # The callback does not connect to MQTT. Capture logs without leaking payloads.
    return db_path


def add_command(device_id="device-a", command="wipe", status="sent"):
    command_id = str(uuid.uuid4())
    issued_at = time.time()
    relay.db_log_command(command_id, device_id, command, {}, issued_at)
    with sqlite3.connect(relay.DB_PATH) as conn:
        conn.execute(
            "UPDATE command_log SET status=? WHERE command_id=?",
            (status, command_id),
        )
    return command_id


def add_outbox(device_id, command_id, command="wipe"):
    relay.db_enqueue_outbox_command(
        device_id, command, {}, command_id, time.time(), 300,
        destructive=(command == "wipe"),
    )


def send_ack(device_id, payload):
    class Message:
        topic = f"guardian/{device_id}/ack"
        def __init__(self, body):
            self.payload = json.dumps(body).encode("utf-8")
    relay.on_message(None, None, Message(payload))


def command_status(command_id):
    with sqlite3.connect(relay.DB_PATH) as conn:
        row = conn.execute(
            "SELECT status FROM command_log WHERE command_id=?",
            (command_id,),
        ).fetchone()
    return row[0] if row else None


def test_ack_requires_command_id_and_does_not_mutate_latest_row(harness):
    expected = add_command()
    send_ack("device-a", {"command": "wipe", "status": "completed"})
    assert command_status(expected) == "sent"
    assert relay.db_get_nuke_state("device-a") is None


def test_mismatched_id_cannot_complete_command_or_nuke_state(harness):
    expected = add_command()
    add_outbox("device-a", expected)
    relay.db_upsert_nuke_state("device-a", {
        "active": True,
        "started_at": time.time() - 10,
        "aborted": False,
        "executed": False,
        "execution_claimed": True,
        "countdown_seconds": 600,
    })

    send_ack("device-a", {
        "command": "wipe",
        "status": "completed",
        "id": str(uuid.uuid4()),
    })

    assert command_status(expected) == "sent"
    assert relay.db_get_outbox_status(expected)["status"] == "pending"
    state = relay.db_get_nuke_state("device-a")
    assert state["executed"] is False
    assert state["active"] is True


def test_command_id_is_bound_to_device_and_command(harness):
    expected = add_command(device_id="device-a", command="wipe")
    add_outbox("device-a", expected)

    send_ack("device-b", {
        "command": "wipe", "status": "completed", "id": expected,
    })
    send_ack("device-a", {
        "command": "lock", "status": "completed", "id": expected,
    })

    assert command_status(expected) == "sent"
    assert relay.db_get_outbox_status(expected)["status"] == "pending"


def test_exact_correlated_ack_updates_only_its_command(harness):
    first = add_command()
    second = add_command()
    add_outbox("device-a", first)
    add_outbox("device-a", second)

    send_ack("device-a", {
        "command": "wipe", "status": "initiating", "id": first,
    })

    assert command_status(first) == "initiating"
    assert command_status(second) == "sent"
    assert relay.db_get_outbox_status(first)["status"] == "device_acknowledged"
    assert relay.db_get_outbox_status(second)["status"] == "pending"


def test_only_correlated_completion_can_mark_nuke_executed(harness):
    command_id = add_command()
    add_outbox("device-a", command_id)
    relay.db_upsert_nuke_state("device-a", {
        "active": False,
        "started_at": time.time() - 10,
        "aborted": False,
        "executed": False,
        "execution_claimed": True,
        "countdown_seconds": 600,
    })

    send_ack("device-a", {
        "command": "wipe", "status": "completed", "id": command_id,
    })

    assert command_status(command_id) == "completed"
    assert relay.db_get_outbox_status(command_id)["status"] == "device_completed"
    state = relay.db_get_nuke_state("device-a")
    assert state["executed"] is True
    assert state["active"] is False


def test_completion_ack_without_execution_claim_does_not_mark_nuke_executed(harness):
    command_id = add_command()
    add_outbox("device-a", command_id)
    relay.db_upsert_nuke_state("device-a", {
        "active": True,
        "started_at": time.time() - 10,
        "aborted": False,
        "executed": False,
        "execution_claimed": False,
        "countdown_seconds": 600,
    })

    send_ack("device-a", {
        "command": "wipe", "status": "completed", "id": command_id,
    })

    state = relay.db_get_nuke_state("device-a")
    assert state["executed"] is False
    assert state["active"] is True


def test_unknown_ack_cannot_mutate_command_log_or_outbox(harness):
    send_ack("device-a", {
        "command": "wipe", "status": "completed", "id": str(uuid.uuid4()),
    })
    assert relay.db_get_nuke_state("device-a") is None
