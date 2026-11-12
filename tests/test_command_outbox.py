"""Durable command outbox tests; all broker operations are mocked."""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vps-setup"))
import relay_server as relay  # noqa: E402


@pytest.fixture
def outbox_db(monkeypatch, tmp_path):
    monkeypatch.setattr(relay, "DB_PATH", str(tmp_path / "outbox.db"))
    relay.init_db()


def enqueue(command="ping", destructive=False, command_id="11111111-1111-4111-8111-111111111111"):
    relay.db_enqueue_outbox_command(
        "device-1", command, {}, command_id, time.time(), 300,
        destructive=destructive,
    )
    return command_id


def test_command_is_persisted_before_publish(outbox_db):
    command_id = enqueue()
    row = relay.db_get_next_outbox_command()
    assert row["command_id"] == command_id
    assert row["status"] == "pending"
    assert row["topic"] == "guardian/device-1/command"
    assert row["payload"]


def test_outbox_claim_is_single_use(outbox_db):
    command_id = enqueue()
    first = relay.db_claim_outbox_command(command_id)
    second = relay.db_claim_outbox_command(command_id)
    assert first is not None
    assert first["attempts"] == 1
    assert second is None


def test_successful_qos1_publish_records_broker_ack(outbox_db, monkeypatch):
    command_id = enqueue()

    class FakeInfo:
        rc = relay.mqtt.MQTT_ERR_SUCCESS
        def wait_for_publish(self, timeout):
            assert timeout == 10
        def is_published(self):
            return True

    monkeypatch.setattr(relay.mqtt_client, "publish", lambda *a, **k: FakeInfo())
    assert relay._publish_outbox_command(command_id) is True
    status = relay.db_get_outbox_status(command_id)
    assert status["status"] == "broker_acked"
    assert status["broker_acked_at"] is not None


def test_destructive_publish_timeout_becomes_uncertain_not_retried(outbox_db, monkeypatch):
    command_id = enqueue(command="wipe", destructive=True)

    class TimedOutInfo:
        rc = relay.mqtt.MQTT_ERR_SUCCESS
        def wait_for_publish(self, timeout):
            return None
        def is_published(self):
            return False

    monkeypatch.setattr(relay.mqtt_client, "publish", lambda *a, **k: TimedOutInfo())
    assert relay._publish_outbox_command(command_id) is False
    status = relay.db_get_outbox_status(command_id)
    assert status["status"] == "uncertain"
    assert status["attempts"] == 1
    assert relay.db_get_next_outbox_command() is None


def test_restart_recovers_safe_commands_but_quarantines_destructive(outbox_db):
    safe_id = enqueue("ping")
    destructive_id = enqueue(
        command="wipe", destructive=True,
        command_id="22222222-2222-4222-8222-222222222222",
    )
    assert relay.db_claim_outbox_command(safe_id) is not None
    assert relay.db_claim_outbox_command(destructive_id) is not None

    relay.db_recover_outbox_after_restart()
    assert relay.db_get_outbox_status(safe_id)["status"] == "pending"
    assert relay.db_get_outbox_status(destructive_id)["status"] == "uncertain"
    assert relay.db_get_next_outbox_command()["command_id"] == safe_id


def test_device_ack_is_bound_to_exact_device_and_command_id(outbox_db):
    command_id = enqueue(command="wipe", destructive=True)
    assert relay.db_mark_outbox_device_acked(
        "other-device", command_id, "wipe", "accepted"
    ) is False
    assert relay.db_mark_outbox_device_acked(
        "device-1", command_id, "ping", "accepted"
    ) is False
    assert relay.db_mark_outbox_device_acked(
        "device-1", command_id, "wipe", "accepted"
    ) is True
    assert relay.db_get_outbox_status(command_id)["status"] == "device_acknowledged"


def test_device_ack_progresses_from_receipt_to_explicit_completion(outbox_db):
    command_id = enqueue(command="wipe", destructive=True)
    assert relay.db_mark_outbox_device_acked(
        "device-1", command_id, "wipe", "initiating"
    ) is True
    first = relay.db_get_outbox_status(command_id)
    assert first["status"] == "device_acknowledged"
    first_ack_at = first["device_acked_at"]

    assert relay.db_mark_outbox_device_acked(
        "device-1", command_id, "wipe", "completed"
    ) is True
    final = relay.db_get_outbox_status(command_id)
    assert final["status"] == "device_completed"
    assert final["device_acked_at"] == first_ack_at


def test_completion_ack_does_not_match_another_command(outbox_db):
    command_id = enqueue(command="wipe", destructive=True)
    assert relay.db_mark_outbox_device_acked(
        "device-1", command_id, "lock", "completed"
    ) is False
    assert relay.db_get_outbox_status(command_id)["status"] == "pending"


def test_duplicate_completion_ack_is_idempotent(outbox_db):
    command_id = enqueue(command="wipe", destructive=True)
    assert relay.db_mark_outbox_device_acked(
        "device-1", command_id, "wipe", "initiating"
    ) is True
    assert relay.db_mark_outbox_device_acked(
        "device-1", command_id, "wipe", "completed"
    ) is True
    assert relay.db_mark_outbox_device_acked(
        "device-1", command_id, "wipe", "completed"
    ) is False
    assert relay.db_get_outbox_status(command_id)["status"] == "device_completed"


def test_expired_queued_command_is_not_published(outbox_db, monkeypatch):
    command_id = "33333333-3333-4333-8333-333333333333"
    relay.db_enqueue_outbox_command(
        "device-1", "ping", {}, command_id, time.time() - 301, 300,
        destructive=False,
    )
    published = []
    monkeypatch.setattr(
        relay.mqtt_client, "publish",
        lambda *args, **kwargs: published.append((args, kwargs)),
    )

    assert relay._publish_outbox_command(command_id) is False
    assert published == []
    assert relay.db_get_outbox_status(command_id)["status"] == "expired"
