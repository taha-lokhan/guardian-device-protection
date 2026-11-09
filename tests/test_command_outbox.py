"""Durable command outbox tests; all broker operations are mocked."""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vps-setup"))
import relay_server as relay  # noqa: E402


@pytest.fixture
def outbox_db(monkeypatch, tmp_path):
    monkeypatch.setattr(relay, "DB_PATH", str(tmp_path / "outbox.db"))
    relay.init_db()


def enqueue(command="ping", destructive=False):
    command_id = "11111111-1111-4111-8111-111111111111"
    relay.db_enqueue_outbox_command(
        "device-1", command, {}, command_id, 1000.0, 300,
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
    safe_id = enqueue("ping", destructive=False)
    destructive_id = "22222222-2222-4222-8222-222222222222"
    relay.db_enqueue_outbox_command(
        "device-1", "wipe", {}, destructive_id, 1000.0, 300,
        destructive=True,
    )

    assert relay.db_claim_outbox_command(safe_id) is not None
    assert relay.db_claim_outbox_command(destructive_id) is not None

    relay.db_recover_outbox_after_restart()

    safe_status = relay.db_get_outbox_status(safe_id)
    destructive_status = relay.db_get_outbox_status(destructive_id)
    assert safe_status["status"] == "pending"
    assert destructive_status["status"] == "uncertain"
    assert relay.db_get_next_outbox_command()["command_id"] == safe_id


def test_device_ack_is_bound_to_exact_device_and_command_id(outbox_db):
    command_id = enqueue("wipe", destructive=True)
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
