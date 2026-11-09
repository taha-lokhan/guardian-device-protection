"""Race-condition regression tests for the nuke state machine.

All persistence is isolated to a temporary SQLite database. MQTT publishing is
mocked; no real device receives a command and no wipe is executed.
"""
import asyncio
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vps-setup"))
import relay_server as relay  # noqa: E402


@pytest.fixture
def isolated_db(monkeypatch, tmp_path):
    monkeypatch.setattr(relay, "DB_PATH", str(tmp_path / "nuke-test.db"))
    relay.init_db()


def outbox_commands():
    with sqlite3.connect(relay.DB_PATH) as conn:
        rows = conn.execute(
            "SELECT command, status FROM command_outbox ORDER BY created_at, command_id"
        ).fetchall()
    return rows


def arm(device_id="test-device", *, started_at=0, countdown=1):
    relay.db_upsert_nuke_state(device_id, {
        "active": True,
        "started_at": started_at,
        "aborted": False,
        "executed": False,
        "countdown_seconds": countdown,
    })


def test_abort_and_execution_are_mutually_exclusive(isolated_db):
    arm()

    assert relay.db_abort_nuke_state("test-device") is True
    assert relay.db_claim_nuke_execution("test-device") is False

    state = relay.db_get_nuke_state("test-device")
    assert state["aborted"] is True
    assert state["executed"] is False
    assert state["active"] is False


def test_execution_claim_can_only_be_won_once(isolated_db):
    arm()

    assert relay.db_claim_nuke_execution("test-device") is True
    assert relay.db_claim_nuke_execution("test-device") is False
    assert relay.db_abort_nuke_state("test-device") is False

    state = relay.db_get_nuke_state("test-device")
    assert state["execution_claimed"] is True
    assert state["executed"] is False
    assert state["aborted"] is False
    assert state["active"] is False


def test_abort_during_final_grace_window_prevents_wipe(isolated_db, monkeypatch):
    arm()
    sleeps = 0

    async def controlled_sleep(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps == 2:
            # Simulate a successful abort during the final three-second grace.
            assert relay.db_abort_nuke_state("test-device") is True

    monkeypatch.setattr(relay.asyncio, "sleep", controlled_sleep)

    asyncio.run(relay.nuke_countdown_task("test-device"))

    assert [row[0] for row in outbox_commands()] == ["location_burst"]
    state = relay.db_get_nuke_state("test-device")
    assert state["aborted"] is True
    assert state["executed"] is False


def test_wipe_is_dispatched_only_after_atomic_execution_claim(isolated_db, monkeypatch):
    arm()
    async def no_wait(_seconds):
        return None

    async def no_alert(**_kwargs):
        return None

    monkeypatch.setattr(relay.asyncio, "sleep", no_wait)
    monkeypatch.setattr(relay, "ntfy_alert", no_alert)

    asyncio.run(relay.nuke_countdown_task("test-device"))

    assert [row[0] for row in outbox_commands()] == ["location_burst", "wipe"]
    assert all(row[1] == "pending" for row in outbox_commands())
    state = relay.db_get_nuke_state("test-device")
    assert state["execution_claimed"] is True
    assert state["executed"] is False  # completion is recorded only by device ACK
    assert state["active"] is False



def test_existing_database_gets_execution_claimed_migration(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    monkeypatch.setattr(relay, "DB_PATH", str(db_path))
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE nuke_state (
                device_id TEXT PRIMARY KEY,
                active INTEGER NOT NULL DEFAULT 1,
                started_at REAL NOT NULL,
                aborted INTEGER NOT NULL DEFAULT 0,
                executed INTEGER NOT NULL DEFAULT 0,
                countdown_secs INTEGER NOT NULL
            )
        """)
    relay.init_db()
    with sqlite3.connect(db_path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(nuke_state)")}
    assert "execution_claimed" in columns
