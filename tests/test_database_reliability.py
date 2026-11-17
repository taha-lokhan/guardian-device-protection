"""SQLite connection policy and concurrent-write regression tests."""
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vps-setup"))
import relay_server as relay  # noqa: E402


@pytest.fixture
def isolated_db(monkeypatch, tmp_path):
    monkeypatch.setattr(relay, "DB_PATH", str(tmp_path / "relay.db"))
    monkeypatch.setattr(relay, "DB_BUSY_TIMEOUT_MS", 5000)
    relay.init_db()


def test_database_connections_use_wal_and_explicit_busy_timeout(isolated_db, monkeypatch):
    monkeypatch.setattr(relay, "DB_BUSY_TIMEOUT_MS", 2750)
    with relay.db_conn() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 2750
        # Preserve SQLite's default FULL durability while enabling WAL.
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2


def test_concurrent_connections_commit_all_rows_without_lock_errors(isolated_db):
    with relay.db_conn() as conn:
        conn.execute(
            "CREATE TABLE concurrent_probe (worker INTEGER NOT NULL, item INTEGER NOT NULL, "
            "PRIMARY KEY(worker, item))"
        )

    workers = 8
    rows_per_worker = 40
    start = threading.Barrier(workers)

    def write_rows(worker_id):
        start.wait(timeout=5)
        for item in range(rows_per_worker):
            with relay.db_conn() as conn:
                conn.execute(
                    "INSERT INTO concurrent_probe(worker, item) VALUES(?, ?)",
                    (worker_id, item),
                )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(write_rows, worker) for worker in range(workers)]
        for future in futures:
            future.result(timeout=30)

    with relay.db_conn() as conn:
        count = conn.execute("SELECT COUNT(*) FROM concurrent_probe").fetchone()[0]
    assert count == workers * rows_per_worker
