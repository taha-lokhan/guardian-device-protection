"""Regression coverage for dashboard and relay session authentication.

All tests use a temporary SQLite database and synthetic credentials. No broker
or enrolled device is contacted.
"""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import relay_server as relay


@pytest.fixture
def session_client(monkeypatch, tmp_path):
    monkeypatch.setattr(relay, "DB_PATH", str(tmp_path / "sessions.sqlite3"))
    monkeypatch.setattr(relay, "MASTER_PASSWORD", "test-master-password")
    monkeypatch.setattr(relay, "SESSION_TTL_SECS", 300)
    monkeypatch.setattr(relay, "verify_totp", lambda secret, token: token == "123456")
    monkeypatch.setattr(relay, "mqtt_connect", lambda: None)

    with TestClient(relay.app) as client:
        yield client


def login(client):
    response = client.post(
        "/auth/login",
        json={"password": "test-master-password", "totp": "123456"},
    )
    assert response.status_code == 200
    token = response.json()["token"]
    assert response.json()["expires_in"] == 300
    return token


def test_login_session_can_authenticate_multiple_requests(session_client):
    token = login(session_client)
    headers = {"Authorization": f"Bearer {token}"}

    first = session_client.get("/devices", headers=headers)
    second = session_client.get("/health", headers=headers)
    third = session_client.get("/agents/latest", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 200


def test_logout_revokes_the_authenticated_session(session_client):
    token = login(session_client)
    headers = {"Authorization": f"Bearer {token}"}

    response = session_client.post(
        "/auth/logout",
        headers=headers,
        json={"token": token},
    )
    assert response.status_code == 200
    assert response.json() == {"status": "logged_out"}

    protected = session_client.get("/devices", headers=headers)
    assert protected.status_code == 401


def test_expired_session_is_rejected(session_client):
    token = login(session_client)
    with relay.db_conn() as conn:
        conn.execute(
            "UPDATE sessions SET expires_at=0 WHERE token=?",
            (token,),
        )

    response = session_client.get(
        "/devices",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


def test_dashboard_uses_login_endpoint_and_session_token():
    dashboard = (
        Path(__file__).resolve().parents[1] / "dashboard" / "dashboard.html"
    ).read_text(encoding="utf-8")

    assert "fetch(API + '/auth/login'" in dashboard
    assert "authToken = data.token" in dashboard
    assert "authToken = pass + ':' + totp" not in dashboard
    assert "res.status === 401 && authToken" in dashboard
    assert "fetch(API + '/auth/logout'" in dashboard
