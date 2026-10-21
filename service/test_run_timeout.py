"""TIMEOUT: an item may ask for a longer one-shot run, up to a ceiling the service owns
(21 October 2026: a 12-test suite hit the old fixed 30 s from agentic.private.fish)."""
import pytest
from fastapi.testclient import TestClient

import terminal_service as t

LOCAL = "http://localhost"


@pytest.fixture
def client():
    return TestClient(t.app)


def test_run_timeout_clamps_to_the_ceiling(monkeypatch):
    monkeypatch.setattr(t, "RUN_TIMEOUT_MAX", 600)
    assert t.run_timeout(None) == (30, False)
    assert t.run_timeout(0) == (30, False)
    assert t.run_timeout(-5) == (30, False)
    assert t.run_timeout("soon") == (30, False)
    assert t.run_timeout(120) == (120, False)
    assert t.run_timeout(600) == (600, False)
    assert t.run_timeout(86400) == (600, True)


def test_default_is_still_30s(client):
    r = client.post("/terminal/run", json={"text": "echo ok"}, headers={"Origin": LOCAL})
    assert r.status_code == 200 and r.json()["timeout"] == 30 and r.json()["stdout"].strip() == "ok"


def test_an_asked_timeout_lets_a_longer_run_finish(client):
    r = client.post("/terminal/run", json={"text": "sleep 2; echo done", "timeout": 5}, headers={"Origin": LOCAL})
    assert r.json()["exit"] == 0 and r.json()["stdout"].strip() == "done" and r.json()["timeout"] == 5


def test_the_limit_still_bites_and_says_what_to_do(client):
    r = client.post("/terminal/run", json={"text": "sleep 3", "timeout": 1}, headers={"Origin": LOCAL})
    d = r.json()
    assert d["exit"] == -1 and d["stderr"].startswith("timed out after 1s") and "TIMEOUT:" in d["stderr"]


def test_a_page_cannot_ask_past_the_ceiling(client, monkeypatch):
    monkeypatch.setattr(t, "RUN_TIMEOUT_MAX", 2)
    r = client.post("/terminal/run", json={"text": "sleep 4", "timeout": 99999}, headers={"Origin": LOCAL})
    d = r.json()
    assert d["exit"] == -1 and d["timeout"] == 2 and "live session" in d["stderr"]
    ok = client.post("/terminal/run", json={"text": "echo x", "timeout": 99999}, headers={"Origin": LOCAL}).json()
    assert ok["timeout"] == 2 and "ceiling is 2s" in ok["timeout_clamped"]
