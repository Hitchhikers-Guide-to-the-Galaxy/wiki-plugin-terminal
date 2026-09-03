"""The trust door of the terminal service, asked the questions a caller would.

    pytest service/

No network: the page fetch is stubbed. No shell for the refusals; the runs
that reach a shell echo a word.
"""
import json
import time

import pytest
from fastapi.testclient import TestClient

import terminal_service as t

PUBLIC = "https://plan.ide.earth"
LOCAL = "http://plan.localhost"
REF = {"site": "plan.ide.earth", "slug": "farm-key-demo", "itemId": "abc"}
SOURCE = "RUN\necho published"


@pytest.fixture(autouse=True)
def trust_file(tmp_path, monkeypatch):
    f = tmp_path / "trust.json"
    f.write_text(json.dumps({"sites": ["plan.ide.earth"], "keys": {}}))
    monkeypatch.setattr(t, "trust", t.TrustStore(str(f)))
    t._page_cache.clear()
    t.lock_all()
    yield f


@pytest.fixture
def published(monkeypatch):
    page = {"story": [{"type": "terminal", "id": "abc", "text": SOURCE},
                      {"type": "markdown", "id": "md1", "text": "not a terminal"}]}
    calls = []

    def fake(url):
        calls.append(url)
        return page
    monkeypatch.setattr(t, "fetch_page", fake)
    return calls


@pytest.fixture
def client():
    return TestClient(t.app)


def same_origin():
    return {"Sec-Fetch-Site": "same-origin", "Origin": "http://testserver"}


# ── origins ───────────────────────────────────────────────────────────────────

def test_allowed_origin_local_and_trusted_only():
    assert t.allowed_origin("http://plan.localhost")
    assert t.allowed_origin("http://localhost:4242")
    assert t.allowed_origin("https://plan.ide.earth")
    assert not t.allowed_origin("http://plan.ide.earth")  # https only for a public site
    assert not t.allowed_origin("https://evil.example")
    assert not t.allowed_origin("")
    assert not t.allowed_origin(None)


def test_stranger_origin_refused(client):
    r = client.post("/terminal/run", json={"text": "id"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_local_run_unchanged(client):
    r = client.post("/terminal/run", json={"text": "echo local"}, headers={"Origin": LOCAL})
    assert r.status_code == 200 and r.json()["stdout"].strip() == "local"


# ── publication ───────────────────────────────────────────────────────────────

def test_lineup_foreign_page_runs_when_published(client, published):
    r = client.post("/terminal/run", json={"text": "echo published", "page": REF, "source": SOURCE},
                    headers={"Origin": LOCAL})
    assert r.status_code == 200
    assert r.json()["stdout"].strip() == "published"
    assert r.json()["verified"]["site"] == "plan.ide.earth"
    assert published == ["https://plan.ide.earth/farm-key-demo.json"]


def test_one_byte_off_refused(client, published):
    r = client.post("/terminal/run", json={"text": "echo published;", "page": REF, "source": SOURCE + ";"},
                    headers={"Origin": LOCAL})
    assert r.status_code == 403 and "differs" in r.json()["stderr"]


def test_text_must_be_the_script_of_the_source(client, published):
    r = client.post("/terminal/run", json={"text": "id", "page": REF, "source": SOURCE}, headers={"Origin": LOCAL})
    assert r.status_code == 403 and "script of the published item" in r.json()["stderr"]


def test_untrusted_site_refused(client, published):
    ref = dict(REF, site="other.example")
    r = client.post("/terminal/run", json={"text": "echo published", "page": ref, "source": SOURCE},
                    headers={"Origin": LOCAL})
    assert r.status_code == 403 and "not a trusted site" in r.json()["stderr"]


def test_wrong_item_and_wrong_type(client, published):
    for item_id, why in (("nope", "has no item"), ("md1", "not a terminal item")):
        ref = dict(REF, itemId=item_id)
        r = client.post("/terminal/run", json={"text": "echo published", "page": ref, "source": SOURCE},
                        headers={"Origin": LOCAL})
        assert r.status_code == 403 and why in r.json()["stderr"]


def test_private_address_never_fetched(trust_file, published):
    trust_file.write_text(json.dumps({"sites": ["10.0.0.5"]}))
    v = t.verify_publication(SOURCE, t.PageRef(site="10.0.0.5", slug="x", itemId="abc"))
    assert not v.ok and published == []


def test_malformed_reference():
    v = t.verify_publication(SOURCE, t.PageRef(site="plan.ide.earth", slug="../etc", itemId="abc"))
    assert not v.ok and v.why == "malformed page reference"


def test_page_cache_expires(monkeypatch, published):
    ref = t.PageRef(**REF)
    assert t.verify_publication(SOURCE, ref).ok
    assert t.verify_publication(SOURCE, ref).ok
    assert len(published) == 1
    real = time.monotonic
    monkeypatch.setattr(t.time, "monotonic", lambda: real() + t.PAGE_CACHE_TTL + 1)
    assert t.verify_publication(SOURCE, ref).ok
    assert len(published) == 2


def test_fetch_failure_refuses(monkeypatch):
    def boom(url):
        raise OSError("down")
    monkeypatch.setattr(t, "fetch_page", boom)
    v = t.verify_publication(SOURCE, t.PageRef(**REF))
    assert not v.ok and "could not read" in v.why


def test_broken_trust_file_closes_the_door(trust_file, published):
    trust_file.write_text("{ not json")
    assert t.trust.sites() == set()
    assert not t.site_trusted("plan.ide.earth")


def test_trust_file_reloads_without_restart(trust_file):
    assert t.trust.sites() == {"plan.ide.earth"}
    trust_file.write_text(json.dumps({"sites": ["plan.ide.earth", "bot.pi5"]}))
    import os
    now = time.time() + 5
    os.utime(trust_file, (now, now))
    assert t.trust.sites() == {"plan.ide.earth", "bot.pi5"}


def test_script_of_and_guard_of():
    assert t.script_of("RUN\nGUARD: test -f x\n\nLABEL: go\necho hi\nls") == "echo hi\nls"
    assert t.script_of("echo plain") == "echo plain"
    assert t.guard_of("RUN\nGUARD: test -f x\necho") == "test -f x"
    assert t.guard_of("echo") is None


# ── consent ───────────────────────────────────────────────────────────────────

def test_public_origin_locked_without_grant(client, published):
    r = client.post("/terminal/run", json={"text": "echo published", "page": REF, "source": SOURCE},
                    headers={"Origin": PUBLIC})
    assert r.status_code == 401 and r.json()["locked"] is True


def test_grant_opens_only_its_origin(client, published):
    g = client.post("/terminal/unlock/grant", json={"origin": PUBLIC}, headers=same_origin())
    assert g.status_code == 200
    tok = g.json()["token"]
    ok = client.post("/terminal/run", json={"text": "echo published", "page": REF, "source": SOURCE},
                     headers={"Origin": PUBLIC, "Authorization": f"Bearer {tok}"})
    assert ok.status_code == 200 and ok.json()["stdout"].strip() == "published"
    other = client.post("/terminal/run", json={"text": "echo published", "page": REF, "source": SOURCE},
                        headers={"Origin": "https://other.example", "Authorization": f"Bearer {tok}"})
    assert other.status_code == 403


def test_grant_needs_same_origin_and_trusted_origin(client):
    assert client.post("/terminal/unlock/grant", json={"origin": PUBLIC},
                       headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/terminal/unlock/grant", json={"origin": "https://evil.example"},
                       headers=same_origin()).status_code == 403


def test_grant_expiry_and_lock():
    tok, exp = t.mint_grant(PUBLIC, ttl=60)
    assert t.check_grant(tok, PUBLIC)
    assert not t.check_grant(tok, "https://other.example")
    assert not t.check_grant(tok + "x", PUBLIC)
    assert not t.check_grant("", PUBLIC)
    t.lock_all()
    assert not t.check_grant(tok, PUBLIC)
    tok2, exp2 = t.mint_grant(PUBLIC, ttl=1)
    assert exp2 - time.time() >= 59  # the floor: a grant is never shorter than a minute
    real = time.time
    t.time.time = lambda: real() + 61
    try:
        assert not t.check_grant(tok2, PUBLIC)
    finally:
        t.time.time = real
    assert t.mint_grant(PUBLIC, ttl=10 ** 9)[1] - time.time() <= t.GRANT_MAX + 1


def test_unlock_page_only_for_allowed_origins(client):
    assert client.get("/terminal/unlock", params={"origin": "https://evil.example"}).status_code == 403
    r = client.get("/terminal/unlock", params={"origin": PUBLIC})
    assert r.status_code == 200 and "plan.ide.earth" in r.text and "<script>" not in json.dumps(r.text[:0])


def test_trust_and_health_report_lock_state(client):
    assert client.get("/terminal/trust", headers={"Origin": PUBLIC}).json()["locked"] is True
    assert client.get("/terminal/trust", headers={"Origin": LOCAL}).json()["locked"] is False
    assert client.get("/terminal/health", headers={"Origin": PUBLIC}).json()["locked"] is True
    assert client.get("/terminal/trust", headers={"Origin": "https://evil.example"}).status_code == 403


def test_verify_endpoint(client, published):
    r = client.post("/terminal/verify", json={"source": SOURCE, "page": REF}, headers={"Origin": PUBLIC})
    assert r.json()["ok"] is True and r.json()["locked"] is True
    r = client.post("/terminal/verify", json={"source": SOURCE + "!", "page": REF}, headers={"Origin": LOCAL})
    assert r.json()["ok"] is False
    r = client.post("/terminal/verify", json={"source": "anything"}, headers={"Origin": LOCAL})
    assert r.json()["local"] is True


def test_check_uses_the_published_guard(client, published, monkeypatch):
    src = "RUN\nGUARD: true\necho published"
    page = {"story": [{"type": "terminal", "id": "abc", "text": src}]}
    monkeypatch.setattr(t, "fetch_page", lambda url: page)
    ok = client.post("/terminal/check", json={"guards": [{"id": "abc", "test": "true"}], "page": REF, "source": src},
                     headers={"Origin": LOCAL})
    assert ok.status_code == 200 and ok.json()["results"]["abc"] is True
    bad = client.post("/terminal/check", json={"guards": [{"id": "abc", "test": "id"}], "page": REF, "source": src},
                      headers={"Origin": LOCAL})
    assert bad.status_code == 403


def test_paste_needs_a_live_session(client, published):
    r = client.post("/terminal/paste", json={"session": "s1", "text": "echo published", "page": REF, "source": SOURCE},
                    headers={"Origin": LOCAL})
    assert r.status_code == 409


def test_websocket_public_origin_needs_auth_frame(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/terminal/pty/wsauth", headers={"Origin": PUBLIC}) as ws:
            ws.send_text(json.dumps({"type": "auth", "token": "bogus"}))
            ws.receive_text()
