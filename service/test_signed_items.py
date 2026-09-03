"""Signed items: trust that follows the author, verified offline."""
import json
import os
import time

import pytest
from fastapi.testclient import TestClient

import bip340
import terminal_service as t

LOCAL = "http://plan.localhost"
SEC = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
PUB = bip340.pubkey_of(SEC)
OTHER_SEC = os.urandom(32)
SOURCE = "RUN\necho signed"


def signature(source, sec=SEC, created_at=1758000000, item_type="terminal"):
    pub = bip340.pubkey_of(sec).hex()
    sig = bip340.sign(t.event_id(pub, created_at, item_type, source), sec)
    return {"alg": "bip340", "pubkey": pub, "created_at": created_at, "sig": sig.hex()}


@pytest.fixture(autouse=True)
def trust_file(tmp_path, monkeypatch):
    f = tmp_path / "trust.json"
    f.write_text(json.dumps({"sites": [], "keys": {bip340.npub(PUB): {"id": "tester"}}}))
    monkeypatch.setattr(t, "trust", t.TrustStore(str(f)))
    t._page_cache.clear()
    # no network: any page fetch is a failure, which a signature must not need

    def boom(url):
        raise OSError("offline")
    monkeypatch.setattr(t, "fetch_page", boom)
    yield f


@pytest.fixture
def client():
    return TestClient(t.app)


def test_trusted_keys_accepts_npub_and_hex(trust_file):
    trust_file.write_text(json.dumps({"keys": {PUB.hex(): {"id": "hex"}, bip340.npub(PUB): {"id": "npub"}}}))
    keys = t.trusted_keys()
    assert PUB.hex() in keys


def test_signed_item_runs_on_an_untrusted_site_offline(client):
    ref = {"site": "stranger.example", "slug": "forked-copy", "itemId": "abc"}
    r = client.post("/terminal/run", json={"text": "echo signed", "page": ref, "source": SOURCE,
                                           "signature": signature(SOURCE)}, headers={"Origin": LOCAL})
    assert r.status_code == 200
    assert r.json()["stdout"].strip() == "signed"
    assert r.json()["verified"]["signed_by"] == "tester"


def test_stale_signature_falls_back_and_fails_offline(client):
    ref = {"site": "stranger.example", "slug": "forked-copy", "itemId": "abc"}
    edited = SOURCE + " # edited"
    r = client.post("/terminal/run", json={"text": "echo signed # edited", "page": ref, "source": edited,
                                           "signature": signature(SOURCE)}, headers={"Origin": LOCAL})
    assert r.status_code == 403
    assert "stale" in r.json()["stderr"] and "not a trusted site" in r.json()["stderr"]


def test_untrusted_key_refused(client):
    ref = {"site": "stranger.example", "slug": "forked-copy", "itemId": "abc"}
    r = client.post("/terminal/run", json={"text": "echo signed", "page": ref, "source": SOURCE,
                                           "signature": signature(SOURCE, sec=OTHER_SEC)}, headers={"Origin": LOCAL})
    assert r.status_code == 403 and "does not trust" in r.json()["stderr"]


def test_signature_covers_directives():
    v = t.verify_signature("GUARD: true\necho signed", t.Signature(**signature(SOURCE)))
    assert not v.ok


def test_signature_binds_item_type():
    v = t.verify_signature(SOURCE, t.Signature(**signature(SOURCE, item_type="code")))
    assert not v.ok


def test_malformed_signature():
    v = t.verify_signature(SOURCE, t.Signature(alg="bip340", pubkey="zz", created_at=1, sig="00"))
    assert not v.ok and v.why == "malformed signature"
    v = t.verify_signature(SOURCE, t.Signature(alg="rsa", pubkey=PUB.hex(), created_at=1, sig="00" * 64))
    assert not v.ok and "unknown signature algorithm" in v.why


def test_text_to_run_must_still_be_the_script(client):
    ref = {"site": "stranger.example", "slug": "forked-copy", "itemId": "abc"}
    r = client.post("/terminal/run", json={"text": "id", "page": ref, "source": SOURCE,
                                           "signature": signature(SOURCE)}, headers={"Origin": LOCAL})
    assert r.status_code == 403 and "script of the published item" in r.json()["stderr"]


def test_verify_endpoint_reports_signer_and_staleness(client):
    ref = {"site": "stranger.example", "slug": "forked-copy", "itemId": "abc"}
    ok = client.post("/terminal/verify", json={"source": SOURCE, "page": ref, "signature": signature(SOURCE)},
                     headers={"Origin": LOCAL}).json()
    assert ok["ok"] and ok["signed_by"] == "tester" and ok["signature"] == "ok"
    stale = client.post("/terminal/verify", json={"source": SOURCE + "!", "page": ref, "signature": signature(SOURCE)},
                        headers={"Origin": LOCAL}).json()
    assert not stale["ok"] and "stale" in stale["signature"]
    local = client.post("/terminal/verify", json={"source": SOURCE, "signature": signature(SOURCE)},
                        headers={"Origin": LOCAL}).json()
    assert local["local"] and local["signed_by"] == "tester"


def test_check_with_a_signed_guard(client):
    src = "GUARD: true\necho signed"
    ref = {"site": "stranger.example", "slug": "forked-copy", "itemId": "abc"}
    r = client.post("/terminal/check", json={"guards": [{"id": "abc", "test": "true"}], "page": ref, "source": src,
                                             "signature": signature(src)}, headers={"Origin": LOCAL})
    assert r.status_code == 200 and r.json()["results"]["abc"] is True


def test_canonical_event_matches_fixture():
    fixture = os.path.join(os.path.dirname(__file__), "..", "test", "fixtures", "sign-vectors.json")
    for v in json.load(open(fixture)):
        assert t.canonical_event(v["pubkey"], v["created_at"], v["type"], v["text"]) == v["canonical"]
        assert t.event_id(v["pubkey"], v["created_at"], v["type"], v["text"]).hex() == v["event_id"]


def test_public_origin_signed_still_needs_grant(client):
    t.lock_all()
    ref = {"site": "stranger.example", "slug": "forked-copy", "itemId": "abc"}
    r = client.post("/terminal/run", json={"text": "echo signed", "page": ref, "source": SOURCE,
                                           "signature": signature(SOURCE)}, headers={"Origin": "https://plan.ide.earth"})
    assert r.status_code == 403  # a stranger origin is not even allowed in; trust sites is empty here
