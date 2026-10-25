"""The standing Unlock and the Claude Sessions door (Standing Unlock Plan, 2026-10-25).

    pytest service/

A farm entry with an owner and "standing": true lets that owner's sites past
the Unlock with no grant. Everything else stays as it was: other owners' sites,
whole-farm entries and excepted sites still need Unlock, and every run from a
remote page is still checked against what its site publishes.
"""
import json

import pytest
from fastapi.testclient import TestClient

import terminal_service as t

MINE = "https://project.private.fish"
THEIRS = "https://lena.solidarity.quest"
REF = {"site": "project.private.fish", "slug": "kanban-wiki-plan", "itemId": "abc"}
SOURCE = "RUN\necho published"


@pytest.fixture(autouse=True)
def trust_file(tmp_path, monkeypatch):
    f = tmp_path / "trust.json"
    f.write_text(json.dumps({"farms": [
        {"anchor": "https://pi5.private.fish", "owner": "david", "standing": True},
        {"anchor": "https://fab.fish"},                                    # whole farm: never standing
    ], "except": ["old.private.fish"]}))
    monkeypatch.setattr(t, "trust", t.TrustStore(str(f)))

    def fake_json(url):
        if "owner=david" in url:
            return {"owner": "david", "sites": ["project.private.fish", "old.private.fish"]}
        return {"x-fedwiki-farm": {"sites": ["lena.solidarity.quest", "project.private.fish"]}}
    monkeypatch.setattr(t, "fetch_json", fake_json)
    t._farm_cache.clear()
    t._page_cache.clear()
    t.lock_all()
    t.resume_standing()
    yield f


@pytest.fixture
def published(monkeypatch):
    page = {"story": [{"type": "terminal", "id": "abc", "text": SOURCE}]}
    monkeypatch.setattr(t, "fetch_page", lambda url: page)


@pytest.fixture
def client():
    return TestClient(t.app)


def same_origin():
    return {"Sec-Fetch-Site": "same-origin", "Origin": "http://testserver"}


def test_standing_sites_are_the_owner_sites_minus_except():
    assert t.standing_sites() == {"project.private.fish"}
    assert t.origin_standing(MINE)
    assert not t.origin_standing("http://project.private.fish")   # https only
    assert not t.origin_standing(THEIRS)                          # trusted by the whole farm, not owned
    assert not t.origin_standing("https://old.private.fish")      # excepted


def test_owned_site_runs_without_a_grant(client, published):
    r = client.post("/terminal/run", json={"text": "echo published", "page": REF, "source": SOURCE},
                    headers={"Origin": MINE})
    assert r.status_code == 200, r.text
    assert r.json()["stdout"] == "published\n"
    assert r.json()["verified"]["site"] == "project.private.fish"


def test_owned_site_still_checked_against_publication(client, published):
    r = client.post("/terminal/run", json={"text": "echo forged", "page": REF, "source": "RUN\necho forged"},
                    headers={"Origin": MINE})
    assert r.status_code == 403 and "differs" in r.json()["stderr"]
    r = client.post("/terminal/run", json={"text": "echo bare"}, headers={"Origin": MINE})
    assert r.status_code != 200 and "no page reference" in r.json()["stderr"]


def test_other_owner_still_locked(client, published):
    ref = dict(REF, site="lena.solidarity.quest")
    r = client.post("/terminal/run", json={"text": "echo published", "page": ref, "source": SOURCE},
                    headers={"Origin": THEIRS})
    assert r.status_code == 401 and r.json()["locked"]
    tok, _ = t.mint_grant(THEIRS)
    r = client.post("/terminal/run", json={"text": "echo published", "page": ref, "source": SOURCE},
                    headers={"Origin": THEIRS, "Authorization": f"Bearer {tok}"})
    assert r.status_code == 200


def test_health_and_trust_say_unlocked_for_owned(client):
    assert client.get("/terminal/health", headers={"Origin": MINE}).json()["locked"] is False
    assert client.get("/terminal/health", headers={"Origin": THEIRS}).json()["locked"] is True
    body = client.get("/terminal/trust", headers={"Origin": MINE}).json()
    assert body["standing"] is True and body["locked"] is False and body["standing_sites"] == 1
    assert client.get("/terminal/trust", headers={"Origin": THEIRS}).json()["standing"] is False


def test_lock_everything_pauses_standing_until_resumed(client, published):
    assert client.post("/terminal/lock", headers=same_origin()).status_code == 200
    assert not t.origin_standing(MINE)
    r = client.post("/terminal/run", json={"text": "echo published", "page": REF, "source": SOURCE},
                    headers={"Origin": MINE})
    assert r.status_code == 401
    st = client.get(f"/terminal/grants?origin={MINE}", headers=same_origin()).json()["standing"]
    assert st == {"sites": 1, "paused": True, "here": False}
    assert client.post("/terminal/unlock/resume", headers={"Origin": MINE, "Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/terminal/unlock/resume", headers=same_origin()).status_code == 200
    assert t.origin_standing(MINE)


def test_standing_needs_an_owner(trust_file):
    trust_file.write_text(json.dumps({"farms": [{"anchor": "https://fab.fish", "standing": True}]}))
    assert t.trust.farms() == [{"anchor": "https://fab.fish", "owner": None, "standing": False}]
    assert t.standing_sites() == set()


def test_websocket_owned_site_needs_no_token(client):
    with client.websocket_connect("/terminal/pty/standing-ws-test", headers={"Origin": MINE}) as ws:
        ws.send_text(json.dumps({"type": "auth", "token": "standing"}))
        ws.send_text(json.dumps({"type": "input", "data": "echo hi\r"}))
        assert ws.receive_bytes() is not None
    t.sessions.pop("standing-ws-test").close()
    with pytest.raises(Exception):
        with client.websocket_connect("/terminal/pty/standing-ws-test2", headers={"Origin": THEIRS}) as ws:
            ws.send_text(json.dumps({"type": "auth", "token": "standing"}))
            ws.receive_bytes()
    if "standing-ws-test2" in t.sessions:
        t.sessions.pop("standing-ws-test2").close()


# ── /terminal/agents ──────────────────────────────────────────────────────────

AGENTS = [{"pid": 101, "name": "kanban", "status": "busy", "kind": "interactive", "cwd": "/Users/david"},
          {"pid": 202, "name": "app", "status": "idle", "kind": "interactive", "cwd": "/"}]
PS = ("  101 claude ZDOTDIR=/Users/david/Code/wiki-plugins/wiki-plugin-terminal/sessions/kanban-wiki-plan-phase-2 "
      "CLAUDE_CODE_OAUTH_TOKEN=sk-secret HOME=/Users/david\n"
      "  202 claude HOME=/Users/david ANTHROPIC_API_KEY=sk-other\n")


@pytest.fixture
def shell(monkeypatch):
    calls = []

    def fake(cmd, check=True):
        calls.append(cmd)
        return json.dumps(AGENTS) if cmd[0] == "zsh" else PS
    monkeypatch.setattr(t, "shell_out", fake)
    return calls


def test_agents_lists_sessions_and_terminal_names_only(client, shell):
    r = client.get("/terminal/agents", headers={"Origin": MINE})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["agents"] == AGENTS
    assert body["terminals"] == {"101": "kanban-wiki-plan-phase-2"}
    assert "sk-secret" not in r.text and "sk-other" not in r.text      # never the environment
    assert shell == [["zsh", "-c", "claude agents --json"], ["ps", "-E", "-o", "pid=,command=", "-p", "101,202"]]


def test_agents_locked_for_other_owner_and_forbidden_for_strangers(client, shell):
    assert client.get("/terminal/agents", headers={"Origin": THEIRS}).status_code == 401
    assert client.get("/terminal/agents", headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.get("/terminal/agents", headers={"Origin": "http://plan.localhost"}).status_code == 200
    assert shell and all(c[0] in ("zsh", "ps") for c in shell)


def test_agents_reports_a_failed_listing(client, monkeypatch):
    def broken(cmd, check=True):
        raise ValueError("claude: command not found")
    monkeypatch.setattr(t, "shell_out", broken)
    r = client.get("/terminal/agents", headers={"Origin": MINE})
    assert r.status_code == 502 and "command not found" in r.json()["error"]


def test_terminals_of_ignores_lines_without_a_wiki_session():
    assert t.terminals_of(PS) == {101: "kanban-wiki-plan-phase-2"}
    assert t.terminals_of("") == {}
