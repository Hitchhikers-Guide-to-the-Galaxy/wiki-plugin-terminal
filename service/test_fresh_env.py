"""Session shells start like a fresh Terminal window, whatever PATH the
service itself was started with (21 October 2026: a restart from a stripped
PATH put Node 18 and an old nvm `claude` first, and every BOOT crashed)."""
import os
import subprocess

import terminal_service as ts


def test_fresh_env_resets_path_and_drops_launcher_vars(monkeypatch):
    monkeypatch.setenv("PATH", "/Users/x/.nvm/versions/node/v18.17.0/bin:/usr/bin")
    monkeypatch.setenv("CLAUDE_CODE_ENTRYPOINT", "cli")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://proxy")
    monkeypatch.setenv("ZDOTDIR", "/tmp/elsewhere")
    env = ts.fresh_env()
    assert env["PATH"] == ts.FRESH_PATH
    assert "CLAUDE_CODE_ENTRYPOINT" not in env
    assert "ANTHROPIC_BASE_URL" not in env
    assert "ZDOTDIR" not in env


def test_session_dir_hands_login_files_on(monkeypatch, tmp_path):
    monkeypatch.setattr(ts, "SESSION_HOME", str(tmp_path))
    path = ts.session_dir("fresh-test")
    for name in (".zshrc", ".zshenv", ".zprofile", ".zlogin"):
        assert os.path.exists(os.path.join(path, name)), name
    assert "source ~/.zprofile" in open(os.path.join(path, ".zprofile")).read()


def test_login_shell_path_ignores_the_service_path(monkeypatch, tmp_path):
    """A login shell built from fresh_env and the session dir gets a PATH that
    does not depend on the PATH this process had."""
    monkeypatch.setattr(ts, "SESSION_HOME", str(tmp_path))
    zdotdir = ts.session_dir("fresh-test")

    def login_path(service_path):
        monkeypatch.setenv("PATH", service_path)
        env = ts.fresh_env()
        env["ZDOTDIR"] = zdotdir
        out = subprocess.run(["/bin/zsh", "-lic", "print -r -- $PATH"],
                             capture_output=True, text=True, timeout=30, env=env)
        return out.stdout.strip().splitlines()[-1]

    assert login_path("/opt/bogus/one:/usr/bin:/bin") == login_path("/opt/bogus/two:/usr/bin:/bin")
