from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "deploy/agent-replay/install.sh"
UNIT = ROOT / "deploy/agent-replay/agent-replay.service"
ENV = ROOT / "deploy/agent-replay/service.env.example"


def test_installer_requires_exact_commit_and_validation_sentinel():
    text = INSTALL.read_text()
    assert "--expected-commit" in text
    assert "^[[" not in text
    assert "git pull" not in text
    assert "reset --hard origin/" not in text
    assert ".agent-replay-validated" in text
    assert "git -C \"$SRC\" rev-parse HEAD" in text
    assert "pytest -q" in text


def test_installer_shell_syntax_is_valid():
    result = subprocess.run(["bash", "-n", str(INSTALL)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_service_uses_immutable_current_release_and_non_root_user():
    text = UNIT.read_text()
    assert "User=agentreplay" in text
    assert "/opt/agent-replay/current/.venv/bin/python" in text
    assert "NoNewPrivileges=yes" in text
    assert "MemoryMax=1G" in text


def test_default_service_bind_is_localhost_only():
    text = ENV.read_text()
    assert "AGENT_REPLAY_HOST=127.0.0.1" in text
    assert "AGENT_REPLAY_PORT=8791" in text
