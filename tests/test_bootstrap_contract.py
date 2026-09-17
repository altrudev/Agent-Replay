from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "deploy/bootstrap-vps-once.sh"


def test_bootstrap_shell_syntax_is_valid():
    result = subprocess.run(["bash", "-n", str(BOOTSTRAP)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_bootstrap_requires_exact_private_revisions_and_existing_credential():
    text = BOOTSTRAP.read_text()
    assert "<ddcre-sha> <dsr-control-sha>" in text
    assert "DDCRE_REPO_READ_TOKEN" in text
    assert "--expected-commit \"$DDCRE_SHA\"" in text
    assert "--expected-commit \"$DSR_SHA\"" in text
    assert "git pull" not in text
    assert "curl" not in text
    assert "wget" not in text


def test_bootstrap_only_enables_named_agent_replay_capability():
    text = BOOTSTRAP.read_text()
    assert "agent_replay.deploy" in text
    assert "service.deploy.agent-replay/v1" in text
    assert "BOUNDED_PRIVILEGED" in text
    assert "altrudev/Agent-Replay" in text


def test_bootstrap_preserves_existing_config_ownership():
    text = BOOTSTRAP.read_text()
    assert "os.chown(tmp,st.st_uid,st.st_gid)" in text
    assert "os.chmod(tmp,st.st_mode & 0o777)" in text


def test_bootstrap_does_not_start_dsr_with_placeholder_tokens():
    text = BOOTSTRAP.read_text()
    marker = text.index("REPLACE_WITH_FINE_GRAINED_TOKEN")
    start = text.index("systemctl enable --now dsr-control.timer")
    assert marker < start
