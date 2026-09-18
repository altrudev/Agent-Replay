from __future__ import annotations

import re
import tomllib
from pathlib import Path

import agent_replay


ROOT = Path(__file__).resolve().parents[1]


def _pyproject(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _module_version(path: Path) -> str:
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', path.read_text(encoding="utf-8"), re.MULTILINE)
    assert match, f"missing __version__ in {path}"
    return match.group(1)


def test_core_module_and_package_versions_match():
    package_version = _pyproject(ROOT / "pyproject.toml")["project"]["version"]
    assert agent_replay.__version__ == package_version


def test_ddc_adapter_version_matches_core_and_dependency_floor():
    core_version = _pyproject(ROOT / "pyproject.toml")["project"]["version"]
    adapter_project = _pyproject(ROOT / "adapters" / "ddc" / "pyproject.toml")["project"]
    adapter_module_version = _module_version(
        ROOT / "adapters" / "ddc" / "src" / "agent_replay_ddc" / "__init__.py"
    )

    assert adapter_project["version"] == core_version
    assert adapter_module_version == core_version
    assert f"agent-replay>={core_version},<0.7.0" in adapter_project["dependencies"]
