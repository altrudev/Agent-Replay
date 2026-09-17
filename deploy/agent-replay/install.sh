#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo 'Run as root.' >&2; exit 2; }
[[ "${1:-}" == "--expected-commit" && -n "${2:-}" ]] || { echo 'usage: install.sh --expected-commit <40-char-sha>' >&2; exit 2; }
EXPECTED="${2,,}"
[[ "$EXPECTED" =~ ^[0-9a-f]{40}$ ]] || { echo 'exact 40-character commit required' >&2; exit 2; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HEAD="$(git -C "$SRC" rev-parse HEAD)"
[[ "$HEAD" == "$EXPECTED" ]] || { echo 'source commit does not match authorized commit' >&2; exit 3; }
[[ -z "$(git -C "$SRC" status --porcelain --untracked-files=all)" ]] || { echo 'source checkout is not clean' >&2; exit 3; }

BASE=/opt/agent-replay
RELEASE="$BASE/releases/$EXPECTED"
id -u agentreplay >/dev/null 2>&1 || useradd --system --home /var/lib/agent-replay --shell /usr/sbin/nologin agentreplay
install -d -o root -g root -m 0755 "$BASE" "$BASE/releases" /etc/agent-replay
install -d -o agentreplay -g agentreplay -m 0750 /var/lib/agent-replay /run/agent-replay

if [[ ! -d "$RELEASE" ]]; then
  install -d -o root -g root -m 0755 "$RELEASE"
  cleanup_failed_release() { rm -rf "$RELEASE"; }
  trap cleanup_failed_release ERR
  git -C "$SRC" archive --format=tar HEAD | tar -xf - -C "$RELEASE"
  python3 -m venv "$RELEASE/.venv"
  "$RELEASE/.venv/bin/python" -m pip install -q --upgrade pip
  "$RELEASE/.venv/bin/python" -m pip install -q -e "$RELEASE[dev]" -e "$RELEASE/service[dev]"
  PYTHONPATH="$RELEASE/src:$RELEASE/service" "$RELEASE/.venv/bin/python" -m pytest -q "$RELEASE/tests" "$RELEASE/service/tests"
  trap - ERR
fi

cp "$RELEASE/deploy/agent-replay/agent-replay.service" /etc/systemd/system/agent-replay.service
if [[ ! -f /etc/agent-replay/service.env ]]; then
  cp "$RELEASE/deploy/agent-replay/service.env.example" /etc/agent-replay/service.env
  chmod 0600 /etc/agent-replay/service.env
fi
ln -sfn "$RELEASE" "$BASE/current.next"
mv -Tf "$BASE/current.next" "$BASE/current"
systemctl daemon-reload
printf 'STAGED %s\n' "$EXPECTED"
