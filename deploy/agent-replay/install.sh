#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/altrudev/Agent-Replay.git"
REF="${1:-feature/hosted-service-v0.1}"
BASE=/opt/agent-replay

sudo id -u agentreplay >/dev/null 2>&1 || sudo useradd --system --home /var/lib/agent-replay --shell /usr/sbin/nologin agentreplay
sudo install -d -o agentreplay -g agentreplay /var/lib/agent-replay /run/agent-replay
sudo install -d -o root -g root /etc/agent-replay "$BASE"

if [ ! -d "$BASE/repo/.git" ]; then
  sudo git clone "$REPO_URL" "$BASE/repo"
fi
sudo git -C "$BASE/repo" fetch --prune origin
sudo git -C "$BASE/repo" checkout --force "$REF"
sudo git -C "$BASE/repo" reset --hard "origin/$REF" 2>/dev/null || true
sudo ln -sfn "$BASE/repo" "$BASE/current"

if [ ! -x "$BASE/venv/bin/python" ]; then
  sudo python3 -m venv "$BASE/venv"
fi
sudo "$BASE/venv/bin/python" -m pip install --upgrade pip
sudo "$BASE/venv/bin/python" -m pip install -e "$BASE/current" -e "$BASE/current/service[dev]"

sudo cp "$BASE/current/deploy/agent-replay/agent-replay.service" /etc/systemd/system/agent-replay.service
if [ ! -f /etc/agent-replay/service.env ]; then
  sudo cp "$BASE/current/deploy/agent-replay/service.env.example" /etc/agent-replay/service.env
  echo "Edit /etc/agent-replay/service.env before starting the service." >&2
fi
sudo systemctl daemon-reload

echo "Installed $REF. Run the test suite before systemctl enable --now agent-replay."
