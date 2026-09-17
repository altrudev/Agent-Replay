#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo 'Run as root.' >&2; exit 2; }
[[ $# -eq 2 ]] || { echo 'usage: bootstrap-vps-once.sh <ddcre-sha> <dsr-control-sha>' >&2; exit 2; }
DDCRE_SHA="${1,,}"
DSR_SHA="${2,,}"
for value in "$DDCRE_SHA" "$DSR_SHA"; do
  [[ "$value" =~ ^[0-9a-f]{40}$ ]] || { echo 'Both revisions must be exact 40-character Git SHAs.' >&2; exit 2; }
done

TOKEN_FILE=/etc/ddcre/repo-read.env
[[ -r "$TOKEN_FILE" ]] || { echo 'Private repository read credential is not available on this VPS.' >&2; exit 3; }
TOKEN="$(sed -n 's/^DDCRE_REPO_READ_TOKEN=//p' "$TOKEN_FILE" | head -n1)"
[[ -n "$TOKEN" ]] || { echo 'Private repository read credential is empty.' >&2; exit 3; }

WORK="$(mktemp -d /var/tmp/agent-replay-bootstrap.XXXXXX)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
SECRET_FILE="$WORK/token"
ASKPASS="$WORK/git-askpass"
printf '%s' "$TOKEN" > "$SECRET_FILE"
chmod 0600 "$SECRET_FILE"
unset TOKEN
cat > "$ASKPASS" <<'EOF'
#!/bin/sh
case "${1:-}" in
  *Username*) printf '%s\n' x-access-token ;;
  *) cat "$BOOTSTRAP_TOKEN_FILE" ;;
esac
EOF
chmod 0700 "$ASKPASS"
export GIT_ASKPASS="$ASKPASS" BOOTSTRAP_TOKEN_FILE="$SECRET_FILE" GIT_TERMINAL_PROMPT=0

fetch_exact() {
  local repo="$1" sha="$2" dest="$3"
  git init -q "$dest"
  git -C "$dest" remote add origin "https://github.com/altrudev/${repo}.git"
  git -C "$dest" -c credential.helper= -c core.hooksPath=/dev/null fetch -q --no-tags origin "$sha"
  git -C "$dest" checkout -q --detach FETCH_HEAD
  [[ "$(git -C "$dest" rev-parse HEAD)" == "$sha" ]] || { echo "${repo}: fetched revision mismatch" >&2; exit 4; }
  [[ "$(git -C "$dest" rev-parse --is-shallow-repository)" == "false" ]] || { echo "${repo}: shallow checkout not accepted" >&2; exit 4; }
  [[ -z "$(git -C "$dest" status --porcelain --untracked-files=all)" ]] || { echo "${repo}: checkout is not clean" >&2; exit 4; }
}

fetch_exact DDC-Remote-Executor "$DDCRE_SHA" "$WORK/ddcre"
bash "$WORK/ddcre/scripts/install-v05.sh" --expected-commit "$DDCRE_SHA" --enable

python3 - "$DDCRE_SHA" <<'PY'
from pathlib import Path
import json, sys
path=Path('/etc/ddcre/config.json')
doc=json.loads(path.read_text())
priv=doc.setdefault('privileged',{})
priv['agent_replay.deploy']={
    'enabled': True,
    'request_dir': '/var/lib/ddcre/privileged/requests',
    'result_dir': '/var/lib/ddcre/privileged/results',
    'timeout_seconds': 980,
}
tmp=path.with_suffix('.json.tmp')
tmp.write_text(json.dumps(doc,sort_keys=True,indent=2)+'\n')
tmp.chmod(0o640)
tmp.replace(path)
PY
systemctl restart ddcre.timer
systemctl start ddcre.service

fetch_exact DSR-Control "$DSR_SHA" "$WORK/dsr-control"
bash "$WORK/dsr-control/scripts/install.sh" --expected-commit "$DSR_SHA"

python3 - <<'PY'
from pathlib import Path
import json
path=Path('/etc/dsr-control/ddcre-adapter.json')
doc=json.loads(path.read_text())
doc.setdefault('repo_aliases',{})['altrudev/Agent-Replay']='altrudev/Agent-Replay'
doc.setdefault('profiles',{})['service.deploy.agent-replay/v1']={
    'action':'agent_replay.deploy',
    'authority_class':'BOUNDED_PRIVILEGED',
}
tmp=path.with_suffix('.json.tmp')
tmp.write_text(json.dumps(doc,sort_keys=True,indent=2)+'\n')
tmp.chmod(0o640)
tmp.replace(path)
PY

ENV=/etc/dsr-control/dsr-control.env
[[ -f "$ENV" ]] || { echo 'DSR-Control environment file is missing after install.' >&2; exit 5; }
python3 - "$ENV" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]); lines=path.read_text().splitlines(); out=[]; seen=False
for line in lines:
    if line.startswith('DSR_CONTROL_BACKEND_ARGV='):
        out.append('DSR_CONTROL_BACKEND_ARGV=/opt/dsr-control/current/bin/dsr-control-agent-replay-adapter --config /etc/dsr-control/ddcre-adapter.json --token-file /etc/dsr-control/ddcre-token')
        seen=True
    elif line.startswith('DSR_CONTROL_BACKEND_TIMEOUT='):
        out.append('DSR_CONTROL_BACKEND_TIMEOUT=1200')
    else:
        out.append(line)
if not seen:
    out.append('DSR_CONTROL_BACKEND_ARGV=/opt/dsr-control/current/bin/dsr-control-agent-replay-adapter --config /etc/dsr-control/ddcre-adapter.json --token-file /etc/dsr-control/ddcre-token')
path.write_text('\n'.join(out)+'\n')
PY
chmod 0640 "$ENV"

if grep -q 'REPLACE_WITH_FINE_GRAINED_TOKEN' /etc/dsr-control/ddcre-token 2>/dev/null || grep -q '^DSR_CONTROL_GITHUB_TOKEN=replace-with-fine-grained-token' "$ENV"; then
  echo 'BOOTSTRAP PARTIAL: code is installed, but DSR-Control GitHub credentials still require owner configuration.'
  echo 'DDCRE remains active; Agent Replay deployment authority is locally installed but DSR-Control is not started.'
  exit 6
fi

runuser -u dsr-control -- /opt/dsr-control/current/bin/dsr-control selftest
runuser -u dsr-control -- /opt/dsr-control/current/bin/dsr-control doctor --json
systemctl enable --now dsr-control.timer
systemctl start dsr-control.service
printf 'PASS: DDCRE %s and DSR-Control %s bootstrapped for bounded Agent Replay deployment.\n' "$DDCRE_SHA" "$DSR_SHA"
