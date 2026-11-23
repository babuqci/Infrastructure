#!/bin/bash
# Deploy qci-infra from this checkout to the Mac Studio and (re)load its launchd jobs.
# Usage: deploy/deploy.sh [--no-launchd]
set -euo pipefail
HOST=${QCI_HOST:-qciadmin@mac.attlocal.net}
cd "$(dirname "$0")/.."

rsync -a --delete --exclude .venv --exclude .git --exclude __pycache__ --exclude .pytest_cache ./ "$HOST:qci-infra/"

ssh "$HOST" 'bash -s' -- "${1:-}" <<'EOF'
set -euo pipefail
export PATH=/opt/homebrew/bin:$PATH
cd ~/qci-infra
uv sync -q --no-dev
mkdir -p ~/Library/Logs/qci-infra ~/.local/share/qci-infra
install -d -m 700 ~/.config/qci-infra
[ -f ~/.config/qci-infra/config.toml ] || install -m 600 config.example.toml ~/.config/qci-infra/config.toml
chmod 700 ~/.config/qci-infra && chmod 600 ~/.config/qci-infra/*
[ "${1:-}" = "--no-launchd" ] && { echo "installed (launchd untouched)"; exit 0; }
for job in check daily; do
  plist=~/Library/LaunchAgents/com.qci.infra.$job.plist
  sed "s#__HOME__#$HOME#g" deploy/com.qci.infra.$job.plist > "$plist"
  launchctl bootout gui/$(id -u) "$plist" 2>/dev/null || true
  launchctl bootstrap gui/$(id -u) "$plist"
done
launchctl list | grep com.qci.infra
EOF
