#!/usr/bin/env bash
# Installs kepler-agent as a periodic systemd service on this host — the
# one-command step an operator runs on a newly-enrolled host, instead of
# the previous fully-manual "build a binary, copy it over, write a unit
# file by hand" process.
#
# Usage: sudo ./install-agent.sh <backend-url> <api-key>
#   e.g. sudo ./install-agent.sh https://api.kepler.example.com:8443 kepler_abc123...
#
# Prerequisites this script does NOT handle:
#   - The kepler-agent binary must already be next to this script (or at
#     /usr/local/bin/kepler-agent). Cross-compile it locally and copy it
#     here first: GOOS=linux GOARCH=amd64 go build ./cmd/kepler-agent
#     (same pattern DEPLOYMENT.md uses for backend/web/landing — there's
#     no binary-release/distribution pipeline yet).
#   - An API key for this host, from an operator running
#     `kepler-backend-admin create-host <hostname>` against the backend.
#     No self-service enrollment in v1 — see backend/README.md.
#
# What this does:
#   1. Installs the kepler-agent binary to /usr/local/bin.
#   2. Writes /etc/kepler/agent.env (root-only — contains the API key).
#   3. Installs the systemd service + timer shipped alongside this script.
#   4. Enables the timer and runs one report immediately, so you find out
#      right away whether it worked instead of waiting up to 6 hours.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run as root (sudo $0 ...)" >&2
  exit 1
fi

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <backend-url> <api-key>" >&2
  echo "  e.g. $0 https://api.kepler.example.com:8443 kepler_abc123..." >&2
  exit 1
fi

# Strip any trailing slash — kepler-agent builds the request URL as
# "<backend-url>/v1/scan-reports"; a trailing slash here would silently
# produce a double slash and a 404 from the backend.
backend_url=${1%/}
api_key=$2
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

binary_src=""
if [[ -x "$script_dir/kepler-agent" ]]; then
  binary_src="$script_dir/kepler-agent"
elif [[ -x /usr/local/bin/kepler-agent ]]; then
  binary_src=/usr/local/bin/kepler-agent
else
  echo "kepler-agent binary not found at $script_dir/kepler-agent or /usr/local/bin/kepler-agent" >&2
  echo "cross-compile it locally (GOOS=linux GOARCH=amd64 go build ./cmd/kepler-agent) and copy it here first" >&2
  exit 1
fi

install -m 0755 "$binary_src" /usr/local/bin/kepler-agent

mkdir -p /etc/kepler
cat > /etc/kepler/agent.env <<EOF
KEPLER_BACKEND_URL=$backend_url
KEPLER_API_KEY=$api_key
EOF
chmod 600 /etc/kepler/agent.env

install -m 0644 "$script_dir/systemd/kepler-agent.service" /etc/systemd/system/kepler-agent.service
install -m 0644 "$script_dir/systemd/kepler-agent.timer" /etc/systemd/system/kepler-agent.timer

systemctl daemon-reload
systemctl enable --now kepler-agent.timer

echo "running an initial report now, rather than waiting for the first scheduled run..."
systemctl start kepler-agent.service
systemctl status --no-pager kepler-agent.service || true

echo
echo "installed. Reports every 6 hours via kepler-agent.timer."
echo "check past/future runs with: journalctl -u kepler-agent.service"
