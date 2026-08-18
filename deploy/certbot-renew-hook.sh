#!/usr/bin/env bash
# Install: copy to /etc/letsencrypt/renewal-hooks/deploy/kepler-restart.sh
# and chmod +x. Certbot runs every script in that directory after any
# certificate renews successfully.
#
# Why this is needed: each Kepler service reads its TLS cert/key once at
# startup (Go's tls.LoadX509KeyPair, called inside ListenAndServeTLS) and
# never re-reads the files. A renewed certificate sitting on disk changes
# nothing for a running process — it has to restart to pick up the new
# cert/key via LoadCredential (see deploy/systemd/*.service). Without this
# hook, certs would renew every ~60 days but the running services would
# keep serving the old one until it actually expired.
set -euo pipefail

systemctl restart kepler-backend.service kepler-web.service kepler-landing.service
