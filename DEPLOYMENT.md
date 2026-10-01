# Deploying Kepler for real

This is the runbook for taking `kepler-backend`, `kepler-web`, and
`kepler-landing` off `localhost` and onto real infrastructure: a real
domain, real Let's Encrypt certificates, a real (encrypted) Postgres
instance, each service running as a hardened systemd unit, and a real
`kepler-agent` onboarded and reporting from an actual scanned host
(Step 8). See "What this doesn't cover" at the end for what's still
manual even after all of that (database refresh automation, backups,
monitoring, binary distribution).

You'll need:

- A domain you control (for three subdomains — see Step 2).
- A small Linux VPS. Any provider is fine — DigitalOcean, Hetzner, and
  Linode all have Ubuntu 22.04/24.04 images and $5–10/mo tiers, which is
  more than enough for this. 1 vCPU / 1–2 GB RAM is plenty.
- A local Go toolchain (already set up — you've been building with it all
  along) to cross-compile the binaries rather than installing Go on the
  server.

Every `CHANGEME` / `<your-domain>` / `<vps-ip>` below is something only
you can fill in.

## Architecture for this phase

Each service keeps terminating its own TLS directly (as it already does
locally), on its existing default port, just with a real cert instead of
the self-signed dev one:

| Service | Subdomain | Port |
|---|---|---|
| `kepler-landing` (public site) | `kepler.<your-domain>` | 8445 |
| `kepler-web` (dashboard) | `dashboard.kepler.<your-domain>` | 8444 |
| `kepler-backend` (ingestion API) | `api.kepler.<your-domain>` | 8443 |

This is a deliberate simplification, flagged explicitly rather than
decided silently: a reverse proxy (Caddy, nginx) in front would let
everything live on the tidy default port 443 with one set of SNI-routed
certs, but that's a real architectural addition — a new component in the
request path, a new place for a security-relevant bug — and isn't needed
to prove the deployment works. Revisit this once pretty URLs on 443
actually matter to a real customer.

## Step 1 — Provision the VPS

Spin up an Ubuntu 22.04 or 24.04 VPS with your provider of choice. Note
its public IP.

**If your provider offers encrypted storage volumes, enable it now.**
Disk encryption for the Postgres data directory has to be set at
volume/instance creation — it cannot be turned on after the fact without
a rebuild (same constraint [`SECURITY.md`](SECURITY.md) already documents
for managed Postgres). If your provider doesn't offer this, plan to set
up LUKS on the data volume yourself, or use a managed Postgres instance
instead of self-hosting (see the callout in Step 4).

SSH in as root once to create a non-root sudo user and lock down SSH:

```
adduser kepler-ops
usermod -aG sudo kepler-ops
rsync --archive --chown=kepler-ops:kepler-ops ~/.ssh /home/kepler-ops
```

Then edit `/etc/ssh/sshd_config`: set `PermitRootLogin no`, confirm
`PasswordAuthentication no` (key-only), `systemctl restart sshd`. From
here on, SSH in as `kepler-ops`.

Firewall — allow only what's needed (80 is temporary, for certbot's HTTP
challenge; drop it once certs exist if you never plan to renew via HTTP-01
again, or leave it open since renewal needs it periodically anyway):

```
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 8443/tcp
sudo ufw allow 8444/tcp
sudo ufw allow 8445/tcp
sudo ufw enable
```

## Step 2 — DNS

Create three A records, all pointing at the VPS's IP:

```
kepler.<your-domain>              A    <vps-ip>
dashboard.kepler.<your-domain>    A    <vps-ip>
api.kepler.<your-domain>          A    <vps-ip>
```

Wait for these to actually resolve (`dig kepler.<your-domain>`) before
Step 5 — certbot's HTTP-01 challenge will fail otherwise.

## Step 3 — Postgres

**Managed Postgres is the recommended path once this handles anything
beyond a proof — see [`SECURITY.md`](SECURITY.md) for why (encryption at
rest is a checkbox at instance creation on RDS/Cloud SQL/Azure, versus
you managing LUKS yourself).** For this "get it real" phase, self-hosted
on the same VPS is the pragmatic default:

```
sudo apt update && sudo apt install -y postgresql
```

Postgres listens on localhost only by default — leave it that way,
nothing outside this VPS ever needs to reach it directly.

Create the databases, apply schemas, and create the three least-privilege
service roles (never the databases' owning role — see
[`deploy/db/production-roles-kepler.sql`](deploy/db/production-roles-kepler.sql)
and
[`deploy/db/production-roles-marketing.sql`](deploy/db/production-roles-marketing.sql)
for why each service gets its own scoped role instead of sharing one).
`kepler`
here is a normal role, not a superuser — it doesn't need to be one, since
owning a database's tables already grants full DML on them, and the
role-creation step below runs as Postgres's own `postgres` superuser
instead:

```
sudo -u postgres createuser kepler       # owning role, admin CLI only — not a superuser
sudo -u postgres createdb -O kepler kepler
sudo -u postgres createdb -O kepler kepler_marketing

# Set a real password now, before the first TCP connection below — Ubuntu's
# default pg_hba.conf requires one for anything that isn't a local Unix
# socket peer-auth connection, and kepler-backend-admin will need it later
# anyway (it's not just for this step).
sudo -u postgres psql -c "ALTER ROLE kepler PASSWORD 'CHANGEME'"

psql "postgres://kepler:CHANGEME@localhost/kepler" -f backend/db/schema.sql
psql "postgres://kepler:CHANGEME@localhost/kepler_marketing" -f web/db/waitlist_schema.sql

# Edit the CHANGEME passwords inside both files first (the per-service role
# passwords, separate from kepler's own above). Run as postgres, not
# kepler, since CREATE ROLE and REVOKE CONNECT ON DATABASE need it. These
# are two separate files, not one file run twice, because `psql -f` runs
# the whole file against a single connection — a single file can't grant
# privileges on tables that live in the other database.
sudo -u postgres psql -d kepler -f deploy/db/production-roles-kepler.sql
sudo -u postgres psql -d kepler_marketing -f deploy/db/production-roles-marketing.sql
```

## Step 4 — TLS certificates

```
sudo apt install -y certbot
sudo certbot certonly --standalone -d kepler.<your-domain>
sudo certbot certonly --standalone -d dashboard.kepler.<your-domain>
sudo certbot certonly --standalone -d api.kepler.<your-domain>
```

`--standalone` briefly binds port 80 itself to answer the challenge —
that's why it's open in the firewall. Each command drops certs at
`/etc/letsencrypt/live/<subdomain>/{fullchain,privkey}.pem`.

Set up the restart hook so renewals (certbot's own timer handles the
schedule) actually take effect — Go loads the cert/key once at process
start and never re-reads them:

```
sudo cp deploy/certbot-renew-hook.sh /etc/letsencrypt/renewal-hooks/deploy/kepler-restart.sh
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/kepler-restart.sh
```

## Step 5 — Build and ship the binaries

From your local machine (no Go install needed on the VPS):

```
cd backend && GOOS=linux GOARCH=amd64 go build -o kepler-backend ./cmd/kepler-backend && GOOS=linux GOARCH=amd64 go build -o kepler-backend-admin ./cmd/kepler-backend-admin && cd ..
cd web && GOOS=linux GOARCH=amd64 go build -o kepler-web ./cmd/kepler-web && GOOS=linux GOARCH=amd64 go build -o kepler-web-admin ./cmd/kepler-web-admin && GOOS=linux GOARCH=amd64 go build -o kepler-landing ./cmd/kepler-landing && cd ..

scp backend/kepler-backend backend/kepler-backend-admin web/kepler-web web/kepler-web-admin web/kepler-landing kepler-ops@<vps-ip>:/tmp/
```

On the VPS:

```
sudo mv /tmp/kepler-backend /tmp/kepler-backend-admin /tmp/kepler-web /tmp/kepler-web-admin /tmp/kepler-landing /usr/local/bin/
sudo chmod +x /usr/local/bin/kepler-*
```

## Step 6 — Configure and install the systemd units

Create the env files (root-only — systemd reads these as root before
dropping to each service's `DynamicUser`, so they're never exposed to the
unprivileged process's own filesystem access):

```
sudo mkdir -p /etc/kepler
sudo tee /etc/kepler/backend.env <<'EOF'
KEPLER_DB_URL=postgres://kepler_backend:CHANGEME@localhost:5432/kepler
KEPLER_LISTEN_ADDR=:8443
EOF

sudo tee /etc/kepler/web.env <<'EOF'
KEPLER_DB_URL=postgres://kepler_dashboard:CHANGEME@localhost:5432/kepler
KEPLER_DASHBOARD_USER=operator
KEPLER_DASHBOARD_PASSWORD_HASH=CHANGEME
KEPLER_LISTEN_ADDR=:8444
EOF

sudo tee /etc/kepler/landing.env <<'EOF'
KEPLER_MARKETING_DB_URL=postgres://kepler_landing:CHANGEME@localhost:5432/kepler_marketing
KEPLER_LISTEN_ADDR=:8445
EOF

sudo chmod 600 /etc/kepler/*.env
```

Generate the real dashboard password hash first (run locally or on the
VPS, doesn't matter — it never touches the network):
`kepler-web-admin hash-password`, paste the result into
`KEPLER_DASHBOARD_PASSWORD_HASH` above.

Copy the unit files, **editing the `CHANGEME` domain in each one first**
to match your actual subdomains from Step 2:

```
scp deploy/systemd/kepler-backend.service deploy/systemd/kepler-web.service deploy/systemd/kepler-landing.service kepler-ops@<vps-ip>:/tmp/
# on the VPS, after editing the domains:
sudo mv /tmp/kepler-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kepler-backend kepler-web kepler-landing
sudo systemctl status kepler-backend kepler-web kepler-landing
```

## Step 7 — Vulnerability database (for scan-report matching)

`POST /v1/scan-reports` — the endpoint a real `kepler-agent` reports
to — needs a Trivy vulnerability database on the backend host.
`POST /v1/findings` works without this step; skip it if you only need
pre-matched submissions.

`kepler-backend` resolves the database at `KEPLER_TRIVY_DB_DIR`, defaulting
to the same per-user cache location the `trivy` CLI itself uses — which
doesn't work here, because `kepler-backend.service` runs under
`DynamicUser` (a different, freshly allocated UID on every restart, with
no persistent home directory). **Set `KEPLER_TRIVY_DB_DIR` explicitly** to
a fixed, shared path instead:

```
sudo apt install -y trivy   # or see https://trivy.dev for other install methods
sudo mkdir -p /var/lib/kepler/trivy-db
sudo trivy image --download-db-only --cache-dir /var/lib/kepler/trivy-db
echo 'KEPLER_TRIVY_DB_DIR=/var/lib/kepler/trivy-db/db' | sudo tee -a /etc/kepler/backend.env
```

`kepler-backend.service`'s `ProtectSystem=strict` makes this directory
read-only to the service by default — add
`ReadOnlyPaths=/var/lib/kepler/trivy-db` to the unit (read-only is
correct: the backend only ever reads this database, never writes it).

**This needs periodic refreshing** — new CVEs are published continuously,
and a stale database silently produces stale findings, not an error. Set
up a daily timer (`trivy image --download-db-only --cache-dir
/var/lib/kepler/trivy-db` on a cron/systemd timer, then `systemctl restart
kepler-backend` to pick it up — matcher.Init only reads the database once
at startup, same reload story as the TLS certs). **Not yet built** — see
"what this doesn't cover" below.

## Step 8 — Onboard a scanned host

With the backend live and a vulnerability database in place, enroll a real
host — see `agent/README.md`'s "Onboarding a host" section for the full
walkthrough. Short version: provision it
(`kepler-backend-admin create-host <hostname>`), cross-compile
`kepler-agent` for Linux, copy it plus `deploy/install-agent.sh` and
`deploy/systemd/` to the target host, then run
`sudo ./install-agent.sh <backend-url> <api-key>` there. It reports every
6 hours on its own from that point on.

## Step 9 — Verify

From your local machine, not the VPS (proves it's actually reachable from
the outside):

```
curl -I https://kepler.<your-domain>:8445/
curl -I https://api.kepler.<your-domain>:8443/v1/findings   # expect 401, not a connection error — proves auth is live
```

If you don't have a real Linux host handy yet for Step 8, prove the full
matching path works first with a hand-built scan report (real matching,
fake collection — `agent/README.md`'s onboarding flow is what replaces
this with a genuinely collected one):

```
KEPLER_DB_URL="postgres://kepler:CHANGEME@localhost/kepler" /usr/local/bin/kepler-backend-admin create-host first-real-host
# then from your local machine:
curl -X POST https://api.kepler.<your-domain>:8443/v1/scan-reports \
  -H "Authorization: Bearer <the key just printed>" \
  -H "Content-Type: application/json" \
  -d '{"host":{"os_name":"Ubuntu","os_version_id":"22.04"},"packages":[{"name":"libssl3","version":"3.0.2-0ubuntu1.1","source_package":"openssl","source_version":"3.0.2-0ubuntu1.1"}]}'
```

Then open `https://dashboard.kepler.<your-domain>:8444/` in a real
browser with a real, CA-trusted cert — no warning this time. Once Step 8's
real agent has reported, the same dashboard shows its actual findings
instead.

## What this doesn't cover

- **Automatic vulnerability database refresh.** Step 7 populates the
  database once; nothing here sets up the daily (or so) re-run that keeps
  it current. A stale database doesn't error — it just silently produces
  stale findings. Needs a cron job or systemd timer running
  `trivy image --download-db-only` plus a `kepler-backend` restart, neither
  of which exists yet as a shipped artifact.
- **Backups.** Nothing here backs up the Postgres data directory.
- **Monitoring/alerting** on the services themselves (uptime, disk space,
  cert expiry beyond certbot's own renewal).
- **Key rotation runbook** — `api_keys` supports revocation/rotation at
  the schema level (see `backend/README.md`), but there's no documented
  operational process for actually doing it yet.
- **Binary distribution.** Onboarding a host (Step 8) still means
  cross-compiling and `scp`-ing a binary by hand — there's no release
  pipeline or package to install from instead.
