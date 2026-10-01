# Deploying Kepler for real

This is the runbook for taking `kepler-backend`, `kepler-web`, and
`kepler-landing` off `localhost` and onto real infrastructure: a real
domain, real Let's Encrypt certificates, a real (encrypted) Postgres
instance, and each service running as a hardened systemd unit.

It does **not** cover `kepler-agent` reporting from a real scanned host —
see "What this doesn't cover" at the end for why, and what's missing.

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

## Step 7 — Verify

From your local machine, not the VPS (proves it's actually reachable from
the outside):

```
curl -I https://kepler.<your-domain>:8445/
curl -I https://api.kepler.<your-domain>:8443/v1/findings   # expect 401, not a connection error — proves auth is live
```

Provision a real host and post a real finding through the real domain,
same as the local demo but over the internet this time:

```
KEPLER_DB_URL="postgres://kepler:CHANGEME@localhost/kepler" /usr/local/bin/kepler-backend-admin create-host first-real-host
# then from your local machine:
curl -X POST https://api.kepler.<your-domain>:8443/v1/findings \
  -H "Authorization: Bearer <the key just printed>" \
  -H "Content-Type: application/json" \
  -d '{"findings":[{"package":"openssl","version":"1.1.1f","cve_id":"CVE-2023-0286","severity":"HIGH"}]}'
```

Then open `https://dashboard.kepler.<your-domain>:8444/` in a real
browser with a real, CA-trusted cert — no warning this time.

## What this doesn't cover

- **`kepler-agent` isn't wired up to report automatically.** Its own
  README covers running it (`deploy/systemd/kepler-agent.service` is
  included here too), but `kepler-matcher` prints a bare JSON array of
  findings, not the `{"findings": [...]}` shape `/v1/findings` expects —
  there's no glue script that collects, matches, reshapes, and posts in
  one step yet. `backend/README.md`'s own usage example has a literal
  `<reshape into {"findings": [...]}>` placeholder. Worth building before
  actually pointing this at a real scanned fleet; out of scope for this
  pass, which was specifically about getting backend/web/landing
  deployable.
- **Backups.** Nothing here backs up the Postgres data directory.
- **Monitoring/alerting** on the services themselves (uptime, disk space,
  cert expiry beyond certbot's own renewal).
- **Key rotation runbook** — `api_keys` supports revocation/rotation at
  the schema level (see `backend/README.md`), but there's no documented
  operational process for actually doing it yet.
