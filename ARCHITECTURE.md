# Architecture

Kepler is three independent Go modules (`agent/`, `backend/`, `web/`), each
with its own `go.mod` on purpose — see each module's own README for why
("these intentionally aren't shared Go types," "it has no import path to
internal/store and never will"). That boundary is load-bearing: a
compromised or abused `kepler-landing` signup form literally cannot reach
findings data, because there's no Go import path between them, not just a
convention not to use one.

## Pipeline

```
collect              report/match             store            query/display
(agent/collector,  → (backend/api,          → (backend/store, → (web/store,
 kepler-agent)         backend/matcher,         Postgres)        web/handlers,
                       POST /v1/scan-reports,                    web/templates)
                       API-key auth)
```

Matching used to be a separate step the agent module owned (`agent/matcher`,
run offline via `kepler-matcher`) — it moved into the backend so a live
agent can report and see results automatically, with no human running a
matching step in between. `POST /v1/findings` still exists as a second,
narrower path for pre-matched submissions (manual/offline use), bypassing
matching entirely:

```
ingest (pre-matched)   store
(backend/api,        → (backend/store,
 POST /v1/findings)      Postgres)
```

A second, fully independent pipeline runs alongside it:

```
signup (web/handlers.Waitlist) → web/waitlist.Store → kepler_marketing database
```

These two pipelines share no code path and no database — see
[`SECURITY.md`](SECURITY.md)'s threat surface table for why that's
deliberate, not incidental.

## Module responsibilities

The signatures below are the real ones. Each module has a small test
(`architecture_doc_test.go`) that references every symbol named in its own
section of this table — a rename or removal fails that module's build, not
just this file going stale silently. See "Keeping this honest" below for
why that test exists only *within* each module rather than as one test
covering the whole table.

### `agent/`

| Package | Entry point(s) | Input → Output |
|---|---|---|
| `internal/collector` | `CollectPackages(ctx)`, `CollectOSInfo(ctx)`, `CollectServices(ctx)`, `CollectPorts()` | live host state (dpkg, `/etc/os-release`, systemd, `/proc/net/*`) → `model.Package` / `model.HostInfo` / `model.Service` / `model.Port` |
| `internal/model` | types only: `ScanReport`, `HostInfo`, `Package`, `Service`, `Port` | the data shapes collection produces |

`cmd/kepler-agent` runs the four collectors, then either prints the
resulting `ScanReport` as JSON (default, stdout) or POSTs it to
`KEPLER_BACKEND_URL/v1/scan-reports` (when `KEPLER_BACKEND_URL` and
`KEPLER_API_KEY` are both set — the production path). This module has zero
third-party dependencies — `go.sum` is empty — now that matching (and its
Trivy dependency) lives in `backend/`.

### `backend/`

| Package | Entry point(s) | Input → Output |
|---|---|---|
| `internal/api` | `NewServer(st, matchingAvailable)` | wires both ingestion endpoints behind API-key auth into an `http.Handler` |
| `internal/auth` | `GenerateAPIKey()`, `HashAPIKey(raw)` | a fresh key pair / a hash to compare against storage |
| `internal/matcher` | `Init(dbDir)`, `Match(ctx, host, packages)`, `Close()` | a scan report + a local trivy-db → `[]model.FindingInput`, ready to store |
| `internal/store` | `Open(ctx, url)`, `CreateHost`, `CreateAPIKey`, `HostIDForKeyHash`, `InsertFindings` | Postgres access — the only module that ever writes findings |
| `internal/model` | `ScanReportInput`, `FindingInput`, `IngestRequest`, `IngestResponse` | the JSON wire contracts for both `POST` endpoints |

`cmd/kepler-backend` serves the API, and tries to open a vulnerability
database at startup (soft dependency — see `backend/README.md`'s "the
vulnerability database is a soft dependency, not a hard one"). `cmd/kepler-backend-admin`
is the operator CLI for provisioning hosts (no self-service enrollment in
v1). `cmd/kepler-matcher` is an offline debug tool — not part of any live
path.

### `web/`

| Package | Entry point(s) | Input → Output |
|---|---|---|
| `internal/api` | `NewServer(st, user, hash)`, `NewLandingServer(st)` | `http.Handler` for the dashboard / the landing+waitlist site |
| `internal/auth` | `RequireBasicAuth(user, hash, next)` | gates every dashboard route |
| `internal/store` | `Open(ctx, url)`, `ListFindings(ctx, filter)`, `ListHostnames(ctx)` | read-only queries against the findings database |
| `internal/waitlist` | `Open(ctx, url)`, `Signup(ctx, email)`, `ErrAlreadySignedUp` | writes against the separate marketing database |
| `internal/handlers` | `Findings(st)`, `Waitlist(st)`, `Landing()` | wires store/waitlist into HTTP handlers |
| `internal/templates` | `Findings`, `Landing` (`*html.Template`) | renders the dashboard and marketing pages |

`cmd/kepler-web` serves the dashboard. `cmd/kepler-landing` serves the
public site. `cmd/kepler-web-admin` generates the bcrypt hash
`kepler-web` needs for `KEPLER_DASHBOARD_PASSWORD_HASH`.

## Keeping this honest

Each module gets its own `architecture_doc_test.go` that does nothing but
reference the symbols listed in its table above — not a real test, a
compile-time tripwire. If a function in the table is renamed or removed
without updating this file, that module fails to build.

This is one test per module rather than Graphify's single whole-codebase
version of the same idea, because Kepler's modules can't import each
other's `internal/` packages — that boundary is the point (see the top of
this file). A test that needs cross-module imports to verify a
cross-module table would mean weakening the boundary just to check a
doc, which isn't a trade worth making. Each module instead vouches for its
own section; nothing currently checks that the *pipeline* diagram's shape
(not its per-module entry points) still matches reality — that's a known
gap, not an oversight.
