# frontend

The dashboard and landing page as a single-page app — React, TypeScript,
Vite, Tailwind. Replaces the plain `html/template` pages in `web/` with a
real UI, without replacing them outright: both Go services still serve
their original pages by default (see `ARCHITECTURE.md`'s "Serving the
frontend"), so this is additive, not a rewrite.

Two sections, one app, client-side routed (`src/App.tsx`):

- **Public**: `/` (the landing page + waitlist form) and `/login`.
- **Authenticated**: `/dashboard` — gated on a credential stored in
  `sessionStorage` (see `src/lib/auth.ts`'s doc comment for why
  `sessionStorage`, not `localStorage`), checked for real on every API
  call the backend itself still enforces via Basic Auth. The frontend's
  own `/login` gate is a UX nicety, not the real security boundary.

## Talking to the backend

`src/lib/api.ts` calls relative paths only (`/api/findings`,
`/waitlist`) — it has no idea whether it's running against Vite's dev
server or a production `kepler-landing`. Both environments proxy those
paths to the real Go services the same way:

- **Dev** (`npm run dev`): `vite.config.ts`'s `server.proxy` forwards
  `/api` → `kepler-web` (`:8444`) and `/waitlist` → `kepler-landing`
  (`:8445`).
- **Production**: `kepler-landing` does the equivalent itself — see
  `web/README.md`'s "Serving the frontend SPA."

## Local development

Requires `kepler-backend` and `kepler-web` running already (see
`backend/README.md`, `web/README.md`) — the dashboard has nothing to show
without them, and the login form needs a real credential to check against.

```
npm install
npm run dev
```

Visit `http://localhost:5173/`. No `kepler-landing` needed for `/waitlist`
in dev — this only matters if you want to test the waitlist form against a
live database; if `kepler-landing` isn't running, Vite's proxy just
returns a connection error, which the form surfaces as "something went
wrong."

## Build

```
npm run build
```

Output lands in `dist/` — a plain static site, no Node runtime needed to
serve it. `tsc -b` runs as part of the build, so a type error fails the
build, not just `npm run dev`'s in-browser overlay.

## Checks

```
npm run lint     # oxlint
npx tsc -b       # type-check only, no build output
```

No component/unit tests yet (the backend side of every API call this app
makes — `GET /api/findings`, `POST /waitlist`, Basic Auth enforcement — is
covered in `web/internal/api` and `web/internal/handlers`'s Go tests
instead). Worth adding if this grows past three pages.
