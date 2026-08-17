# ArcticWorks Identity — Local Development

## Prerequisites

- Rust (stable, 1.85+), Node.js 20+, npm
- Podman with a machine (recommended) **or** Docker Desktop
- Git Bash / WSL terminal on Windows

## One-time setup

```sh
# 1. Start the infrastructure (PostgreSQL, Valkey, Mailpit).
#    Podman:
podman machine start main
podman compose up -d
#    or Docker Desktop: docker compose up -d

# 2. Install JavaScript dependencies (workspaces: web, sdk, mock, e2e).
npm install

# 3. Build the TypeScript SDK (the mock app imports its dist/).
npm run build:sdk
```

## Running the stack (four terminals)

```sh
# API — http://localhost:8080  (Swagger UI at /api/docs)
cd apps/api
RUST_LOG=info REDIS_URL=redis://localhost:6380 \
SMTP_HOST=localhost SMTP_PORT=1025 SMTP_TLS=none \
cargo run --bin api

# Identity web UI — http://localhost:5173
npm run dev:web

# Mock Continuity app — http://localhost:5174
cd examples/continuity-mock
IDENTITY_ISSUER=http://localhost:8080 \
IDENTITY_CLIENT_ID=awapp_continuity_mock \
IDENTITY_CLIENT_SECRET=<from seed> \
IDENTITY_REDIRECT_URI=http://localhost:5174/callback \
IDENTITY_SA_CLIENT_ID=<from seed> \
IDENTITY_SA_CLIENT_SECRET=<from seed> \
npm run dev
```

The API auto-applies migrations at startup (`AUTO_MIGRATE=1` default) and
rate limits are stored in Valkey (`REDIS_URL`); without it the API falls back
to in-memory limits. Registration is limited to 3/hour/IP by default
(`REGISTER_RATE_LIMIT_PER_HOUR`); set it higher for development and e2e
runs, and flush Valkey between heavy test sessions. Email is delivered to **Mailpit** (web UI at
http://localhost:8025) when `SMTP_HOST` points at it; otherwise emails are
logged to the API console.

## Seed

```sh
cd apps/api
SEED_ADMIN_PASSWORD="ChangeMe-1234" cargo run --bin seed
```

Creates (idempotently): the admin user (`admin@arcticworks.dev`), the
`arcticworks` organization with built-in roles, the confidential OIDC client
`awapp_continuity_mock` (redirect `http://localhost:5174/callback`), and the
demo service account `continuity-backend`. The client secret and service
account credentials are printed once — copy them into the mock's environment.

`SEED_MEMBER_EMAILS` (comma-separated) adds extra members to the seeded
organization: accounts are created as verified users when missing, and each
is assigned the demo "Document Reader" role (with
`continuity.document.read`) so the mock Continuity permission check shows
ALLOWED. Applications are org-scoped — a user must be a member of the
application's organization to sign in through it.

## The demonstration flow

With the stack running and seeded:

1. http://localhost:5174 → **Sign in with ArcticWorks**
2. Log in as `admin@arcticworks.dev` / `ChangeMe-1234` (first run: consent
   screen) — back in the mock you see the ID-token claims and the permission
   check `continuity.document.read → ALLOWED`.
3. Register a fresh account at http://localhost:5173/register, verify via the
   Mailpit link, create an organization, invite someone, and explore the
   admin shell (members, roles, applications, service accounts, devices,
   audit).

## Tests

```sh
# Rust unit + integration tests (needs the Postgres container; DATABASE_URL
# points at the compose database; sqlx::test creates isolated databases).
DATABASE_URL="postgres://identity:identity@localhost:5433/identity" \
  cargo test --manifest-path apps/api/Cargo.toml

# TypeScript SDK tests
npm run test:sdk

# Web app type-check
npm run check:web

# End-to-end (full stack must be running and seeded; registration and
# invitation rate limits are per IP — flush Valkey first if you run often):
podman exec arcticworks-identity-valkey-1 valkey-cli FLUSHDB
npx playwright install chromium   # once
cd e2e && npx playwright test
```

The e2e suite covers the complete demonstration: registration, email
verification, passkey setup (virtual authenticator), organization creation,
member invitation and acceptance, role assignment, OIDC login from the mock
Continuity app, permission checking, session revocation, device enrollment,
and the corresponding audit events — plus a UI isolation spec (Viewer and
non-member gating).

## Resetting

```sh
podman compose down -v   # wipe databases and volumes
podman compose up -d
```
