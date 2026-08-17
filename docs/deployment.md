# ArcticWorks Identity — Production Deployment

## Topology

A single-host Docker Compose deployment is the reference topology:

```
                        clients
                           │
                    ┌──────▼──────┐
                    │    nginx    │  TLS termination, HTTP/2, rate limits
                    │  (443/80)   │
                    └──┬───────┬──┘
                       │       │
              ┌────────▼──┐  ┌─▼──────────┐
              │ web (5173)│  │ api (8080) │
              └───────────┘  └─┬──────────┘
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
              PostgreSQL    Valkey     SMTP relay
```

`compose.prod.yaml` builds the API and web images and runs them behind nginx
with TLS on a single origin (`identity.example.com`): the web app is served
at `/`, the API at `/api/*` via proxy — same origin, so the session cookie
works without CORS and `SameSite=Lax` fully applies.

## Configuration

| Variable | Production value | Notes |
|---|---|---|
| `DATABASE_URL` | `postgres://…` | Managed credential |
| `REDIS_URL` | `redis://valkey:6379` | Rate limiting; required in production |
| `PUBLIC_BASE_URL` | `https://identity.example.com` | OIDC issuer; never change casually |
| `WEB_ORIGIN` / `ALLOWED_ORIGINS` | `https://identity.example.com` | CORS allowlist |
| `API_BIND` | `0.0.0.0:8080` | Behind the proxy only |
| `SECURE_COOKIES` | `true` | HttpOnly + Secure + SameSite=Lax |
| `TRUST_PROXY` | `true` | Reads `X-Forwarded-For` for audit/rate limits |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_TLS` | real relay (`starttls`/`tls`) | Transactional email |
| `SMTP_FROM` | `ArcticWorks Identity <no-reply@…>` | |
| `RP_ID` | `identity.example.com` | WebAuthn relying party id |
| `RP_ORIGINS` | `https://identity.example.com` | Exact origins allowed to authenticate |
| `AUTO_MIGRATE` | `true` (or run `migrate` in a job) | Apply migrations before rolling out new app versions |
| `LOG_FORMAT` | `json` | Structured logs for the collector |
| `RUST_LOG` | `info,tower_http=info,sqlx=warn` | |

## Secrets

- Passwords, tokens, client secrets, recovery codes and credentials are
  stored hashed; nothing credential-shaped is ever written to logs.
- Service-account/device credentials and client secrets are shown exactly
  once at creation — store them in the consuming application's secret
  manager.
- The OIDC signing key lives in the database. Back up the database and keep
  key material with it; losing the key invalidates issued tokens.

## Backups and restore

- `pg_dump` the PostgreSQL volume on a schedule (point-in-time recovery via
  WAL archiving for production-grade setups).
- Valkey holds only ephemeral counters — no backup needed.
- Restore procedure: restore the dump into a fresh database, start the stack,
  verify `/healthz/ready`, then spot-check a token exchange.

## Upgrades

1. Build and push new images; pull on the host.
2. Run `migrate` (or let `AUTO_MIGRATE` apply migrations) before starting
   the new API — SQLx migrations are forward-only; never edit applied
   migration files (checksummed).
3. Rolling restart of api/web; nginx is stateless.

## Operations

### Signing key rotation

```sh
# Rotate the active OIDC signing key (new key signs immediately; JWKS keeps
# the retired key for 24 hours so in-flight tokens still validate).
cargo run --bin keys -- rotate
```

Verify after rotation: `GET /oidc/jwks.json` contains two keys (active +
retired), new tokens validate, and tokens minted before the rotation keep
validating until their expiry (validation honors the 24-hour grace window).

### Sign-out / user lifecycle

- Revoking a browser session is immediate (session row).
- Revoking an OAuth grant stops future tokens and revokes its refresh-token
  family.
- RFC 7009 revocation marks access-token jti records; UserInfo and the
  permission-check endpoint reject revoked tokens.
- Suspending a member denies all organization access immediately: the
  permission-check endpoint denies by default and the user's OAuth access
  and refresh tokens are revoked.
- Suspended service accounts and revoked devices are checked on every
  access-token validation, so already-issued bearer tokens stop working.

### Observability

- Structured JSON logs with `x-correlation-id` on every request and audit
  event; ship to your log pipeline.
- `/healthz` (liveness) and `/healthz/ready` (database connectivity) for the
  orchestrator/load balancer.
- The audit log is the security record — replicate it off-host.

## Capacity notes

The modular monolith scales vertically first. The only shared state is
PostgreSQL and Valkey, so horizontal scaling is a matter of running more API
replicas behind the proxy once database capacity allows; sessions, tokens
and rate limits are all database/Valkey-backed.
