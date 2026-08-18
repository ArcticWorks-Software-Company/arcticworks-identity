# ArcticWorks Identity — Architecture

## 1. Overview

ArcticWorks Identity is the centralized identity and access platform for the
ArcticWorks software ecosystem. It authenticates **humans**, issues machine
identities for **services** (service accounts) and **devices**, organizes them
into organizations and teams, authorizes access through organization-scoped
roles and permissions, and issues standards-compatible credentials
(OIDC / OAuth 2.0, WebAuthn) to ArcticWorks products.

### 1.1 Trust topology

```
               Identity
          /       |       \
         /        |        \
    Humans    Services   Devices
         \        |        /
          \       |        /
            SecureNet
                 |
     ┌───────────┼───────────┐
     │           │           │
Continuity      Hub        Future Apps
```

Identity is the **single trust root**. SecureNet, Continuity, Hub and every
future product authenticate **directly through Identity** — via OIDC for
users and via service-account/device credentials for machine-to-machine
access — and ask Identity for permission decisions through the documented
check endpoint or the TypeScript SDK. **No product depends on another
product for authentication.** Identity contains no product-specific business
logic.

### 1.2 Guiding principles

- **Security first**: memory-hard password hashing, hashed-at-rest tokens,
  constant-time comparisons, deny-by-default authorization, minimal token
  lifetimes, reauthentication for sensitive actions.
- **Tenant isolation**: every organization-owned record carries an
  organization identifier; every query is tenant-scoped; an organization id
  supplied by a client is never trusted without verifying the principal's
  membership.
- **Standards compliance**: OIDC Core, OAuth 2.0 (RFC 6749), PKCE (RFC 7636),
  token revocation (RFC 7009), WebAuthn Level 2. No proprietary protocols.
- **Maintainability**: modular monolith with domain modules (`accounts`,
  `orgs`, `rbac`, `oidc`, `machine`, `audit`) that keep domain logic
  independent of HTTP handlers and database access.
- **UTC everywhere**; public identifiers are UUIDv7 (sortable, globally
  unique, never sequential).

## 2. Components

```
┌───────────────┐     ┌────────────────────┐     ┌──────────────────┐
│ Identity web  │     │  Mock Continuity   │     │  Product backends│
│ (SvelteKit)   │     │  (example client)  │     │  (SecureNet, …)  │
└───────┬───────┘     └─────────┬──────────┘     └────────┬─────────┘
        │ browser session       │ OIDC (PKCE)             │ client_credentials
        │ cookie (same-site)    │ (authorize → consent →  │ + permission checks
        ▼                       ▼ token → userinfo)       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        Identity API (Axum)                            │
│  accounts · passkeys · orgs · rbac · oidc · machine · audit          │
└───────┬──────────────────────────────┬───────────────────────────────┘
        │ SQL                           │ rate limiting (ephemeral)
        ▼                               ▼
┌───────────────┐              ┌────────────────┐
│  PostgreSQL   │              │  Valkey/Redis  │
└───────────────┘              └────────────────┘
        ▲
        │ SMTP
┌───────────────┐
│  Mailpit/dev  │
└───────────────┘
```

- **Identity API** (Rust, `apps/api`) — modular monolith. HTTP handlers are
  thin adapters; domain logic lives in modules; all persistence goes through
  SQLx against PostgreSQL. The API also serves the OIDC endpoints, JWKS and
  discovery.
- **Identity web** (SvelteKit, `apps/web`) — the human interface: public
  screens (login, registration, verification, password reset, passkey
  authentication, OAuth consent, invitation acceptance), personal account,
  and organization administration. Built on `@arcticworks/design` and
  `@arcticworks/svelte`; no component in those packages is re-implemented.
  The browser talks to the API directly with `credentials: include`; the
  session cookie is owned by the API.
- **TypeScript SDK** (`packages/identity-sdk`) — for ArcticWorks
  applications: OIDC login (PKCE) and the `PermissionClient` for
  organization-scoped permission checks.
- **Mock Continuity app** (`examples/continuity-mock`) — a product that
  authenticates users through Identity and demonstrates permission checks.
- **PostgreSQL** — the system of record. **Valkey** — only ephemeral state
  (rate-limit counters). **Mailpit** — development email capture.

## 3. Data model

All tables are defined in `apps/api/migrations/` (0001–0010). Highlights:

| Table | Purpose |
|---|---|
| `users` | Human accounts; password hash (Argon2id), email verification |
| `email_verifications`, `password_resets` | One-time tokens, hashed, expiring |
| `sessions` | Browser sessions: opaque token hash, active org, reauth timestamp |
| `recovery_code_sets`, `recovery_codes` | Recovery codes, hashed, single-use |
| `totp_secrets`, `mfa_challenges` | TOTP second factor: AES-256-GCM encrypted seeds; single-use login challenges |
| `organizations`, `org_memberships` | Tenancy root; membership carries role + status |
| `invitations`, `teams`, `team_members` | Invite-by-email flow; simple teams |
| `roles`, `role_permissions` | Org-scoped roles; built-ins per org: Owner, Administrator, Member, Viewer |
| `oidc_clients`, `oidc_client_secrets` | OIDC applications; current + rotated secrets |
| `oauth_grants`, `auth_codes` | User consent and single-use authorization codes |
| `refresh_tokens` | Rotating refresh tokens with family chains |
| `device_authorizations` | RFC 8628 device grants: pending/approved/denied, polling interval |
| `webhook_endpoints`, `webhook_deliveries` | Org webhooks: encrypted signing secrets; per-event delivery log |
| `access_token_records` | jti allowlist for RFC 7009 revocation |
| `oidc_signing_keys` | Rotatable RSA keys (PKCS#8 v1 DER in DB) |
| `service_accounts`, `service_account_credentials` | Machine identities with short-lived credentials |
| `device_enrollment_tokens`, `devices` | Single-use enrollment; enrolled device credentials |
| `audit_events` | Append-only security log |

### 3.1 Secrets at rest

Nothing credential-shaped is stored in plaintext: passwords (Argon2id),
session tokens, authorization codes, refresh tokens, invitation/verification
tokens, enrollment tokens, recovery codes and client secrets are all stored
as **SHA-256 hashes** and compared in constant time; TOTP secrets are stored
**AES-256-GCM encrypted**. Client secrets, service account credentials and
device credentials are shown exactly once at generation; the UI stores only
a preview suffix.

## 4. Session and token model

### 4.1 Browser sessions (Identity UI)

- Opaque 32-byte token in an `HttpOnly; SameSite=Lax; Secure (prod); Path=/`
  cookie; SHA-256 hash at rest; fixed 30-day lifetime; revocable.
- The session row stores the user's **active organization** (org switching).
- Sensitive actions (password change, session/passkey revocation, recovery
  codes, ownership transfer, secret rotation) require **reauthentication**
  within a 10-minute window (password entry recorded as `last_reauth_at`).

### 4.2 OAuth/OIDC tokens

- **Access tokens**: RS256 JWTs, 15-minute lifetime, minimal claims
  (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `org`, `actor_type`, `scope`)
  and a `kid` header. Every issued token is recorded (`access_token_records`),
  which serves as both the RFC 7009 revocation store and a jti allowlist.
  Validation checks the record (unrevoked, unexpired, claim-consistent) and
  the actor's live status (active membership for users, active service
  accounts, unrevoked devices), so suspension or revocation invalidates
  already-issued tokens.
- **ID tokens**: OIDC Core compliant (`auth_time`, `nonce`, `azp`,
  `at_hash`, profile/email claims per scope).
- **Refresh tokens**: opaque, rotating on every use (30-day sliding expiry),
  chained in families (`family_id` / `rotated_from_id`). Presenting an
  already-rotated token is treated as **reuse detection**: the whole family
  is revoked and the event is audited.
- **Authorization codes**: single-use, 5-minute lifetime, bound to the
  client, redirect URI, PKCE challenge and nonce.

### 4.3 Signing keys

RSA-2048 keys generated at runtime (PKCS#8 v1 DER stored in the database;
the `rsa` crate emits v2, which ring rejects — the v1 envelope is built
manually). The active key signs; JWKS publishes the active key plus keys
retired within the last 24 hours. Access-token verification honors the same
grace window (selected by `kid`), so rotation never invalidates in-flight
tokens. Rotation is a documented runbook step (`cargo run --bin keys --
rotate`, see deployment docs).

## 5. Authentication flows

### 5.1 Password login

`POST /api/auth/login` — rate limited per IP and per account; generic
failure message (no account enumeration); unverified accounts are refused
with `email_not_verified`; success sets the session cookie and audits
`auth.login`. Users with an enabled TOTP second factor receive a short-lived
single-use challenge instead of a session and complete the step at
`POST /api/auth/mfa`.

### 5.2 TOTP two-factor authentication

RFC 6238 (SHA-1, 30-second period, 6 digits). Setup requires reauthentication:
the API generates a 160-bit secret, returns it once as base32 (with an
`otpauth://` URI), and stores it **AES-256-GCM encrypted** (key from
`TOTP_ENC_KEY`; ephemeral with a warning when unset). A correct code within
the current/previous/next window enables the factor; verification is
rate-limited per account. Disabling requires reauthentication. Recovery
codes and passkey login remain available as alternative factors.

### 5.3 Passkeys (WebAuthn)

Attestation `none`; the platform advertises ES256, RS256 and EdDSA
credentials. Verification is implemented in pure Rust (`passkeys::webauthn`)
— no OpenSSL dependency: clientDataJSON binding (type/challenge/origin),
rpIdHash, user presence, COSE key parsing, signature verification
(P-256 / RSA PKCS#1 v1.5 / Ed25519), sign-counter regression detection, and
user-handle binding. Challenges are single-use and stored hashed server-side.

### 5.4 OIDC authorization code + PKCE
1. Product redirects the user to `GET /oidc/authorize` with
   `code_challenge` (S256 required).
2. The API validates the client and redirect URI (**exact registered match
   only**) and checks the user's active membership in the application's
   organization.
3. Not signed in → redirected to the Identity login page, returning to the
   exact authorize URL.
4. Consent is skipped when the user already granted the same or wider
   scopes (`oauth_grants`); otherwise the consent screen shows the
   application, organization, scopes and redirect target.
5. `POST /oidc/consent` issues a single-use code; `POST /oidc/token`
   verifies PKCE and issues access + id (+ refresh when `offline_access`)
   tokens. `GET /oidc/userinfo` returns scoped claims.

### 5.5 Device authorization (RFC 8628)

For CLI/headless clients:

1. `POST /oidc/device_authorization` (client id + secret for confidential
   clients) returns a `device_code`, an 8-character `user_code`,
   `verification_uri` (`{web}/device`) and `verification_uri_complete`.
   Codes are hashed at rest and expire after 15 minutes.
2. The user signs in at the verification page, sees the client name and
   requested scopes, and approves or denies (`POST /api/oidc/device-approve`;
   only active members of the client's organization can decide).
3. The client polls `POST /oidc/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code`; pending
   requests return `authorization_pending` (with `slow_down` enforcement
   per the polling interval) until approval mints tokens exactly once.

**Account deletion**: `DELETE /api/account` (reauthentication required)
erases the account — sessions, memberships, passkeys, TOTP seeds, grants
and OAuth tokens — after revoking OAuth tokens; users who own an
organization must transfer ownership first. Audit history is retained
without a foreign key to the user.

### 5.6 Machine authentication
- **Service accounts** and **devices** authenticate with
  `client_credentials` using their short-lived client id/secret pair
  (90-day service-account credentials, 365-day device credentials, both
  rotatable and revocable).
- **Device enrollment**: an administrator mints a single-use, 24-hour
  enrollment token; the device presents it at `POST /api/enroll` and
  receives its credentials, bound to the organization (and optionally a
  team).
- Permission checks for products go through
  `POST /api/v1/authorize/check` (documented in OpenAPI and the SDK) with
  the product's own access token; the caller may only ask about users in
  its own organization.

## 6. Authorization model

- Permission identifiers use `product.resource.action`
  (e.g. `continuity.document.read`, `org.members.manage`).
- Every organization seeds four built-in roles: **Owner** (implicit
  allow-all, transferable), **Administrator**, **Member**, **Viewer**;
  custom roles are org-scoped collections of permissions.
- **Every decision is scoped to an organization** and **denies by default**:
  membership must be active, the role must exist, the permission must be
  present. Suspended members and revoked devices get `false` everywhere.
- The permission-check endpoint and SDK are authoritative: access tokens are
  short-lived and stateless; the check performs full validation (signature,
  issuer, expiry, jti revocation, membership status, role).

## 7. Audit

Append-only `audit_events` with correlation ID, actor (user / service
account / device / system), organization, target, IP, user agent and JSON
metadata. Event types cover authentication (login, failures, passkey
login, reauth, recovery), credential lifecycle (passkeys, sessions,
recovery codes), organization administration (members, roles, teams,
invitations, ownership), applications (registration, secret rotation,
grants), machine identities (service accounts, enrollment, devices) and
OAuth events (token issuance, refresh, **reuse detection**, revocation,
PKCE failures).

**Webhooks**: organizations may register HTTP endpoints that receive every
org-scoped audit event asynchronously (one retry per delivery, never
blocking the audited request). Each delivery is signed with HMAC-SHA256
over the timestamp and raw body (`x-arcticworks-signature: t=…,v1=…`);
signing secrets are shown once, AES-256-GCM encrypted at rest, and
rotatable. URLs must be http(s) without embedded credentials. Delivery
attempts are logged per endpoint (`webhook_deliveries`) and the lifecycle
is itself audited (`webhook.created/updated/secret_rotated/deleted`).

## 8. Security mechanisms (summary)

- Argon2id (OWASP parameters: m=19 MiB, t=2, p=1) for passwords.
- All bearer tokens hashed at rest; constant-time comparisons.
- CSRF: `SameSite=Lax` cookies + CORS allowlist with credentials; state
  changes require `application/json` from the UI (no form CSRF surface).
- Rate limiting (Valkey fixed-window; in-memory fallback): login per IP and
  per account, registration, password reset, recovery, enrollment, token
  endpoint.
- Password reset is enumeration-safe (identical responses).
- Reauthentication gate for sensitive actions.
- Redirect URIs: exact string match against the registered list; http
  allowed only for loopback.
- Log hygiene: passwords, codes, tokens and secrets are never logged; a
  panic handler logs only the message, never request data.
- Correlation IDs on every request and audit event (`X-Correlation-ID`).

## 9. Tenancy rules (enforced)

1. Every organization-owned record carries `org_id`.
2. Every query for organization-owned data is tenant-scoped.
3. An organization id from a client is verified against the principal's
   membership before use.
4. Users may belong to multiple organizations (switching via the session's
   active organization).
5. Service accounts and devices belong to exactly one organization.

## 10. Operational characteristics

- Modular monolith: one deployable; domain modules are the seam for a
  future split if scale demands it.
- All times UTC (`timestamptz`); identifiers UUIDv7.
- Structured tracing (`tracing`/`tracing-subscriber`) with correlation ids;
  JSON or text logs via `LOG_FORMAT`.
- Readiness probe (`/healthz/ready`) checks database connectivity; the
  rate-limit store degrades gracefully to in-memory.

## 11. Testing strategy

- **Unit tests** (Rust): token hashing/equality, validation (email, slug,
  permission, redirect URI), rate-limit windows, WebAuthn primitives.
- **Integration tests** (`tests/`, real Postgres per test via `sqlx::test`):
  registration/verification/reset flows; **privilege escalation**;
  **tenant isolation**; **token revocation** (rotation, reuse detection,
  RFC 7009); PKCE; exact redirect matching; cookie flags; enumeration-safe
  reset; audit presence.
- **SDK tests** (vitest): PKCE, authorize URL building, token exchange,
  error mapping, permission client.
- **End-to-end** (Playwright, `e2e/`): the full demonstration — registration,
  verification, passkey setup (virtual authenticator), organization
  creation, invitation + acceptance, role assignment, OIDC login from the
  mock Continuity app, permission check, session revocation, device
  enrollment, audit events.
