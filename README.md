<div align="center">
	<h1>ArcticWorks Identity</h1>
	<p>Centralized identity and access platform for the ArcticWorks ecosystem.</p>
</div>

[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![CI](https://github.com/ArcticWorks-Software-Company/arcticworks-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/ArcticWorks-Software-Company/arcticworks-identity/actions/workflows/ci.yml)

## What is ArcticWorks Identity?

Identity is the single trust root for the ArcticWorks software ecosystem. It manages three identity classes: humans, services (service accounts), and devices. It issues standards-compatible credentials (OIDC / OAuth 2.0, WebAuthn) to ArcticWorks products, and every product authenticates directly through Identity. No product depends on another product for authentication. Identity contains no product-specific business logic.

### Features

- 👤 Accounts, organizations, teams, and role-based access control
- 🔐 OIDC and OAuth 2.0
- 🖐️ WebAuthn passkeys and machine identities
- 📜 Audit trail
- 🧩 TypeScript SDK for ArcticWorks applications

## Repository layout

| Path | Contents |
|---|---|
| `apps/api` | Rust (Axum) backend: accounts, orgs/teams, RBAC, OIDC, passkeys, machine identities, audit |
| `apps/web` | SvelteKit frontend on the ArcticWorks design system |
| `packages/identity-sdk` | TypeScript SDK for ArcticWorks applications |
| `examples/continuity-mock` | Mock product app demonstrating OIDC login and permission checks |
| `e2e` | Playwright end-to-end suite (the full demonstration flow) |
| `docs` | Architecture, threat model, development and deployment guides |
| `compose.yaml` | Local development infrastructure (Postgres, Valkey, Mailpit) |

## Installing and running

```sh
docker compose up -d          # postgres + valkey + mailpit
npm install                   # install workspace dependencies
npm run db:migrate            # apply database migrations
npm run db:seed               # dev administrator + test OIDC client
npm run dev:api               # API on http://localhost:8080
npm run dev:web               # Identity UI on http://localhost:5173
npm run dev:mock              # mock product app on http://localhost:5174
```

See [docs/development.md](docs/development.md) for the full guide.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Development](docs/development.md)
- [Deployment](docs/deployment.md)

## License

MIT. See [LICENSE](LICENSE).
