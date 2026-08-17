# ArcticWorks Identity

Centralized identity and access platform for the ArcticWorks software ecosystem.

**Trust topology:** ArcticWorks Identity is the single trust root. It manages
three identity classes — **Humans**, **Services** (service accounts) and
**Devices** — and issues standards-compatible credentials (OIDC / OAuth 2.0,
WebAuthn) to ArcticWorks products. SecureNet, Continuity, Hub and any future
product authenticate **directly through Identity**; no product depends on
another product for authentication. Identity contains no product-specific
business logic.

## Repository layout

| Path | Contents |
|---|---|
| `apps/api` | Rust (Axum) backend — accounts, orgs/teams, RBAC, OIDC, passkeys, machine identities, audit |
| `apps/web` | SvelteKit frontend on the ArcticWorks design system |
| `packages/identity-sdk` | TypeScript SDK for ArcticWorks applications |
| `examples/continuity-mock` | Mock product app demonstrating OIDC login and permission checks |
| `e2e` | Playwright end-to-end suite (the full demonstration flow) |
| `docs` | Architecture, threat model, development and deployment guides |
| `compose.yaml` | Local development infrastructure (Postgres, Valkey, Mailpit) |

## Quick start

See [docs/development.md](docs/development.md) for the full guide. Short form:

```sh
docker compose up -d          # postgres + valkey + mailpit
npm install                   # install workspace dependencies
npm run db:migrate            # apply database migrations
npm run db:seed               # dev administrator + test OIDC client
npm run dev:api               # API on http://localhost:8080
npm run dev:web               # Identity UI on http://localhost:5173
npm run dev:mock              # mock product app on http://localhost:5174
```

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Development](docs/development.md)
- [Deployment](docs/deployment.md)

## License

MIT. See [LICENSE](LICENSE).
