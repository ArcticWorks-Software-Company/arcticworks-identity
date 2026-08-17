-- 0004_oidc: OIDC clients, grants, authorization codes, refresh tokens,
-- access token records (jti allowlist) and signing keys.
CREATE TABLE oidc_clients (
    id uuid PRIMARY KEY,
    org_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    client_id text NOT NULL UNIQUE,
    client_secret_hash text,
    secret_preview text NOT NULL DEFAULT '',
    redirect_uris jsonb NOT NULL DEFAULT '[]'::jsonb,
    is_confidential boolean NOT NULL DEFAULT false,
    application_enabled boolean NOT NULL DEFAULT true,
    created_by uuid REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Secret rotation history; the current secret lives in oidc_clients.
CREATE TABLE oidc_client_secrets (
    id uuid PRIMARY KEY,
    client_id text NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    secret_hash text NOT NULL,
    preview text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE INDEX ON oidc_client_secrets(client_id);

CREATE TABLE oauth_grants (
    id uuid PRIMARY KEY,
    client_id text NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scopes jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    UNIQUE (client_id, user_id, org_id)
);
CREATE INDEX ON oauth_grants(user_id);

CREATE TABLE auth_codes (
    id uuid PRIMARY KEY,
    code_hash text NOT NULL UNIQUE,
    client_id text NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scopes jsonb NOT NULL,
    pkce_challenge text NOT NULL,
    redirect_uri text NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON auth_codes(client_id);

CREATE TABLE refresh_tokens (
    id uuid PRIMARY KEY,
    token_hash text NOT NULL UNIQUE,
    family_id uuid NOT NULL,
    rotated_from_id uuid,
    client_id text NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    actor_type text NOT NULL,
    actor_id uuid NOT NULL,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scopes jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    reuse_detected_at timestamptz
);
CREATE INDEX ON refresh_tokens(family_id);
CREATE INDEX ON refresh_tokens(actor_id);

CREATE TABLE access_token_records (
    jti uuid PRIMARY KEY,
    actor_type text NOT NULL,
    actor_id uuid NOT NULL,
    org_id uuid,
    client_id text,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX ON access_token_records(actor_id);
CREATE INDEX ON access_token_records(expires_at);

CREATE TABLE oidc_signing_keys (
    id uuid PRIMARY KEY,
    kid text NOT NULL UNIQUE,
    alg text NOT NULL DEFAULT 'RS256',
    private_key_pem text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);
