-- 0005_machine: service accounts, device enrollment tokens, devices.
CREATE TABLE service_accounts (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    role_id uuid REFERENCES roles(id),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_by uuid REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON service_accounts(org_id);

CREATE TABLE service_account_credentials (
    id uuid PRIMARY KEY,
    service_account_id uuid NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    client_id text NOT NULL UNIQUE,
    secret_hash text NOT NULL,
    preview text NOT NULL,
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE INDEX ON service_account_credentials(service_account_id);

CREATE TABLE device_enrollment_tokens (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id uuid REFERENCES teams(id) ON DELETE SET NULL,
    token_hash text NOT NULL UNIQUE,
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz
);

CREATE TABLE devices (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id uuid REFERENCES teams(id) ON DELETE SET NULL,
    name text NOT NULL,
    client_id text NOT NULL UNIQUE,
    credential_hash text NOT NULL,
    secret_preview text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    enrolled_by uuid REFERENCES users(id),
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON devices(org_id);
