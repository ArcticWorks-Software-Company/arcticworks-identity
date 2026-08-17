-- 0013_device_flow: OAuth 2.0 Device Authorization Grant (RFC 8628).
CREATE TABLE device_authorizations (
    id uuid PRIMARY KEY,
    device_code_hash text NOT NULL UNIQUE,
    user_code_hash text NOT NULL UNIQUE,
    client_id text NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    org_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
    scopes jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    last_polled_at timestamptz,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON device_authorizations(client_id);
