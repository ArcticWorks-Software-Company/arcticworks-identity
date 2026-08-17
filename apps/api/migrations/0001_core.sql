-- 0001_core: users, email verification, password reset, sessions,
-- recovery codes, audit events. All public identifiers are UUIDv7.
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id uuid PRIMARY KEY,
    email citext NOT NULL UNIQUE,
    display_name text NOT NULL DEFAULT '',
    password_hash text,
    email_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE email_verifications (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE INDEX ON email_verifications(user_id);

CREATE TABLE password_resets (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE INDEX ON password_resets(user_id);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    current_org_id uuid,
    ip inet,
    user_agent text,
    last_reauth_at timestamptz,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX ON sessions(user_id);
CREATE INDEX ON sessions(token_hash);
CREATE INDEX ON sessions(expires_at);

CREATE TABLE recovery_code_sets (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    invalidated_at timestamptz
);
CREATE INDEX ON recovery_code_sets(user_id);

CREATE TABLE recovery_codes (
    id uuid PRIMARY KEY,
    set_id uuid NOT NULL REFERENCES recovery_code_sets(id) ON DELETE CASCADE,
    code_hash text NOT NULL,
    used_at timestamptz
);
CREATE INDEX ON recovery_codes(set_id);

-- Append-only audit log. Rows are never updated or deleted by application code.
CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    correlation_id uuid NOT NULL,
    event_type text NOT NULL,
    actor_type text NOT NULL,
    actor_id uuid,
    org_id uuid,
    target_type text,
    target_id uuid,
    ip inet,
    user_agent text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON audit_events(org_id, occurred_at DESC);
CREATE INDEX ON audit_events(actor_id, occurred_at DESC);
CREATE INDEX ON audit_events(event_type, occurred_at DESC);
CREATE INDEX ON audit_events(actor_type, occurred_at DESC);
