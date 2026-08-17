-- 0008_passkeys: WebAuthn credentials. (The passkeys table was referenced by
-- the application since day one but never migrated — this closes the gap.)
CREATE TABLE passkeys (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name text NOT NULL DEFAULT 'Passkey',
    credential_id text NOT NULL UNIQUE,
    public_key text NOT NULL,
    sign_count bigint NOT NULL DEFAULT 0,
    transports jsonb NOT NULL DEFAULT '[]'::jsonb,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON passkeys(user_id);
