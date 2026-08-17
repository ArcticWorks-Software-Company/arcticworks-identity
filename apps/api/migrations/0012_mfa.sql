-- 0012_mfa: TOTP authenticator secrets (encrypted at rest) and single-use
-- login challenges for the second authentication step.
CREATE TABLE totp_secrets (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    nonce text NOT NULL,
    ciphertext text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    verified_at timestamptz,
    enabled_at timestamptz
);

CREATE TABLE mfa_challenges (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON mfa_challenges(user_id);
