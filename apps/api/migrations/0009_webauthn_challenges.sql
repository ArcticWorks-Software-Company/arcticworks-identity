-- 0009_webauthn_challenges: single-use WebAuthn ceremony challenges.
CREATE TABLE webauthn_challenges (
    id uuid PRIMARY KEY,
    challenge text NOT NULL,
    user_id uuid,
    purpose text NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX ON webauthn_challenges(challenge);
