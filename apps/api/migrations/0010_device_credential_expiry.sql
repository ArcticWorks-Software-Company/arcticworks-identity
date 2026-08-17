-- Persist the expiry that device enrollment and credential rotation already
-- return to callers. Existing credentials receive a full migration-time TTL
-- because their original rotation time was not stored.
ALTER TABLE devices ADD COLUMN credential_expires_at timestamptz;
UPDATE devices SET credential_expires_at = now() + interval '365 days';
ALTER TABLE devices ALTER COLUMN credential_expires_at SET NOT NULL;
