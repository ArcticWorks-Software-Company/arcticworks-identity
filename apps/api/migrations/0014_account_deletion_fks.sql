-- 0014_account_deletion_fks: let users erase their accounts. Records that
-- reference users for provenance only keep working after the account is
-- gone; organizational ownership remains a hard blocker (handled in code).
ALTER TABLE invitations ALTER COLUMN invited_by DROP NOT NULL;
ALTER TABLE invitations DROP CONSTRAINT invitations_invited_by_fkey;
ALTER TABLE invitations ADD CONSTRAINT invitations_invited_by_fkey
    FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE device_enrollment_tokens ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE device_enrollment_tokens DROP CONSTRAINT device_enrollment_tokens_created_by_fkey;
ALTER TABLE device_enrollment_tokens ADD CONSTRAINT device_enrollment_tokens_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE service_accounts DROP CONSTRAINT service_accounts_created_by_fkey;
ALTER TABLE service_accounts ADD CONSTRAINT service_accounts_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE devices DROP CONSTRAINT devices_enrolled_by_fkey;
ALTER TABLE devices ADD CONSTRAINT devices_enrolled_by_fkey
    FOREIGN KEY (enrolled_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_created_by_fkey;
ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
