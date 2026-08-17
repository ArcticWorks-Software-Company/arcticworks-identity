-- 0003_rbac: roles and role permissions.
-- org_id NULL = system role template (seeded); per-organization roles are
-- copies with org_id set. Owner is implicit allow-all (is_owner = true).
CREATE TABLE roles (
    id uuid PRIMARY KEY,
    org_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    is_system boolean NOT NULL DEFAULT false,
    is_owner boolean NOT NULL DEFAULT false,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE role_permissions (
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission text NOT NULL,
    PRIMARY KEY (role_id, permission)
);

ALTER TABLE org_memberships
    ADD CONSTRAINT org_memberships_role_fk
    FOREIGN KEY (role_id) REFERENCES roles(id);

ALTER TABLE invitations
    ADD CONSTRAINT invitations_role_fk
    FOREIGN KEY (role_id) REFERENCES roles(id);

-- System role templates. Fixed UUIDs so seeding is idempotent.
INSERT INTO roles (id, org_id, name, is_system, is_owner, description) VALUES
    ('10000000-0000-7000-8000-000000000001', NULL, 'Owner',       true, true,  'Full control over the organization.'),
    ('10000000-0000-7000-8000-000000000002', NULL, 'Administrator', true, false, 'Manages members, roles, applications and settings.'),
    ('10000000-0000-7000-8000-000000000003', NULL, 'Member',      true, false, 'Default role for organization members.'),
    ('10000000-0000-7000-8000-000000000004', NULL, 'Viewer',      true, false, 'Read-only access.');
