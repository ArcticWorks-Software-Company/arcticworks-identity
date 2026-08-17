-- 0002_orgs: organizations, memberships, invitations, teams.
CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    slug text NOT NULL UNIQUE,
    owner_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE sessions
    ADD CONSTRAINT sessions_current_org_fk
    FOREIGN KEY (current_org_id) REFERENCES organizations(id);

CREATE TABLE org_memberships (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id uuid,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    joined_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, user_id)
);
CREATE INDEX ON org_memberships(user_id);

CREATE TABLE invitations (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email citext NOT NULL,
    role_id uuid,
    token_hash text NOT NULL UNIQUE,
    invited_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX ON invitations(org_id);
CREATE INDEX ON invitations(email);

CREATE TABLE teams (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE team_members (
    id uuid PRIMARY KEY,
    team_id uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (team_id, user_id)
);
CREATE INDEX ON team_members(user_id);
