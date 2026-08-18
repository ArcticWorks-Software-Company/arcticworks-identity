-- 0015_webhooks: org-scoped outbound webhooks for audit events.
CREATE TABLE webhook_endpoints (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    url text NOT NULL,
    secret_nonce text NOT NULL,
    secret_ciphertext text NOT NULL,
    secret_preview text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT true,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON webhook_endpoints(org_id);

CREATE TABLE webhook_deliveries (
    id uuid PRIMARY KEY,
    endpoint_id uuid NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_id uuid NOT NULL,
    event_type text NOT NULL,
    status text NOT NULL CHECK (status IN ('success', 'failed')),
    attempts integer NOT NULL DEFAULT 1,
    response_status integer,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON webhook_deliveries(endpoint_id, created_at DESC);

-- Existing Administrator roles gain the new permission (new organizations
-- pick it up from the seeded ADMIN_PERMS set at creation).
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, 'org.webhooks.manage'
FROM roles r
WHERE r.name = 'Administrator'
  AND NOT EXISTS (
      SELECT 1 FROM role_permissions rp
      WHERE rp.role_id = r.id AND rp.permission = 'org.webhooks.manage'
  );
