-- 0011_end_session: RP-initiated logout redirect targets per client.
ALTER TABLE oidc_clients
    ADD COLUMN post_logout_redirect_uris jsonb NOT NULL DEFAULT '[]'::jsonb;
