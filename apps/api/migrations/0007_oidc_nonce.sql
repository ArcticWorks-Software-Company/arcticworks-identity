-- 0007: authorization codes must carry the OIDC nonce through to the token
-- exchange (it is claimed in the id_token).
ALTER TABLE auth_codes ADD COLUMN nonce text;
