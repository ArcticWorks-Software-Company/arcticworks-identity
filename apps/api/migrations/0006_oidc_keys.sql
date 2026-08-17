-- 0006: signing key public parts (for JWKS) and accurate column naming.
-- private_key_der holds PKCS#8 DER, base64url-encoded.
ALTER TABLE oidc_signing_keys RENAME COLUMN private_key_pem TO private_key_der;
ALTER TABLE oidc_signing_keys ADD COLUMN public_n text NOT NULL DEFAULT '';
ALTER TABLE oidc_signing_keys ADD COLUMN public_e text NOT NULL DEFAULT '';
