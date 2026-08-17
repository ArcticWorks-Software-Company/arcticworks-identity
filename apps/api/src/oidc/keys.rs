//! OIDC signing keys: RSA-2048 / RS256, generated at runtime, stored in the
//! database (PKCS#8 DER, base64url), rotatable. JWKS publishes active keys
//! plus keys retired within the last 24 hours (validation grace period).

use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult, MapInternal};
use crate::ids::new_id;

pub const KEY_GRACE_HOURS: i64 = 24;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SigningKeyRow {
    pub id: Uuid,
    pub kid: String,
    pub alg: String,
    pub private_key_der: String,
    pub public_n: String,
    pub public_e: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Load the active signing key, generating one on first boot.
pub async fn ensure_active_key(pool: &PgPool) -> ApiResult<SigningKeyRow> {
    if let Some(key) = active_key(pool).await? {
        return Ok(key);
    }
    let key = generate_and_store(pool).await?;
    tracing::info!(kid = %key.kid, "generated new OIDC signing key");
    Ok(key)
}

pub async fn active_key(pool: &PgPool) -> ApiResult<Option<SigningKeyRow>> {
    let key = sqlx::query_as::<_, SigningKeyRow>(
        "SELECT * FROM oidc_signing_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_internal("load active signing key")?;
    Ok(key)
}

/// Retire the current key (if any) and generate a fresh one.
pub async fn rotate_key(pool: &PgPool) -> ApiResult<SigningKeyRow> {
    sqlx::query("UPDATE oidc_signing_keys SET retired_at = now() WHERE retired_at IS NULL")
        .execute(pool)
        .await
        .map_internal("retire signing key")?;
    let key = generate_and_store(pool).await?;
    tracing::info!(kid = %key.kid, "rotated OIDC signing key");
    Ok(key)
}

async fn generate_and_store(pool: &PgPool) -> ApiResult<SigningKeyRow> {
    let (kid, der_b64, n_b64, e_b64) = generate_rsa_key()?;
    let id = new_id();
    sqlx::query(
        r#"
        INSERT INTO oidc_signing_keys (id, kid, alg, private_key_der, public_n, public_e)
        VALUES ($1, $2, 'RS256', $3, $4, $5)
        "#,
    )
    .bind(id)
    .bind(&kid)
    .bind(&der_b64)
    .bind(&n_b64)
    .bind(&e_b64)
    .execute(pool)
    .await
    .map_internal("store signing key")?;

    Ok(SigningKeyRow {
        id,
        kid,
        alg: "RS256".into(),
        private_key_der: der_b64,
        public_n: n_b64,
        public_e: e_b64,
        created_at: chrono::Utc::now(),
        retired_at: None,
    })
}

fn generate_rsa_key() -> ApiResult<(String, String, String, String)> {
    let mut rng = rand_core::OsRng;
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| ApiError::internal("generate RSA key", e))?;
    // ring (used by jsonwebtoken) requires PKCS#8 v1; the `rsa` crate emits
    // v2 by default, so wrap the PKCS#1 payload in a v1 envelope manually.
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let pkcs1 = private
        .to_pkcs1_der()
        .map_err(|e| ApiError::internal("encode RSA key", e))?;
    let pkcs8 = pkcs8_v1_envelope(pkcs1.as_bytes());

    let public = private.to_public_key();
    let n = public.n().to_bytes_be();
    let e = public.e().to_bytes_be();
    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    Ok((
        new_id().to_string(),
        enc.encode(&pkcs8),
        enc.encode(n),
        enc.encode(e),
    ))
}

/// Minimal DER builder for a PKCS#8 v1 PrivateKeyInfo wrapping PKCS#1 DER:
/// SEQUENCE { INTEGER 0, SEQUENCE { OID rsaEncryption, NULL }, OCTET STRING }
fn pkcs8_v1_envelope(pkcs1: &[u8]) -> Vec<u8> {
    const RSA_ENCRYPTION_ALGORITHM: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    fn der_len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else {
            let mut bytes = Vec::new();
            let mut v = n;
            while v > 0 {
                bytes.push((v & 0xff) as u8);
                v >>= 8;
            }
            bytes.reverse();
            let mut out = vec![0x80 | bytes.len() as u8];
            out.extend(bytes);
            out
        }
    }
    fn der_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_len(contents.len()));
        out.extend(contents);
        out
    }
    let mut inner = vec![0x02, 0x01, 0x00]; // version 0
    inner.extend_from_slice(&RSA_ENCRYPTION_ALGORITHM);
    inner.extend(der_tlv(0x04, pkcs1)); // OCTET STRING (PKCS#1)
    der_tlv(0x30, &inner) // SEQUENCE
}

/// jsonwebtoken signing key for a stored key row. The private key is stored
/// as PKCS#8 v1 DER; jsonwebtoken's PEM loader accepts it inside a PEM
/// envelope (its `from_rsa_der` does no parsing and ring requires PEM).
pub fn encoding_key(key: &SigningKeyRow) -> ApiResult<EncodingKey> {
    let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&key.private_key_der)
        .map_err(|e| ApiError::internal("decode signing key", e))?;
    EncodingKey::from_rsa_pem(&pem_encode("PRIVATE KEY", &der))
        .map_err(|e| ApiError::internal("load signing key", e))
}

/// Verification key built from the stored public components (no private key
/// material involved).
pub fn decoding_key(key: &SigningKeyRow) -> ApiResult<DecodingKey> {
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&key.public_n)
        .map_err(|e| ApiError::internal("decode key modulus", e))?;
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&key.public_e)
        .map_err(|e| ApiError::internal("decode key exponent", e))?;
    Ok(DecodingKey::from_rsa_raw_components(&n, &e))
}

/// PEM encode DER bytes (standard base64, 64 columns).
fn pem_encode(kind: &str, der: &[u8]) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {kind}-----\n").into_bytes();
    for chunk in b64.as_bytes().chunks(64) {
        out.extend_from_slice(chunk);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("-----END {kind}-----\n").as_bytes());
    out
}

/// JWKS document: active keys plus recently retired ones.
pub async fn jwks(pool: &PgPool) -> ApiResult<serde_json::Value> {
    let keys = sqlx::query_as::<_, SigningKeyRow>(
        r#"
        SELECT * FROM oidc_signing_keys
        WHERE retired_at IS NULL OR retired_at > now() - make_interval(hours => $1)
        ORDER BY created_at DESC
        "#,
    )
    .bind(KEY_GRACE_HOURS)
    .fetch_all(pool)
    .await
    .map_internal("load signing keys for JWKS")?;

    let keys: Vec<serde_json::Value> = keys
        .into_iter()
        .map(|k| {
            serde_json::json!({
                "kty": "RSA",
                "use": "sig",
                "alg": k.alg,
                "kid": k.kid,
                "n": k.public_n,
                "e": k.public_e,
            })
        })
        .collect();

    Ok(serde_json::json!({ "keys": keys }))
}
