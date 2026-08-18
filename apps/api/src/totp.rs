//! TOTP two-factor authentication (RFC 6238, SHA-1, 30-second period,
//! 6 digits). Secrets are AES-256-GCM encrypted at rest with a key from
//! `TOTP_ENC_KEY` (ephemeral per process when unset — development only).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::audit::{self, ActorType, AuditEvent};
use crate::authn::Authed;
use crate::config::Config;
use crate::correlation::HttpMeta;
use crate::error::{ApiError, ApiResult, MapInternal};
use crate::ids::new_id;
use crate::state::AppState;
use crate::tokens::{hash_token, random_token, tokens_equal};

const RL_TOTP_VERIFY_ACCOUNT: (u32, u64) = (5, 900); // 5 per 15 min per account
const MFA_CHALLENGE_TTL_MINUTES: i64 = 5;

// ------------------------------------------------------------------ routes

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/account/totp", get(totp_status).delete(disable_totp))
        .route("/api/account/totp/setup", post(setup_totp))
        .route("/api/account/totp/verify", post(verify_totp))
}

// ------------------------------------------------------------------- crypto

/// Build the TOTP encryption cipher from configuration. Decodes the
/// configured base64 key; falls back to an ephemeral key (development) with
/// a warning so a missing key never silently disables the feature.
pub fn cipher_from_config(config: &Config) -> Aes256Gcm {
    match config.totp_enc_key.as_deref() {
        Some(encoded) => match decode_enc_key(encoded) {
            Some(key) => Aes256Gcm::new_from_slice(&key).expect("32-byte key"),
            None => {
                tracing::warn!("TOTP_ENC_KEY is not valid base64(32 bytes); using an ephemeral key");
                ephemeral_cipher()
            }
        },
        None => {
            tracing::warn!("TOTP_ENC_KEY is not set; TOTP secrets will be lost on restart (development only)");
            ephemeral_cipher()
        }
    }
}

fn decode_enc_key(encoded: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    bytes.try_into().ok()
}

fn ephemeral_cipher() -> Aes256Gcm {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut key);
    Aes256Gcm::new_from_slice(&key).expect("32-byte key")
}

/// Generate a fresh 20-byte TOTP secret (160-bit, RFC 4226).
pub fn generate_secret() -> Vec<u8> {
    let mut secret = [0u8; 20];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret);
    secret.to_vec()
}

/// RFC 4226 HOTP value with the configured digit count.
pub fn totp_value(secret: &[u8], counter: u64, digits: u32) -> u32 {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha1::Sha1> as hmac::Mac>::new_from_slice(secret)
        .expect("hmac accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;
    bin % 10u32.pow(digits)
}

/// Codes valid right now: current, previous and next 30-second window
/// (accepts modest clock skew).
pub fn current_codes(secret: &[u8]) -> Vec<String> {
    let counter = chrono::Utc::now().timestamp().max(0) as u64 / 30;
    let mut codes = vec![totp_value(secret, counter, 6)];
    if counter > 0 {
        codes.push(totp_value(secret, counter - 1, 6));
    }
    codes.push(totp_value(secret, counter + 1, 6));
    codes.iter().map(|c| format!("{c:06}")).collect()
}

/// Verify a submitted code against the current code window (constant-time).
pub fn verify_code(secret: &[u8], code: &str) -> bool {
    current_codes(secret)
        .iter()
        .any(|candidate| tokens_equal(candidate, code))
}

pub fn base32_encode(bytes: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(bytes)
}

pub fn base32_decode(value: &str) -> Option<Vec<u8>> {
    data_encoding::BASE32_NOPAD.decode(value.trim().as_bytes()).ok()
}

pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        urlencode(issuer),
        urlencode(account),
        base32_encode(secret),
        urlencode(issuer),
    )
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn encrypt_secret(cipher: &Aes256Gcm, plaintext: &[u8]) -> ApiResult<(String, String)> {
    use base64::Engine;
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| ApiError::internal("encrypt totp secret", e))?;
    let enc = base64::engine::general_purpose::STANDARD;
    Ok((enc.encode(nonce_bytes), enc.encode(ciphertext)))
}

pub fn decrypt_secret(
    cipher: &Aes256Gcm,
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> ApiResult<Vec<u8>> {
    use base64::Engine;
    let enc = base64::engine::general_purpose::STANDARD;
    let nonce_bytes = enc
        .decode(nonce_b64)
        .map_err(|e| ApiError::internal("decode totp nonce", e))?;
    let ciphertext = enc
        .decode(ciphertext_b64)
        .map_err(|e| ApiError::internal("decode totp ciphertext", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|e| ApiError::internal("decrypt totp secret", e))
}

// ------------------------------------------------------------------ queries

#[derive(sqlx::FromRow)]
struct TotpRow {
    nonce: String,
    ciphertext: String,
    created_at: chrono::DateTime<chrono::Utc>,
    enabled_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// True when the user has an enabled second factor.
pub async fn is_enabled(pool: &sqlx::PgPool, user_id: Uuid) -> ApiResult<bool> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM totp_secrets WHERE user_id = $1 AND enabled_at IS NOT NULL)",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_internal("check totp status")
}

/// Create a single-use MFA login challenge; returns the plaintext token.
pub async fn create_login_challenge(state: &AppState, user_id: Uuid) -> ApiResult<String> {
    let token = random_token();
    sqlx::query(
        r#"
        INSERT INTO mfa_challenges (id, user_id, token_hash, expires_at)
        VALUES ($1, $2, $3, now() + make_interval(mins => $4::int))
        "#,
    )
    .bind(new_id())
    .bind(user_id)
    .bind(hash_token(&token))
    .bind(MFA_CHALLENGE_TTL_MINUTES)
    .execute(&state.pool)
    .await
    .map_internal("create mfa challenge")?;
    Ok(token)
}

/// Resolve and consume a login challenge; returns the user id.
pub async fn consume_login_challenge(state: &AppState, token: &str) -> ApiResult<Option<Uuid>> {
    let user_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        UPDATE mfa_challenges SET used_at = now()
        WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
        RETURNING user_id
        "#,
    )
    .bind(hash_token(token))
    .fetch_optional(&state.pool)
    .await
    .map_internal("consume mfa challenge")?;
    Ok(user_id)
}

/// Verify the user's TOTP code against their enabled secret.
pub async fn verify_user_code(state: &AppState, user_id: Uuid, code: &str) -> ApiResult<bool> {
    let row = sqlx::query_as::<_, TotpRow>(
        "SELECT nonce, ciphertext, created_at, enabled_at FROM totp_secrets WHERE user_id = $1 AND enabled_at IS NOT NULL",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load totp secret")?;
    let Some(row) = row else {
        return Ok(false);
    };
    let secret = decrypt_secret(&state.totp_key, &row.nonce, &row.ciphertext)?;
    Ok(verify_code(&secret, code))
}

// ----------------------------------------------------------------- handlers

#[derive(Deserialize)]
struct VerifyTotpReq {
    code: String,
}

/// Get the user's TOTP status.
async fn totp_status(State(state): State<AppState>, authed: Authed) -> ApiResult<Response> {
    let row = sqlx::query_as::<_, TotpRow>(
        "SELECT nonce, ciphertext, created_at, enabled_at FROM totp_secrets WHERE user_id = $1",
    )
    .bind(authed.0.user.id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load totp status")?;
    Ok(Json(serde_json::json!({
        "enabled": row.as_ref().is_some_and(|r| r.enabled_at.is_some()),
        "pending": row.as_ref().is_some_and(|r| r.enabled_at.is_none()),
        "createdAt": row.as_ref().map(|r| r.created_at),
    }))
    .into_response())
}

/// Start TOTP setup: generate a secret, store it encrypted (pending), and
/// return it exactly once together with the otpauth URI.
async fn setup_totp(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    if is_enabled(&state.pool, authed.0.user.id).await? {
        return Err(ApiError::Conflict(
            "two-factor authentication is already enabled".into(),
        ));
    }

    let secret = generate_secret();
    let (nonce, ciphertext) = encrypt_secret(&state.totp_key, &secret)?;
    sqlx::query(
        r#"
        INSERT INTO totp_secrets (user_id, nonce, ciphertext)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id) DO UPDATE
          SET nonce = EXCLUDED.nonce, ciphertext = EXCLUDED.ciphertext,
              created_at = now(), verified_at = NULL, enabled_at = NULL
        "#,
    )
    .bind(authed.0.user.id)
    .bind(&nonce)
    .bind(&ciphertext)
    .execute(&state.pool)
    .await
    .map_internal("store totp secret")?;

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: "totp.setup_initiated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: Some("user"),
            target_id: Some(authed.0.user.id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    let encoded = base32_encode(&secret);
    let issuer = state.config.web_origin.clone();
    Ok(Json(serde_json::json!({
        "secret": encoded,
        "otpauthUri": otpauth_uri(&issuer, &authed.0.user.email, &secret),
    }))
    .into_response())
}

/// Verify a setup code and enable the second factor.
async fn verify_totp(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Json(req): Json<VerifyTotpReq>,
) -> ApiResult<Response> {
    let account_key = authed.0.user.id.to_string();
    if let Err(retry) = state
        .rl
        .check("totp-verify-account", &account_key, RL_TOTP_VERIFY_ACCOUNT.0, RL_TOTP_VERIFY_ACCOUNT.1)
        .await
    {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    let row = sqlx::query_as::<_, TotpRow>(
        "SELECT nonce, ciphertext, created_at, enabled_at FROM totp_secrets WHERE user_id = $1 AND enabled_at IS NULL",
    )
    .bind(authed.0.user.id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load pending totp secret")?
    .ok_or_else(|| ApiError::Validation("no pending two-factor setup".into()))?;

    let secret = decrypt_secret(&state.totp_key, &row.nonce, &row.ciphertext)?;
    if !verify_code(&secret, &req.code) {
        return Err(ApiError::Validation("invalid authentication code".into()));
    }

    sqlx::query(
        "UPDATE totp_secrets SET verified_at = now(), enabled_at = now() WHERE user_id = $1 AND enabled_at IS NULL",
    )
    .bind(authed.0.user.id)
    .execute(&state.pool)
    .await
    .map_internal("enable totp")?;

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: "totp.enabled",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: Some("user"),
            target_id: Some(authed.0.user.id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "enabled": true })).into_response())
}

/// Disable the second factor.
async fn disable_totp(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    let res = sqlx::query("DELETE FROM totp_secrets WHERE user_id = $1")
        .bind(authed.0.user.id)
        .execute(&state.pool)
        .await
        .map_internal("disable totp")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: "totp.disabled",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: Some("user"),
            target_id: Some(authed.0.user.id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 test vectors (SHA-1, secret = "12345678901234567890",
    /// base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ).
    #[test]
    fn rfc6238_sha1_vectors() {
        let secret = b"12345678901234567890";
        let expected: [(u64, u32); 6] = [
            (59, 94287082),
            (1111111109, 07081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ];
        for (counter, code) in expected {
            assert_eq!(
                totp_value(secret, counter / 30, 8),
                code,
                "counter {counter}"
            );
        }
    }

    #[test]
    fn code_window_accepts_skew_and_wrong_code_fails() {
        let secret = b"12345678901234567890";
        let counter = chrono::Utc::now().timestamp().max(0) as u64 / 30;
        let exact = format!("{:06}", totp_value(secret, counter, 6));
        assert!(current_codes(secret).contains(&exact));
        assert!(verify_code(secret, &exact));
        assert!(!verify_code(secret, "000000"));
    }

    #[test]
    fn secrets_roundtrip_through_encryption() {
        let config = Config::from_env().unwrap();
        let cipher = cipher_from_config(&config);
        let secret = generate_secret();
        let (nonce, ciphertext) = encrypt_secret(&cipher, &secret).unwrap();
        assert_ne!(ciphertext.as_bytes(), secret.as_slice());
        assert_eq!(decrypt_secret(&cipher, &nonce, &ciphertext).unwrap(), secret);
    }
}
