//! OIDC token minting and validation (RS256).

use base64::Engine;
use jsonwebtoken::{decode, decode_header, encode, Algorithm, Header, Validation};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult, MapInternal};
use crate::ids::new_id;
use crate::oidc::keys;
use crate::state::AppState;
use crate::tokens::{hash_token, random_token, new_jti};

/// What a token is about to be minted for.
pub struct TokenRequest {
    pub actor_type: &'static str, // "user" | "service_account" | "device"
    pub actor_id: Uuid,
    pub org_id: Option<Uuid>,
    pub client_id: String,
    pub scopes: Vec<String>,
    /// OIDC user claims (id_token), when actor_type == "user".
    pub user: Option<UserClaims>,
    pub auth_time: Option<i64>,
    pub nonce: Option<String>,
}

pub struct UserClaims {
    pub sub: Uuid,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
}

#[derive(Serialize)]
struct AccessClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    jti: String,
    org: Option<String>,
    actor_type: String,
    scope: String,
}

#[derive(Serialize)]
struct IdClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    auth_time: Option<i64>,
    nonce: Option<String>,
    azp: String,
    at_hash: String,
    org: Option<String>,
    name: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
}

pub struct MintedTokens {
    pub access_token: String,
    pub expires_in: i64,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

/// Issue an access token and record its jti for revocation.
pub async fn mint_access_token(state: &AppState, req: &TokenRequest) -> ApiResult<(String, i64)> {
    let key = keys::ensure_active_key(&state.pool).await?;
    let now = chrono::Utc::now().timestamp();
    let exp = now + state.config.access_token_ttl.as_secs() as i64;
    let jti = new_jti();

    let claims = AccessClaims {
        iss: state.config.issuer().to_string(),
        sub: req.actor_id.to_string(),
        aud: req.client_id.clone(),
        exp,
        iat: now,
        jti: jti.to_string(),
        org: req.org_id.map(|o| o.to_string()),
        actor_type: req.actor_type.to_string(),
        scope: req.scopes.join(" "),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    let token = encode(&header, &claims, &keys::encoding_key(&key)?)
        .map_err(|e| ApiError::internal("mint access token", e))?;

    sqlx::query(
        r#"
        INSERT INTO access_token_records (jti, actor_type, actor_id, org_id, client_id, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(jti)
    .bind(req.actor_type)
    .bind(req.actor_id)
    .bind(req.org_id)
    .bind(&req.client_id)
    .bind(chrono::DateTime::from_timestamp(exp, 0).unwrap_or(chrono::Utc::now()))
    .execute(&state.pool)
    .await
    .map_internal("record access token")?;

    Ok((token, exp - now))
}

async fn mint_id_token(state: &AppState, req: &TokenRequest, access_token: &str) -> ApiResult<String> {
    let key = keys::ensure_active_key(&state.pool).await?;
    let now = chrono::Utc::now().timestamp();
    let exp = now + state.config.access_token_ttl.as_secs() as i64;

    let wants = |s: &str| req.scopes.iter().any(|x| x == s);
    let claims = IdClaims {
        iss: state.config.issuer().to_string(),
        sub: req.actor_id.to_string(),
        aud: req.client_id.clone(),
        exp,
        iat: now,
        auth_time: req.auth_time,
        nonce: req.nonce.clone(),
        azp: req.client_id.clone(),
        at_hash: at_hash(access_token),
        org: req.org_id.map(|o| o.to_string()),
        name: if wants("profile") { req.user.as_ref().map(|u| u.name.clone()) } else { None },
        email: if wants("email") { req.user.as_ref().map(|u| u.email.clone()) } else { None },
        email_verified: if wants("email") { req.user.as_ref().map(|u| u.email_verified) } else { None },
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    encode(&header, &claims, &keys::encoding_key(&key)?)
        .map_err(|e| ApiError::internal("mint id token", e))
}

/// Mint access (+ optional id/refresh) tokens.
pub async fn mint_tokens(
    state: &AppState,
    req: &TokenRequest,
    with_refresh: bool,
) -> ApiResult<MintedTokens> {
    let (access_token, expires_in) = mint_access_token(state, req).await?;

    let id_token = if req.actor_type == "user" {
        Some(mint_id_token(state, req, &access_token).await?)
    } else {
        None
    };

    let refresh_token = if with_refresh {
        Some(issue_refresh_token(state, req).await?)
    } else {
        None
    };

    Ok(MintedTokens {
        access_token,
        expires_in,
        id_token,
        refresh_token,
    })
}

/// Store a new refresh token (rotation chains via `rotated_from_id`).
pub async fn issue_refresh_token(state: &AppState, req: &TokenRequest) -> ApiResult<String> {
    let token = random_token();
    let expires_at = chrono::Utc::now() + chrono::Duration::from_std(state.config.refresh_token_ttl).unwrap_or_default();
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens
            (id, token_hash, family_id, client_id, actor_type, actor_id, org_id, scopes, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(new_id())
    .bind(hash_token(&token))
    .bind(new_id())
    .bind(&req.client_id)
    .bind(req.actor_type)
    .bind(req.actor_id)
    .bind(req.org_id)
    .bind(serde_json::to_value(&req.scopes).unwrap_or_else(|_| serde_json::json!([])))
    .bind(expires_at)
    .execute(&state.pool)
    .await
    .map_internal("issue refresh token")?;
    Ok(token)
}

/// `at_hash` per OIDC Core: base64url(SHA-256(access_token))[0..16].
pub fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
}

/// SHA-256 base64url of a plaintext value — used for PKCE S256 verification.
pub fn sha256_b64url(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

// ---------------------------------------------------------------- validation

#[derive(Debug, Clone)]
pub struct ValidatedToken {
    pub jti: Uuid,
    pub sub: Uuid,
    pub actor_type: String,
    pub actor_id: Uuid,
    pub org_id: Option<Uuid>,
    pub client_id: String,
    pub scopes: Vec<String>,
}

/// Validate an access token: signature, issuer, expiry, jti revocation.
/// `expected_audience` is optional (userinfo accepts any of our clients;
/// the permission-check endpoint requires the caller's client id).
pub async fn validate_access_token(
    state: &AppState,
    token: &str,
    expected_audience: Option<&str>,
) -> ApiResult<ValidatedToken> {
    let header = decode_header(token).map_err(|_| ApiError::Unauthorized)?;
    if header.alg != Algorithm::RS256 {
        return Err(ApiError::Unauthorized);
    }

    // First boot may not have a key yet. Keep verification aligned with JWKS:
    // active plus recently retired keys, selected by kid when present.
    keys::ensure_active_key(&state.pool).await?;
    let verification_keys = keys::verification_keys(&state.pool).await?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[state.config.issuer().to_string()]);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    // Audience is checked explicitly below (optional expected audience).
    validation.validate_aud = false;

    let data = verification_keys
        .iter()
        .filter(|key| header.kid.as_ref().is_none_or(|kid| kid == &key.kid))
        .find_map(|key| {
            let decoding_key = keys::decoding_key(key).ok()?;
            decode::<serde_json::Value>(token, &decoding_key, &validation).ok()
        })
        .ok_or_else(|| {
            tracing::warn!(kid = header.kid.as_deref().unwrap_or("missing"), "access token validation failed");
            ApiError::Unauthorized
        })?;
    let claims = &data.claims;

    let aud = claims.get("aud").and_then(|v| v.as_str()).unwrap_or("");
    if let Some(expected) = expected_audience {
        if aud != expected {
            return Err(ApiError::Unauthorized);
        }
    }
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(ApiError::Unauthorized)?;
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(ApiError::Unauthorized)?;
    let actor_type = claims.get("actor_type").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let org_id = claims
        .get("org")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    let client_id = aud.to_string();
    let scopes = claims
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|s| s.split(' ').map(ToOwned::to_owned).collect())
        .unwrap_or_default();

    // The jti table is an allowlist as well as the RFC 7009 revocation store.
    let record = sqlx::query_as::<_, (
        String,
        Uuid,
        Option<Uuid>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    )>(
        r#"
        SELECT actor_type, actor_id, org_id, client_id, expires_at, revoked_at
        FROM access_token_records
        WHERE jti = $1
        "#,
    )
    .bind(jti)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load access token record")?
    .ok_or(ApiError::Unauthorized)?;
    if record.5.is_some()
        || record.4 <= chrono::Utc::now()
        || record.0 != actor_type
        || record.1 != sub
        || record.2 != org_id
        || record.3.as_deref() != Some(client_id.as_str())
    {
        return Err(ApiError::Unauthorized);
    }

    let Some(actor_org) = org_id else {
        return Err(ApiError::Unauthorized);
    };
    let actor_active = match actor_type.as_str() {
        "user" => crate::rbac::is_active_member(&state.pool, sub, actor_org).await?,
        "service_account" => {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM service_accounts WHERE id = $1 AND org_id = $2 AND status = 'active')",
            )
            .bind(sub)
            .bind(actor_org)
            .fetch_one(&state.pool)
            .await
            .map_internal("check service account status")?
        }
        "device" => {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1 AND org_id = $2 AND status = 'active')",
            )
            .bind(sub)
            .bind(actor_org)
            .fetch_one(&state.pool)
            .await
            .map_internal("check device status")?
        }
        _ => false,
    };
    if !actor_active {
        return Err(ApiError::Unauthorized);
    }

    Ok(ValidatedToken {
        jti,
        sub,
        actor_type,
        actor_id: sub,
        org_id,
        client_id,
        scopes,
    })
}

/// Validate an ID token presented as an RP-initiated logout hint.
/// Returns `(client_id, subject)`.
pub async fn validate_id_token_hint(state: &AppState, token: &str) -> ApiResult<(String, Uuid)> {
    let header = decode_header(token).map_err(|_| ApiError::Unauthorized)?;
    if header.alg != Algorithm::RS256 {
        return Err(ApiError::Unauthorized);
    }
    keys::ensure_active_key(&state.pool).await?;
    let verification_keys = keys::verification_keys(&state.pool).await?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[state.config.issuer().to_string()]);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.validate_aud = false;

    let data = verification_keys
        .iter()
        .filter(|key| header.kid.as_ref().is_none_or(|kid| kid == &key.kid))
        .find_map(|key| {
            let decoding_key = keys::decoding_key(key).ok()?;
            decode::<serde_json::Value>(token, &decoding_key, &validation).ok()
        })
        .ok_or(ApiError::Unauthorized)?;

    let aud = data
        .claims
        .get("aud")
        .and_then(|v| v.as_str())
        .ok_or(ApiError::Unauthorized)?
        .to_string();
    let sub = data
        .claims
        .get("sub")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(ApiError::Unauthorized)?;
    Ok((aud, sub))
}

/// Look up a refresh token row by plaintext (hashed comparison).
pub async fn find_refresh_token<'e>(
    state: &'e AppState,
    token: &str,
) -> ApiResult<Option<RefreshTokenRow>> {
    let row = sqlx::query_as::<_, RefreshTokenRow>(
        r#"
        SELECT id, token_hash, family_id, rotated_from_id, client_id, actor_type,
               actor_id, org_id, scopes, created_at, expires_at, revoked_at, reuse_detected_at
        FROM refresh_tokens
        WHERE token_hash = $1
        "#,
    )
    .bind(hash_token(token))
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup refresh token")?;
    Ok(row)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshTokenRow {
    pub id: Uuid,
    pub token_hash: String,
    pub family_id: Uuid,
    pub rotated_from_id: Option<Uuid>,
    pub client_id: String,
    pub actor_type: String,
    pub actor_id: Uuid,
    pub org_id: Option<Uuid>,
    pub scopes: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub reuse_detected_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Revoke a user's OAuth tokens globally or within one organization.
pub async fn revoke_user_tokens(state: &AppState, user_id: Uuid, org_id: Option<Uuid>) -> ApiResult<()> {
    sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = now()
        WHERE actor_type = 'user' AND actor_id = $1
          AND ($2::uuid IS NULL OR org_id = $2)
          AND revoked_at IS NULL
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&state.pool)
    .await
    .map_internal("revoke user refresh tokens")?;

    sqlx::query(
        r#"
        UPDATE access_token_records
        SET revoked_at = now()
        WHERE actor_type = 'user' AND actor_id = $1
          AND ($2::uuid IS NULL OR org_id = $2)
          AND revoked_at IS NULL
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&state.pool)
    .await
    .map_internal("revoke user access tokens")?;
    Ok(())
}

pub enum RotateRefreshOutcome {
    Rotated(String),
    ReuseDetected,
    Revoked,
}

/// Rotate a refresh token under a row lock. A concurrent second use revokes
/// the whole family instead of minting a second successor.
pub async fn rotate_refresh_token(
    state: &AppState,
    old: &RefreshTokenRow,
) -> ApiResult<RotateRefreshOutcome> {
    let token = random_token();
    let expires_at = chrono::Utc::now() + chrono::Duration::from_std(state.config.refresh_token_ttl).unwrap_or_default();
    let new_id = new_id();

    let mut tx = state.pool.begin().await.map_internal("begin rotation tx")?;
    let revoked_at = sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
        "SELECT revoked_at FROM refresh_tokens WHERE id = $1 FOR UPDATE",
    )
        .bind(old.id)
        .fetch_optional(&mut *tx)
        .await
        .map_internal("rotate: lock old")?
        .ok_or(ApiError::Unauthorized)?;

    if revoked_at.is_some() {
        let was_rotated = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM refresh_tokens WHERE rotated_from_id = $1)",
        )
        .bind(old.id)
        .fetch_one(&mut *tx)
        .await
        .map_internal("rotate: check successor")?;
        if was_rotated {
            sqlx::query(
                r#"
                UPDATE refresh_tokens
                SET revoked_at = COALESCE(revoked_at, now()), reuse_detected_at = now()
                WHERE family_id = $1
                "#,
            )
            .bind(old.family_id)
            .execute(&mut *tx)
            .await
            .map_internal("rotate: revoke reused family")?;
            tx.commit().await.map_internal("commit reuse detection")?;
            return Ok(RotateRefreshOutcome::ReuseDetected);
        }
        tx.commit().await.map_internal("commit revoked rotation")?;
        return Ok(RotateRefreshOutcome::Revoked);
    }

    sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1")
        .bind(old.id)
        .execute(&mut *tx)
        .await
        .map_internal("rotate: revoke old")?;
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens
            (id, token_hash, family_id, rotated_from_id, client_id, actor_type,
             actor_id, org_id, scopes, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(new_id)
    .bind(hash_token(&token))
    .bind(old.family_id)
    .bind(old.id)
    .bind(&old.client_id)
    .bind(&old.actor_type)
    .bind(old.actor_id)
    .bind(old.org_id)
    .bind(&old.scopes)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_internal("rotate: insert new")?;
    tx.commit().await.map_internal("commit rotation")?;

    Ok(RotateRefreshOutcome::Rotated(token))
}
