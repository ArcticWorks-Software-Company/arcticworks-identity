//! Browser session authentication.
//!
//! Sessions are opaque 32-byte tokens in HttpOnly cookies, stored hashed
//! (SHA-256) at rest. Sessions are revocable, expire after a fixed lifetime,
//! and carry the user's active organization.

use std::time::Duration;

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use axum::http::HeaderValue;
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::ids::new_id;
use crate::tokens::{hash_token, random_token};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub current_org_id: Option<Uuid>,
    pub last_reauth_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

/// A live session together with its user.
#[derive(Debug, Clone)]
pub struct SessionUser {
    pub session: SessionRow,
    pub user: UserRow,
}

pub struct Authed(pub SessionUser);

pub struct OptAuthed(pub Option<SessionUser>);

impl SessionUser {
    pub fn is_reauth_ok(&self, window: Duration) -> bool {
        match self.session.last_reauth_at {
            Some(t) => chrono::Utc::now().signed_duration_since(t) <= chrono::Duration::from_std(window).unwrap_or_default(),
            None => false,
        }
    }

    pub fn require_reauth(&self, config: &Config) -> ApiResult<()> {
        if self.is_reauth_ok(config.reauth_window) {
            Ok(())
        } else {
            Err(ApiError::ReauthRequired)
        }
    }
}

/// Create a session for a user and return the raw token the caller must set
/// as a cookie. Only the hash is stored.
pub async fn create_session(
    pool: &PgPool,
    config: &Config,
    user_id: Uuid,
    ip: Option<String>,
    user_agent: Option<String>,
) -> ApiResult<(SessionRow, String)> {
    let token = random_token();
    let expires_at = chrono::Utc::now() + chrono::Duration::from_std(config.session_max_age).unwrap_or_default();
    let id = new_id();
    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, token_hash, ip, user_agent, expires_at)
        VALUES ($1, $2, $3, $4::inet, $5, $6)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(hash_token(&token))
    .bind(&ip)
    .bind(&user_agent)
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(|e| ApiError::internal("create session", e))?;

    Ok((
        SessionRow {
            id,
            user_id,
            current_org_id: None,
            last_reauth_at: None,
            created_at: chrono::Utc::now(),
            expires_at,
            ip,
            user_agent,
        },
        token,
    ))
}

pub async fn revoke_session(pool: &PgPool, session_id: Uuid) -> ApiResult<()> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1")
        .bind(session_id)
        .execute(pool)
        .await
        .map_err(|e| ApiError::internal("revoke session", e))?;
    Ok(())
}

pub async fn revoke_all_user_sessions(pool: &PgPool, user_id: Uuid, except: Option<Uuid>) -> ApiResult<u64> {
    let mut q = sqlx::query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user_id);
    if let Some(except) = except {
        q = q.bind(except);
        q = sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL AND id <> $2",
        )
        .bind(user_id)
        .bind(except);
    }
    let res = q.execute(pool).await.map_err(|e| ApiError::internal("revoke sessions", e))?;
    Ok(res.rows_affected())
}

/// The session cookie value (Set-Cookie header).
pub fn session_cookie_value(config: &Config, token: &str) -> HeaderValue {
    let mut v = format!(
        "{}={}; Path=/; Max-Age={}; SameSite=Lax; HttpOnly",
        config.session_cookie_name,
        token,
        config.session_max_age.as_secs()
    );
    if config.secure_cookies {
        v.push_str("; Secure");
    }
    HeaderValue::from_str(&v).expect("cookie header is valid")
}

/// A Set-Cookie header that expires the session cookie immediately.
pub fn session_cookie_clear(config: &Config) -> HeaderValue {
    HeaderValue::from_str(&format!("{}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly", config.session_cookie_name))
        .expect("cookie header is valid")
}

fn read_session_cookie(parts: &Parts, config: &Config) -> Option<String> {
    let header = parts.headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in header.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == config.session_cookie_name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

async fn lookup_session(pool: &PgPool, token: &str) -> ApiResult<SessionUser> {
    let row = sqlx::query_as::<_, SessionUserRow>(
        r#"
        SELECT
            s.id, s.user_id, s.current_org_id, s.last_reauth_at,
            s.created_at, s.expires_at, s.ip::text AS ip, s.user_agent,
            u.email, u.display_name, u.email_verified_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = $1
          AND s.revoked_at IS NULL
          AND s.expires_at > now()
        "#,
    )
    .bind(hash_token(token))
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError::internal("lookup session", e))?
    .ok_or(ApiError::Unauthorized)?;

    Ok(SessionUser {
        session: SessionRow {
            id: row.id,
            user_id: row.user_id,
            current_org_id: row.current_org_id,
            last_reauth_at: row.last_reauth_at,
            created_at: row.created_at,
            expires_at: row.expires_at,
            ip: row.ip,
            user_agent: row.user_agent,
        },
        user: UserRow {
            id: row.user_id,
            email: row.email,
            display_name: row.display_name,
            email_verified_at: row.email_verified_at,
        },
    })
}

#[derive(sqlx::FromRow)]
struct SessionUserRow {
    id: Uuid,
    user_id: Uuid,
    current_org_id: Option<Uuid>,
    last_reauth_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    ip: Option<String>,
    user_agent: Option<String>,
    email: String,
    display_name: String,
    email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl FromRequestParts<crate::state::AppState> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::state::AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = read_session_cookie(parts, &state.config).ok_or(ApiError::Unauthorized)?;
        let session_user = lookup_session(&state.pool, &token).await?;
        throttle_last_seen(&state.pool, session_user.session.id);
        Ok(Authed(session_user))
    }
}

impl FromRequestParts<crate::state::AppState> for OptAuthed {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::state::AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = match read_session_cookie(parts, &state.config) {
            Some(t) => t,
            None => return Ok(OptAuthed(None)),
        };
        match lookup_session(&state.pool, &token).await {
            Ok(s) => {
                throttle_last_seen(&state.pool, s.session.id);
                Ok(OptAuthed(Some(s)))
            }
            Err(ApiError::Unauthorized) => Ok(OptAuthed(None)),
            Err(e) => Err(e),
        }
    }
}

/// Fire-and-forget refresh of last_seen_at, throttled to once per 5 minutes.
fn throttle_last_seen(pool: &PgPool, session_id: Uuid) {
    let pool = pool.clone();
    tokio::spawn(async move {
        let _ = sqlx::query(
            "UPDATE sessions SET last_seen_at = now() WHERE id = $1 AND last_seen_at < now() - interval '5 minutes'",
        )
        .bind(session_id)
        .execute(&pool)
        .await;
    });
}

#[derive(Deserialize)]
pub struct SetCurrentOrg {
    pub org_id: Uuid,
}

/// Mark the session's reauthentication timestamp (call after password entry
/// on sensitive actions).
pub async fn mark_reauth(pool: &PgPool, session_id: Uuid) -> ApiResult<()> {
    sqlx::query("UPDATE sessions SET last_reauth_at = now() WHERE id = $1")
        .bind(session_id)
        .execute(pool)
        .await
        .map_err(|e| ApiError::internal("mark reauth", e))?;
    Ok(())
}
