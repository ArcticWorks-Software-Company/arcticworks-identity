//! Human accounts: registration, email verification, login/logout, password
//! reset, recovery codes, profile, security and session management.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::{Path, State};
use axum::http::header;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use utoipa::ToSchema;

use crate::audit::{self, ActorType, AuditEvent};
use crate::authn::{self, Authed, OptAuthed};
use crate::correlation::HttpMeta;
use crate::error::{ApiError, ApiResult, MapInternal};
use crate::ids::new_id;
use crate::state::AppState;
use crate::tokens::{hash_token, random_token};
use crate::util;

pub mod seed;

// ---------------------------------------------------------------- rate limits

const RL_LOGIN_IP: (u32, u64) = (10, 60); // 10 per minute per IP
const RL_LOGIN_ACCOUNT: (u32, u64) = (10, 900); // 10 per 15 min per account
// Registration limit per IP (per hour); configurable for development.
fn register_limit(state: &AppState) -> u32 {
    state.config.register_rate_limit_per_hour.max(1)
}
const RL_RESET_IP: (u32, u64) = (3, 900); // 3 per 15 min per IP
const RL_RECOVERY_IP: (u32, u64) = (5, 60); // 5 per minute per IP
const RL_RESEND_IP: (u32, u64) = (3, 3600); // 3 per hour per IP

// ------------------------------------------------------------- password hashing

pub fn hash_password(password: &str) -> ApiResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| ApiError::internal("hash password", e))
}

pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// ------------------------------------------------------------------- models

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserJson {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub email_verified: bool,
}

impl From<&authn::UserRow> for UserJson {
    fn from(u: &authn::UserRow) -> Self {
        UserJson {
            id: u.id,
            email: u.email.clone(),
            display_name: u.display_name.clone(),
            email_verified: u.email_verified_at.is_some(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionJson {
    pub id: Uuid,
    pub is_current: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

// ------------------------------------------------------------------- requests

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterReq {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub display_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyEmailReq {
    pub token: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginReq {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgotPasswordReq {
    pub email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordReq {
    pub token: String,
    pub password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryLoginReq {
    pub email: String,
    pub code: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReauthReq {
    pub password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordReq {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfileReq {
    pub display_name: String,
}

// -------------------------------------------------------------------- routes

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth/register", post(register))
        .route("/api/auth/verify-email", post(verify_email))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/forgot-password", post(forgot_password))
        .route("/api/auth/reset-password", post(reset_password))
        .route("/api/auth/recovery", post(recovery_login))
        .route("/api/auth/resend-verification", post(resend_verification))
        .route("/api/auth/reauth", post(reauth))
        .route("/api/auth/me", get(me))
        .route("/api/account/sessions", get(list_sessions))
        .route("/api/account/sessions/{id}/revoke", post(revoke_session))
        .route("/api/account/sessions/revoke-others", post(revoke_others))
        .route("/api/account/password", post(change_password))
        .route("/api/account/profile", post(update_profile))
        .route("/api/account/recovery-codes", get(generate_recovery_codes))
}

// ---------------------------------------------------------------- handlers

/// Register a new human account. A verification email is sent; the account
/// cannot log in until the email is verified.
#[utoipa::path(
    post,
    path = "/api/auth/register",
    request_body = RegisterReq,
    responses(
        (status = 201, description = "Account created (email verification pending)"),
        (status = 409, description = "Email already registered"),
        (status = 429, description = "Rate limited")
    )
)]
pub async fn register(
    State(state): State<AppState>,
    meta: HttpMeta,
    Json(req): Json<RegisterReq>,
) -> ApiResult<Response> {
    let email = req.email.trim().to_lowercase();
    let key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("register", &key, register_limit(&state), 3600).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }
    if !util::is_valid_email(&email) {
        return Err(ApiError::Validation("invalid email address".into()));
    }
    if !util::is_valid_password(&req.password) {
        return Err(ApiError::Validation("password must be between 8 and 128 characters".into()));
    }
    let display_name = if req.display_name.trim().is_empty() {
        email.split('@').next().unwrap_or("user").to_string()
    } else {
        req.display_name.trim().chars().take(100).collect()
    };

    let user_id = new_id();
    let password_hash = hash_password(&req.password)?;
    let inserted = sqlx::query(
        "INSERT INTO users (id, email, display_name, password_hash) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(&display_name)
    .bind(&password_hash)
    .execute(&state.pool)
    .await;

    if let Err(e) = inserted {
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            return Err(ApiError::Conflict("an account with this email already exists".into()));
        }
        return Err(ApiError::internal("register user", e));
    }

    issue_verification(&state, &meta, user_id, &email).await;
    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "account.register",
            actor_type: ActorType::User,
            actor_id: Some(user_id),
            org_id: None,
            target_type: Some("user"),
            target_id: Some(user_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    let user = UserJson {
        id: user_id,
        email,
        display_name,
        email_verified: false,
    };
    Ok((StatusCode::CREATED, Json(user)).into_response())
}

async fn verify_email(
    State(state): State<AppState>,
    meta: HttpMeta,
    Json(req): Json<VerifyEmailReq>,
) -> ApiResult<Response> {
    let row = sqlx::query_as::<_, (Uuid, Uuid, Option<chrono::DateTime<chrono::Utc>>)>(
        r#"
        SELECT ev.user_id, ev.id, ev.used_at
        FROM email_verifications ev
        WHERE ev.token_hash = $1
        "#,
    )
    .bind(hash_token(&req.token))
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup verification token")?;

    let Some((user_id, verification_id, used_at)) = row else {
        return Err(ApiError::TokenInvalid);
    };
    if used_at.is_some() {
        return Err(ApiError::TokenInvalid);
    }

    let res = sqlx::query_as::<_, (Uuid,)>(
        r#"
        UPDATE email_verifications ev
        SET used_at = now()
        FROM users u
        WHERE ev.token_hash = $1 AND ev.id = $2 AND ev.expires_at > now()
          AND u.id = $3 AND u.email_verified_at IS NULL
        RETURNING u.id
        "#,
    )
    .bind(hash_token(&req.token))
    .bind(verification_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("consume verification token")?;

    let Some((uid,)) = res else {
        return Err(ApiError::TokenInvalid);
    };

    sqlx::query("UPDATE users SET email_verified_at = now() WHERE id = $1")
        .bind(uid)
        .execute(&state.pool)
        .await
        .map_internal("mark email verified")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "account.email_verified",
            actor_type: ActorType::User,
            actor_id: Some(uid),
            org_id: None,
            target_type: Some("user"),
            target_id: Some(uid),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "verified": true })).into_response())
}

/// Log in with email and password. Sets the browser session cookie.
#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginReq,
    responses(
        (status = 200, description = "Logged in; session cookie set"),
        (status = 403, description = "Email not verified"),
        (status = 429, description = "Rate limited")
    )
)]
pub async fn login(
    State(state): State<AppState>,
    meta: HttpMeta,
    Json(req): Json<LoginReq>,
) -> ApiResult<Response> {
    let email = req.email.trim().to_lowercase();
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("login-ip", &ip_key, RL_LOGIN_IP.0, RL_LOGIN_IP.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }
    if let Err(retry) = state.rl.check("login-account", &email, RL_LOGIN_ACCOUNT.0, RL_LOGIN_ACCOUNT.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    let user = sqlx::query_as::<_, authn::UserRow>(
        "SELECT id, email, display_name, email_verified_at FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup user for login")?;

    let Some(user) = user else {
        // Constant-time-ish generic failure; never reveals account existence.
        return Err(ApiError::Validation("invalid email or password".into()));
    };
    let Some(password_hash) = sqlx::query_scalar::<_, Option<String>>("SELECT password_hash FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await
        .map_internal("load password hash")?
    else {
        return Err(ApiError::Validation("invalid email or password".into()));
    };

    if !verify_password(&req.password, &password_hash) {
        audit::record(
            &state.pool,
            &meta,
            AuditEvent {
                event_type: "auth.login_failed",
                actor_type: ActorType::User,
                actor_id: Some(user.id),
                org_id: None,
                target_type: None,
                target_id: None,
                metadata: serde_json::json!({ "reason": "bad_password" }),
            },
        )
        .await;
        return Err(ApiError::Validation("invalid email or password".into()));
    }

    if user.email_verified_at.is_none() {
        return Err(ApiError::EmailNotVerified);
    }

    let (session, token) = authn::create_session(
        &state.pool,
        &state.config,
        user.id,
        meta.ip.map(|ip| ip.to_string()),
        meta.user_agent.clone(),
    )
    .await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "auth.login",
            actor_type: ActorType::User,
            actor_id: Some(user.id),
            org_id: None,
            target_type: Some("session"),
            target_id: Some(session.id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    let mut resp = Json(serde_json::json!({ "user": UserJson::from(&user) })).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, authn::session_cookie_value(&state.config, &token));
    Ok(resp)
}

async fn logout(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
) -> ApiResult<Response> {
    authn::revoke_session(&state.pool, authed.0.session.id).await?;
    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "auth.logout",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: Some("session"),
            target_id: Some(authed.0.session.id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, authn::session_cookie_clear(&state.config));
    Ok(resp)
}

async fn forgot_password(
    State(state): State<AppState>,
    meta: HttpMeta,
    Json(req): Json<ForgotPasswordReq>,
) -> ApiResult<Response> {
    let email = req.email.trim().to_lowercase();
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("reset", &ip_key, RL_RESET_IP.0, RL_RESET_IP.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    // Identical response whether or not the account exists (no enumeration).
    let user = sqlx::query_as::<_, (Uuid, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT id, email_verified_at FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup user for password reset")?;

    if let Some((user_id, _verified)) = user {
        let token = random_token();
        sqlx::query(
            "INSERT INTO password_resets (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(new_id())
        .bind(user_id)
        .bind(hash_token(&token))
        .bind(chrono::Utc::now() + chrono::Duration::from_std(state.config.reset_ttl).unwrap_or_default())
        .execute(&state.pool)
        .await
        .map_internal("store password reset token")?;

        let link = format!("{}/reset-password?token={}", state.config.web_origin, token);
        let _ = state
            .mailer
            .send(&email, "Reset your ArcticWorks password", reset_email_html(&link))
            .await;

        audit::record(
            &state.pool,
            &meta,
            AuditEvent {
                event_type: "auth.reset_requested",
                actor_type: ActorType::User,
                actor_id: Some(user_id),
                org_id: None,
                target_type: Some("user"),
                target_id: Some(user_id),
                metadata: serde_json::json!({}),
            },
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

async fn reset_password(
    State(state): State<AppState>,
    meta: HttpMeta,
    Json(req): Json<ResetPasswordReq>,
) -> ApiResult<Response> {
    if !util::is_valid_password(&req.password) {
        return Err(ApiError::Validation("password must be between 8 and 128 characters".into()));
    }

    let row = sqlx::query_as::<_, (Uuid, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT user_id, used_at FROM password_resets WHERE token_hash = $1",
    )
    .bind(hash_token(&req.token))
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup reset token")?;

    let Some((user_id, used_at)) = row else {
        return Err(ApiError::TokenInvalid);
    };
    if used_at.is_some() {
        return Err(ApiError::TokenInvalid);
    }

    let consumed = sqlx::query(
        "UPDATE password_resets SET used_at = now() WHERE token_hash = $1 AND expires_at > now() AND used_at IS NULL",
    )
    .bind(hash_token(&req.token))
    .execute(&state.pool)
    .await
    .map_internal("consume reset token")?;
    if consumed.rows_affected() == 0 {
        return Err(ApiError::TokenInvalid);
    }

    let password_hash = hash_password(&req.password)?;
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&password_hash)
        .bind(user_id)
        .execute(&state.pool)
        .await
        .map_internal("set new password")?;

    // Revoke every session: a reset means the previous session may be hostile.
    authn::revoke_all_user_sessions(&state.pool, user_id, None).await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "account.password_reset",
            actor_type: ActorType::User,
            actor_id: Some(user_id),
            org_id: None,
            target_type: Some("user"),
            target_id: Some(user_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn resend_verification(
    State(state): State<AppState>,
    meta: HttpMeta,
    Json(req): Json<ForgotPasswordReq>,
) -> ApiResult<Response> {
    let email = req.email.trim().to_lowercase();
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("resend-verify", &ip_key, RL_RESEND_IP.0, RL_RESEND_IP.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    let user = sqlx::query_as::<_, (Uuid, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT id, email_verified_at FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup user for resend")?;

    if let Some((user_id, verified)) = user {
        if verified.is_none() {
            issue_verification(&state, &meta, user_id, &email).await;
        }
    }
    // Always succeed: no enumeration.
    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

async fn reauth(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Json(req): Json<ReauthReq>,
) -> ApiResult<Response> {
    let password_hash = sqlx::query_scalar::<_, Option<String>>("SELECT password_hash FROM users WHERE id = $1")
        .bind(authed.0.user.id)
        .fetch_one(&state.pool)
        .await
        .map_internal("load password hash")?;

    let ok = password_hash.as_deref().is_some_and(|h| verify_password(&req.password, h));
    if !ok {
        return Err(ApiError::Validation("invalid password".into()));
    }

    authn::mark_reauth(&state.pool, authed.0.session.id).await?;
    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "auth.reauth",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: Some("session"),
            target_id: Some(authed.0.session.id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Current session: user, memberships and the active organization.
#[utoipa::path(
    get,
    path = "/api/auth/me",
    responses(
        (status = 200, description = "Current user and memberships"),
        (status = 401, description = "Not authenticated")
    ),
    security(("sessionCookie" = []))
)]
pub async fn me(State(state): State<AppState>, authed: OptAuthed) -> ApiResult<Response> {
    match authed.0 {
        Some(su) => {
            let memberships =
                crate::orgs::list_memberships(&state.pool, su.user.id, su.session.current_org_id).await?;
            Ok(Json(serde_json::json!({
                "user": UserJson::from(&su.user),
                "currentOrgId": su.session.current_org_id,
                "memberships": memberships,
            }))
            .into_response())
        }
        None => Err(ApiError::Unauthorized),
    }
}

#[derive(Debug, sqlx::FromRow)]
struct SessionRowJson {
    id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    last_seen_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    ip: Option<String>,
    user_agent: Option<String>,
}

async fn list_sessions(State(state): State<AppState>, authed: Authed) -> ApiResult<Response> {
    let rows = sqlx::query_as::<_, SessionRowJson>(
        r#"
        SELECT id, created_at, last_seen_at, expires_at, ip::text AS ip, user_agent
        FROM sessions
        WHERE user_id = $1 AND revoked_at IS NULL
        ORDER BY created_at DESC
        "#,
    )
    .bind(authed.0.user.id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list sessions")?;

    let sessions: Vec<SessionJson> = rows
        .into_iter()
        .map(|r| SessionJson {
            id: r.id,
            is_current: r.id == authed.0.session.id,
            created_at: r.created_at,
            last_seen_at: r.last_seen_at,
            expires_at: r.expires_at,
            ip: r.ip,
            user_agent: r.user_agent,
        })
        .collect();

    Ok(Json(serde_json::json!({ "sessions": sessions })).into_response())
}

async fn revoke_session(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    if id == authed.0.session.id {
        return Err(ApiError::Validation("use logout to end the current session".into()));
    }
    let res = sqlx::query(
        "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(authed.0.user.id)
    .execute(&state.pool)
    .await
    .map_internal("revoke session")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "session.revoke",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: Some("session"),
            target_id: Some(id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn revoke_others(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    authn::revoke_all_user_sessions(&state.pool, authed.0.user.id, Some(authed.0.session.id)).await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "session.revoke_others",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: None,
            target_id: None,
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn change_password(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Json(req): Json<ChangePasswordReq>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    if !util::is_valid_password(&req.new_password) {
        return Err(ApiError::Validation("password must be between 8 and 128 characters".into()));
    }
    let password_hash = sqlx::query_scalar::<_, Option<String>>("SELECT password_hash FROM users WHERE id = $1")
        .bind(authed.0.user.id)
        .fetch_one(&state.pool)
        .await
        .map_internal("load password hash")?;
    let Some(current) = password_hash else {
        return Err(ApiError::Validation("invalid current password".into()));
    };
    if !verify_password(&req.current_password, &current) {
        return Err(ApiError::Validation("invalid current password".into()));
    }

    let new_hash = hash_password(&req.new_password)?;
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&new_hash)
        .bind(authed.0.user.id)
        .execute(&state.pool)
        .await
        .map_internal("update password")?;

    // Keep the current session, revoke all others.
    authn::revoke_all_user_sessions(&state.pool, authed.0.user.id, Some(authed.0.session.id)).await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "account.password_changed",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: None,
            target_id: None,
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn update_profile(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Json(req): Json<UpdateProfileReq>,
) -> ApiResult<Response> {
    let display_name = req.display_name.trim();
    if display_name.is_empty() || display_name.chars().count() > 100 {
        return Err(ApiError::Validation("display name must be between 1 and 100 characters".into()));
    }
    sqlx::query("UPDATE users SET display_name = $1, updated_at = now() WHERE id = $2")
        .bind(display_name)
        .bind(authed.0.user.id)
        .execute(&state.pool)
        .await
        .map_internal("update profile")?;

    let user = sqlx::query_as::<_, authn::UserRow>(
        "SELECT id, email, display_name, email_verified_at FROM users WHERE id = $1",
    )
    .bind(authed.0.user.id)
    .fetch_one(&state.pool)
    .await
    .map_internal("reload user")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "account.profile_updated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: None,
            target_id: None,
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(UserJson::from(&user)).into_response())
}

async fn generate_recovery_codes(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;

    // Invalidate previous sets.
    sqlx::query(
        "UPDATE recovery_code_sets SET invalidated_at = now() WHERE user_id = $1 AND invalidated_at IS NULL",
    )
    .bind(authed.0.user.id)
    .execute(&state.pool)
    .await
    .map_internal("invalidate old recovery code sets")?;

    let set_id = new_id();
    sqlx::query("INSERT INTO recovery_code_sets (id, user_id) VALUES ($1, $2)")
        .bind(set_id)
        .bind(authed.0.user.id)
        .execute(&state.pool)
        .await
        .map_internal("create recovery code set")?;

    let mut codes: Vec<String> = Vec::with_capacity(8);
    for _ in 0..8 {
        let code = random_recovery_code();
        sqlx::query("INSERT INTO recovery_codes (id, set_id, code_hash) VALUES ($1, $2, $3)")
            .bind(new_id())
            .bind(set_id)
            .bind(hash_token(&normalize_recovery_code(&code)))
            .execute(&state.pool)
            .await
            .map_internal("store recovery code")?;
        codes.push(code);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "recovery_codes.generated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: None,
            target_id: None,
            metadata: serde_json::json!({ "count": 8 }),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "codes": codes })).into_response())
}

async fn recovery_login(
    State(state): State<AppState>,
    meta: HttpMeta,
    Json(req): Json<RecoveryLoginReq>,
) -> ApiResult<Response> {
    let email = req.email.trim().to_lowercase();
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("recovery", &ip_key, RL_RECOVERY_IP.0, RL_RECOVERY_IP.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    let normalized = normalize_recovery_code(&req.code);
    let user = sqlx::query_as::<_, (Uuid, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT id, email_verified_at FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup user for recovery")?;

    let Some((user_id, verified)) = user else {
        return Err(ApiError::TokenInvalid);
    };
    if verified.is_none() {
        return Err(ApiError::EmailNotVerified);
    }

    // Find the user's code among the unused codes of the active set.
    let hashes = sqlx::query_scalar::<_, String>(
        r#"
        SELECT rc.code_hash
        FROM recovery_codes rc
        JOIN recovery_code_sets rcs ON rcs.id = rc.set_id
        WHERE rcs.user_id = $1 AND rcs.invalidated_at IS NULL AND rc.used_at IS NULL
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list recovery codes")?;

    // Constant-time match against stored hashes.
    let normalized_hash = hash_token(&normalized);
    let Some(matched_hash) = hashes
        .iter()
        .find(|h| crate::tokens::tokens_equal(&normalized_hash, h))
        .cloned()
    else {
        return Err(ApiError::TokenInvalid);
    };

    let marked = sqlx::query(
        "UPDATE recovery_codes SET used_at = now() WHERE code_hash = $1 AND used_at IS NULL",
    )
    .bind(&matched_hash)
    .execute(&state.pool)
    .await
    .map_internal("mark recovery code used")?;
    if marked.rows_affected() == 0 {
        return Err(ApiError::TokenInvalid);
    }

    let (session, token) = authn::create_session(
        &state.pool,
        &state.config,
        user_id,
        meta.ip.map(|ip| ip.to_string()),
        meta.user_agent.clone(),
    )
    .await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "auth.recovery_used",
            actor_type: ActorType::User,
            actor_id: Some(user_id),
            org_id: None,
            target_type: Some("session"),
            target_id: Some(session.id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    let user_row = sqlx::query_as::<_, authn::UserRow>(
        "SELECT id, email, display_name, email_verified_at FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("reload user")?;

    let mut resp = Json(serde_json::json!({ "user": UserJson::from(&user_row) })).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, authn::session_cookie_value(&state.config, &token));
    Ok(resp)
}

// ------------------------------------------------------------------ helpers

async fn issue_verification(state: &AppState, meta: &HttpMeta, user_id: Uuid, email: &str) {
    let token = random_token();
    let stored = sqlx::query(
        "INSERT INTO email_verifications (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(new_id())
    .bind(user_id)
    .bind(hash_token(&token))
    .bind(chrono::Utc::now() + chrono::Duration::from_std(state.config.verify_ttl).unwrap_or_default())
    .execute(&state.pool)
    .await;

    if let Err(e) = stored {
        tracing::error!(error = %e, "failed to store email verification token");
        return;
    }

    let link = format!("{}/verify-email?token={}", state.config.web_origin, token);
    if let Err(e) = state
        .mailer
        .send(email, "Verify your ArcticWorks account", verify_email_html(&link))
        .await
    {
        tracing::warn!(error = %e, "failed to send verification email");
    }
    let _ = meta;
}

/// 8 codes, each `XXXX-XXXX-XXXX-XXXX` (16 random hex chars, grouped).
fn random_recovery_code() -> String {
    let mut buf = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut buf);
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}",
        &hex[0..4],
        &hex[4..8],
        &hex[8..12],
        &hex[12..16]
    )
}

fn normalize_recovery_code(code: &str) -> String {
    code.chars().filter(|c| *c != '-' && !c.is_whitespace()).collect::<String>().to_lowercase()
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn verify_email_html(link: &str) -> String {
    format!(
        "<p>Welcome to ArcticWorks! Verify your email address to activate your account:</p>\
         <p><a href=\"{link}\">Verify email</a></p>\
         <p>If the link does not work, copy this URL into your browser:</p>\
         <p>{link}</p>\
         <p>This link expires in 24 hours.</p>"
    )
}

fn reset_email_html(link: &str) -> String {
    format!(
        "<p>You requested a password reset for your ArcticWorks account.</p>\
         <p><a href=\"{link}\">Reset password</a></p>\
         <p>If the link does not work, copy this URL into your browser:</p>\
         <p>{link}</p>\
         <p>This link expires in 30 minutes. If you did not request this, you can ignore this email.</p>"
    )
}

pub fn email_for_html(display_name: &str) -> String {
    escape_html(display_name)
}
