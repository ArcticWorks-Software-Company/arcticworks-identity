//! Machine identities: service accounts, device enrollment tokens and
//! enrolled devices. A service account or device belongs to exactly one
//! organization. Credentials are short-lived, hashed at rest, and every
//! event is recorded in the audit log.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use utoipa::ToSchema;

use crate::audit::{self, ActorType, AuditEvent};
use crate::authn::Authed;
use crate::correlation::HttpMeta;
use crate::error::{ApiError, ApiResult, MapInternal};
use crate::ids::new_id;
use crate::rbac;
use crate::state::AppState;
use crate::tokens::{hash_token, random_secret, secret_preview, tokens_equal};
use secrecy::ExposeSecret;

pub mod seed;

pub const SA_CRED_TTL_DAYS: i64 = 90;
pub const DEVICE_CRED_TTL_DAYS: i64 = 365;
pub const ENROLLMENT_TOKEN_TTL_HOURS: i64 = 24;
const RL_ENROLL: (u32, u64) = (5, 3600); // 5 per hour per IP
const RL_SA_CREATE: (u32, u64) = (10, 3600); // 10 per hour per IP

// ------------------------------------------------------------------- models

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountJson {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub role_id: Option<Uuid>,
    pub role_name: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeviceJson {
    pub id: Uuid,
    pub name: String,
    pub team_id: Option<Uuid>,
    pub team_name: Option<String>,
    pub status: String,
    pub enrolled_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A machine actor authenticated via client credentials.
#[derive(Debug, Clone)]
pub enum MachineActor {
    ServiceAccount {
        id: Uuid,
        org_id: Uuid,
        name: String,
    },
    Device {
        id: Uuid,
        org_id: Uuid,
        name: String,
    },
}

impl MachineActor {
    pub fn id(&self) -> Uuid {
        match self {
            MachineActor::ServiceAccount { id, .. } => *id,
            MachineActor::Device { id, .. } => *id,
        }
    }

    pub fn org_id(&self) -> Uuid {
        match self {
            MachineActor::ServiceAccount { org_id, .. } => *org_id,
            MachineActor::Device { org_id, .. } => *org_id,
        }
    }

    pub fn actor_type(&self) -> ActorType {
        match self {
            MachineActor::ServiceAccount { .. } => ActorType::ServiceAccount,
            MachineActor::Device { .. } => ActorType::Device,
        }
    }
}

// ------------------------------------------------------------------ requests

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateServiceAccountReq {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub role_id: Uuid,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateServiceAccountReq {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub role_id: Option<Uuid>,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateEnrollmentTokenReq {
    #[serde(default)]
    pub team_id: Option<Uuid>,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EnrollReq {
    pub token: String,
    pub name: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDeviceReq {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub team_id: Option<Uuid>,
}

// -------------------------------------------------------------------- routes

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/orgs/{org_id}/service-accounts",
            get(list_service_accounts).post(create_service_account),
        )
        .route(
            "/api/orgs/{org_id}/service-accounts/{sa_id}",
            patch(update_service_account).delete(delete_service_account),
        )
        .route(
            "/api/orgs/{org_id}/service-accounts/{sa_id}/credentials",
            post(rotate_service_account_credential),
        )
        .route(
            "/api/orgs/{org_id}/service-accounts/{sa_id}/suspend",
            post(suspend_service_account),
        )
        .route(
            "/api/orgs/{org_id}/service-accounts/{sa_id}/unsuspend",
            post(unsuspend_service_account),
        )
        .route(
            "/api/orgs/{org_id}/enrollment-tokens",
            post(create_enrollment_token),
        )
        .route("/api/enroll", post(enroll_device))
        .route("/api/orgs/{org_id}/devices", get(list_devices))
        .route(
            "/api/orgs/{org_id}/devices/{device_id}",
            patch(update_device).delete(revoke_device),
        )
        .route(
            "/api/orgs/{org_id}/devices/{device_id}/rotate-credential",
            post(rotate_device_credential),
        )
}

// ---------------------------------------------------------------- handlers

/// Create a service account with its first short-lived client credential
/// (requires `org.service-accounts.manage`). The secret is returned once.
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/service-accounts",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    request_body = CreateServiceAccountReq,
    responses(
        (status = 201, description = "Service account and credential created"),
        (status = 403, description = "Insufficient permissions"),
        (status = 429, description = "Rate limited")
    ),
    security(("sessionCookie" = []))
)]
pub async fn create_service_account(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(org_id): Path<Uuid>,
    Json(req): Json<CreateServiceAccountReq>,
) -> ApiResult<Response> {
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("sa-create", &ip_key, RL_SA_CREATE.0, RL_SA_CREATE.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::SERVICE_ACCOUNTS_MANAGE).await?;

    let name = validate_sa_name(&req.name)?;
    let description = req.description.trim().chars().take(500).collect::<String>();
    validate_role_for_org(&state, org_id, req.role_id).await?;

    let sa_id = new_id();
    let (client_id, secret, secret_hash, preview, expires_at) = generate_credential("awsa", "awsec", SA_CRED_TTL_DAYS);

    let mut tx = state.pool.begin().await.map_internal("begin SA tx")?;
    sqlx::query(
        r#"
        INSERT INTO service_accounts (id, org_id, name, description, role_id, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(sa_id)
    .bind(org_id)
    .bind(&name)
    .bind(&description)
    .bind(req.role_id)
    .bind(authed.0.user.id)
    .execute(&mut *tx)
    .await
    .map_internal("create service account")?;

    sqlx::query(
        r#"
        INSERT INTO service_account_credentials
            (id, service_account_id, client_id, secret_hash, preview, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(new_id())
    .bind(sa_id)
    .bind(&client_id)
    .bind(&secret_hash)
    .bind(&preview)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_internal("create service account credential")?;
    tx.commit().await.map_internal("commit SA tx")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "sa.created",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("service_account"),
            target_id: Some(sa_id),
            metadata: serde_json::json!({ "name": name }),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "serviceAccount": {
                "id": sa_id, "name": name, "description": description,
                "roleId": req.role_id, "status": "active"
            },
            "clientId": client_id,
            "clientSecret": secret.expose_secret(),
            "expiresAt": expires_at,
        })),
    )
        .into_response())
}

/// List service accounts (requires `org.service-accounts.read`).
#[utoipa::path(
    get,
    path = "/api/orgs/{org_id}/service-accounts",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    responses(
        (status = 200, description = "List of service accounts", body = inline(crate::openapi::ServiceAccountsResponse)),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn list_service_accounts(
    State(state): State<AppState>,
    authed: Authed,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::SERVICE_ACCOUNTS_READ).await?;
    let accounts = sqlx::query_as::<_, ServiceAccountRow>(
        r#"
        SELECT sa.id, sa.name, sa.description, sa.role_id, r.name AS role_name,
               sa.status, sa.created_at
        FROM service_accounts sa
        LEFT JOIN roles r ON r.id = sa.role_id
        WHERE sa.org_id = $1
        ORDER BY sa.created_at
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list service accounts")?;

    Ok(Json(serde_json::json!({ "serviceAccounts": accounts })).into_response())
}

#[derive(sqlx::FromRow, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceAccountRow {
    id: Uuid,
    name: String,
    description: String,
    role_id: Option<Uuid>,
    role_name: Option<String>,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn update_service_account(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, sa_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateServiceAccountReq>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::SERVICE_ACCOUNTS_MANAGE).await?;

    let mut changes: Vec<String> = Vec::new();
    let mut bind_idx = 1usize;

    let mut sql = String::from("UPDATE service_accounts SET ");
    if let Some(name) = &req.name {
        let name = validate_sa_name(name)?;
        sql.push_str(&format!("name = ${bind_idx}, "));
        bind_idx += 1;
        changes.push(name);
    }
    if let Some(description) = &req.description {
        let description = description.trim().chars().take(500).collect::<String>();
        sql.push_str(&format!("description = ${bind_idx}, "));
        bind_idx += 1;
        changes.push(description);
    }
    if let Some(role_id) = req.role_id {
        validate_role_for_org(&state, org_id, role_id).await?;
        sql.push_str(&format!("role_id = ${bind_idx}, "));
        bind_idx += 1;
        changes.push(role_id.to_string());
    }
    sql.push_str("updated_at = now() WHERE id = $");
    sql.push_str(&bind_idx.to_string());
    sql.push_str(" AND org_id = $");
    sql.push_str(&(bind_idx + 1).to_string());

    let mut q = sqlx::query(&sql);
    for c in &changes {
        q = q.bind(c);
    }
    q = q.bind(sa_id).bind(org_id);
    let res = q.execute(&state.pool).await.map_internal("update service account")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "sa.updated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("service_account"),
            target_id: Some(sa_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

/// Rotate a service account credential (requires `org.service-accounts.manage`
/// + reauthentication). The old credential is revoked immediately.
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/service-accounts/{sa_id}/credentials",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("sa_id" = Uuid, Path, description = "Service account id")
    ),
    responses(
        (status = 200, description = "New client credential (returned once)"),
        (status = 403, description = "Insufficient permissions or reauthentication required"),
        (status = 404, description = "Service account not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn rotate_service_account_credential(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, sa_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::SERVICE_ACCOUNTS_MANAGE).await?;

    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM service_accounts WHERE id = $1 AND org_id = $2)",
    )
    .bind(sa_id)
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("check service account")?;
    if !exists {
        return Err(ApiError::NotFound);
    }

    let (client_id, secret, secret_hash, preview, expires_at) = generate_credential("awsa", "awsec", SA_CRED_TTL_DAYS);

    let mut tx = state.pool.begin().await.map_internal("begin rotate tx")?;
    sqlx::query(
        "UPDATE service_account_credentials SET revoked_at = now() WHERE service_account_id = $1 AND revoked_at IS NULL",
    )
    .bind(sa_id)
    .execute(&mut *tx)
    .await
    .map_internal("revoke old credential")?;
    sqlx::query(
        r#"
        INSERT INTO service_account_credentials
            (id, service_account_id, client_id, secret_hash, preview, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(new_id())
    .bind(sa_id)
    .bind(&client_id)
    .bind(&secret_hash)
    .bind(&preview)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_internal("insert new credential")?;
    tx.commit().await.map_internal("commit rotate")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "sa.credential_rotated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("service_account"),
            target_id: Some(sa_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({
        "clientId": client_id,
        "clientSecret": secret.expose_secret(),
        "expiresAt": expires_at,
    }))
    .into_response())
}

/// Suspend a service account (requires `org.service-accounts.manage`).
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/service-accounts/{sa_id}/suspend",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("sa_id" = Uuid, Path, description = "Service account id")
    ),
    responses(
        (status = 200, description = "Service account suspended"),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn suspend_service_account(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, sa_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    set_sa_status(&state, &meta, authed.0.user.id, org_id, sa_id, "suspended").await
}

/// Restore a suspended service account (requires
/// `org.service-accounts.manage`).
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/service-accounts/{sa_id}/unsuspend",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("sa_id" = Uuid, Path, description = "Service account id")
    ),
    responses(
        (status = 200, description = "Service account restored"),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn unsuspend_service_account(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, sa_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    set_sa_status(&state, &meta, authed.0.user.id, org_id, sa_id, "active").await
}

async fn set_sa_status(
    state: &AppState,
    meta: &HttpMeta,
    actor_id: Uuid,
    org_id: Uuid,
    sa_id: Uuid,
    status: &str,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, actor_id, org_id, rbac::perms::SERVICE_ACCOUNTS_MANAGE).await?;
    let res = sqlx::query(
        "UPDATE service_accounts SET status = $1, updated_at = now() WHERE id = $2 AND org_id = $3 AND status <> $1",
    )
    .bind(status)
    .bind(sa_id)
    .bind(org_id)
    .execute(&state.pool)
    .await
    .map_internal("update service account status")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        meta,
        AuditEvent {
            event_type: if status == "suspended" { "sa.suspended" } else { "sa.unsuspended" },
            actor_type: ActorType::User,
            actor_id: Some(actor_id),
            org_id: Some(org_id),
            target_type: Some("service_account"),
            target_id: Some(sa_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

/// Delete a service account (requires `org.service-accounts.manage` +
/// reauthentication).
#[utoipa::path(
    delete,
    path = "/api/orgs/{org_id}/service-accounts/{sa_id}",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("sa_id" = Uuid, Path, description = "Service account id")
    ),
    responses(
        (status = 204, description = "Service account deleted"),
        (status = 403, description = "Insufficient permissions or reauthentication required"),
        (status = 404, description = "Service account not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn delete_service_account(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, sa_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::SERVICE_ACCOUNTS_MANAGE).await?;
    let res = sqlx::query("DELETE FROM service_accounts WHERE id = $1 AND org_id = $2")
        .bind(sa_id)
        .bind(org_id)
        .execute(&state.pool)
        .await
        .map_internal("delete service account")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "sa.deleted",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("service_account"),
            target_id: Some(sa_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Create a single-use, expiring device-enrollment token
/// (requires `org.devices.manage`). The token is returned once.
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/enrollment-tokens",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    request_body = CreateEnrollmentTokenReq,
    responses(
        (status = 201, description = "Enrollment token created (returned once)"),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn create_enrollment_token(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(org_id): Path<Uuid>,
    Json(req): Json<CreateEnrollmentTokenReq>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::DEVICES_MANAGE).await?;

    if let Some(team_id) = req.team_id {
        let team_ok = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM teams WHERE id = $1 AND org_id = $2)",
        )
        .bind(team_id)
        .bind(org_id)
        .fetch_one(&state.pool)
        .await
        .map_internal("check team")?;
        if !team_ok {
            return Err(ApiError::Validation("team does not belong to this organization".into()));
        }
    }

    let token = crate::tokens::random_token();
    let token_id = new_id();
    sqlx::query(
        r#"
        INSERT INTO device_enrollment_tokens (id, org_id, team_id, token_hash, created_by, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(token_id)
    .bind(org_id)
    .bind(req.team_id)
    .bind(hash_token(&token))
    .bind(authed.0.user.id)
    .bind(chrono::Utc::now() + chrono::Duration::hours(ENROLLMENT_TOKEN_TTL_HOURS))
    .execute(&state.pool)
    .await
    .map_internal("create enrollment token")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "device.enrollment_token_created",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("enrollment_token"),
            target_id: Some(token_id),
            metadata: serde_json::json!({ "ttlHours": ENROLLMENT_TOKEN_TTL_HOURS }),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "token": token, "expiresAt": chrono::Utc::now() + chrono::Duration::hours(ENROLLMENT_TOKEN_TTL_HOURS) })),
    )
        .into_response())
}

/// Enroll a device into an organization using a single-use enrollment
/// token. The device credential (client id + secret) is returned once.
#[utoipa::path(
    post,
    path = "/api/enroll",
    request_body = EnrollReq,
    responses(
        (status = 201, description = "Device enrolled; credential returned once"),
        (status = 401, description = "Invalid or used enrollment token"),
        (status = 429, description = "Rate limited")
    )
)]
pub async fn enroll_device(
    State(state): State<AppState>,
    meta: HttpMeta,
    Json(req): Json<EnrollReq>,
) -> ApiResult<Response> {
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("enroll", &ip_key, RL_ENROLL.0, RL_ENROLL.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::Validation("device name must be between 1 and 100 characters".into()));
    }

    // Single-use, expiring enrollment token.
    let token_row = sqlx::query_as::<_, (Uuid, Uuid, Option<Uuid>, Option<chrono::DateTime<chrono::Utc>>)>(
        r#"
        SELECT id, org_id, team_id, used_at
        FROM device_enrollment_tokens
        WHERE token_hash = $1
        "#,
    )
    .bind(hash_token(&req.token))
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup enrollment token")?;

    let Some((token_id, org_id, team_id, used_at)) = token_row else {
        return Err(ApiError::TokenInvalid);
    };
    if used_at.is_some() {
        return Err(ApiError::TokenInvalid);
    }
    let consumed = sqlx::query(
        "UPDATE device_enrollment_tokens SET used_at = now() WHERE id = $1 AND used_at IS NULL AND expires_at > now() AND revoked_at IS NULL",
    )
    .bind(token_id)
    .execute(&state.pool)
    .await
    .map_internal("consume enrollment token")?;
    if consumed.rows_affected() == 0 {
        return Err(ApiError::TokenInvalid);
    }

    let device_id = new_id();
    let (client_id, secret, secret_hash, preview, expires_at) = generate_credential("awdev", "awdsec", DEVICE_CRED_TTL_DAYS);
    sqlx::query(
        r#"
        INSERT INTO devices
            (id, org_id, team_id, name, client_id, credential_hash, secret_preview, credential_expires_at, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active')
        "#,
    )
    .bind(device_id)
    .bind(org_id)
    .bind(team_id)
    .bind(name)
    .bind(&client_id)
    .bind(&secret_hash)
    .bind(&preview)
    .bind(expires_at)
    .execute(&state.pool)
    .await
    .map_internal("enroll device")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "device.enrolled",
            actor_type: ActorType::System,
            actor_id: None,
            org_id: Some(org_id),
            target_type: Some("device"),
            target_id: Some(device_id),
            metadata: serde_json::json!({ "name": name, "enrollmentTokenId": token_id }),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "device": { "id": device_id, "name": name, "teamId": team_id },
            "clientId": client_id,
            "clientSecret": secret.expose_secret(),
            "expiresAt": expires_at,
        })),
    )
        .into_response())
}

/// List enrolled devices (requires `org.devices.read`).
#[utoipa::path(
    get,
    path = "/api/orgs/{org_id}/devices",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    responses(
        (status = 200, description = "List of devices", body = inline(crate::openapi::DevicesResponse)),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn list_devices(
    State(state): State<AppState>,
    authed: Authed,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::DEVICES_READ).await?;
    let devices = sqlx::query_as::<_, DeviceRow>(
        r#"
        SELECT d.id, d.name, d.team_id, t.name AS team_name, d.status,
               d.enrolled_at, d.last_seen_at
        FROM devices d
        LEFT JOIN teams t ON t.id = d.team_id
        WHERE d.org_id = $1
        ORDER BY d.enrolled_at
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list devices")?;
    Ok(Json(serde_json::json!({ "devices": devices })).into_response())
}

#[derive(sqlx::FromRow, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceRow {
    id: Uuid,
    name: String,
    team_id: Option<Uuid>,
    team_name: Option<String>,
    status: String,
    enrolled_at: chrono::DateTime<chrono::Utc>,
    last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Rename or re-team a device (requires `org.devices.manage`).
#[utoipa::path(
    patch,
    path = "/api/orgs/{org_id}/devices/{device_id}",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("device_id" = Uuid, Path, description = "Device id")
    ),
    request_body = UpdateDeviceReq,
    responses(
        (status = 200, description = "Device updated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Device not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn update_device(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, device_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateDeviceReq>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::DEVICES_MANAGE).await?;

    let mut changes: Vec<String> = Vec::new();
    let mut bind_idx = 1usize;
    let mut sql = String::from("UPDATE devices SET ");
    if let Some(name) = &req.name {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Err(ApiError::Validation("device name must be between 1 and 100 characters".into()));
        }
        sql.push_str(&format!("name = ${bind_idx}, "));
        bind_idx += 1;
        changes.push(name.to_string());
    }
    if let Some(team_id) = req.team_id {
        let team_ok = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM teams WHERE id = $1 AND org_id = $2)",
        )
        .bind(team_id)
        .bind(org_id)
        .fetch_one(&state.pool)
        .await
        .map_internal("check team")?;
        if !team_ok {
            return Err(ApiError::Validation("team does not belong to this organization".into()));
        }
        sql.push_str(&format!("team_id = ${bind_idx}, "));
        bind_idx += 1;
        changes.push(team_id.to_string());
    }
    sql.push_str("WHERE id = $");
    sql.push_str(&bind_idx.to_string());
    sql.push_str(" AND org_id = $");
    sql.push_str(&(bind_idx + 1).to_string());

    let mut q = sqlx::query(&sql);
    for c in &changes {
        q = q.bind(c);
    }
    q = q.bind(device_id).bind(org_id);
    let res = q.execute(&state.pool).await.map_internal("update device")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "device.updated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("device"),
            target_id: Some(device_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

/// Rotate a device credential (requires `org.devices.manage` +
/// reauthentication). The old credential is revoked immediately.
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/devices/{device_id}/rotate-credential",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("device_id" = Uuid, Path, description = "Device id")
    ),
    responses(
        (status = 200, description = "New device credential (returned once)"),
        (status = 403, description = "Insufficient permissions or reauthentication required"),
        (status = 404, description = "Device not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn rotate_device_credential(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, device_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::DEVICES_MANAGE).await?;

    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1 AND org_id = $2)",
    )
    .bind(device_id)
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("check device")?;
    if !exists {
        return Err(ApiError::NotFound);
    }

    let (client_id, secret, secret_hash, preview, expires_at) = generate_credential("awdev", "awdsec", DEVICE_CRED_TTL_DAYS);
    sqlx::query(
        "UPDATE devices SET client_id = $1, credential_hash = $2, secret_preview = $3, credential_expires_at = $4 WHERE id = $5 AND org_id = $6",
    )
    .bind(&client_id)
    .bind(&secret_hash)
    .bind(&preview)
    .bind(expires_at)
    .bind(device_id)
    .bind(org_id)
    .execute(&state.pool)
    .await
    .map_internal("rotate device credential")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "device.credential_rotated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("device"),
            target_id: Some(device_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({
        "clientId": client_id,
        "clientSecret": secret.expose_secret(),
        "expiresAt": expires_at,
    }))
    .into_response())
}

/// Revoke a device (requires `org.devices.manage` + reauthentication).
/// Revoked devices can no longer authenticate.
#[utoipa::path(
    delete,
    path = "/api/orgs/{org_id}/devices/{device_id}",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("device_id" = Uuid, Path, description = "Device id")
    ),
    responses(
        (status = 204, description = "Device revoked"),
        (status = 403, description = "Insufficient permissions or reauthentication required"),
        (status = 404, description = "Device not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn revoke_device(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, device_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::DEVICES_MANAGE).await?;
    let res = sqlx::query(
        "UPDATE devices SET status = 'revoked' WHERE id = $1 AND org_id = $2 AND status <> 'revoked'",
    )
    .bind(device_id)
    .bind(org_id)
    .execute(&state.pool)
    .await
    .map_internal("revoke device")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "device.revoked",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("device"),
            target_id: Some(device_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ------------------------------------------------------------------ machine auth

/// Authenticate a machine (service account or device) with client
/// credentials. Returns the actor and updates `last_used_at`.
pub async fn authenticate_machine(
    state: &AppState,
    client_id: &str,
    secret: &str,
) -> ApiResult<MachineActor> {
    // Service account credential.
    if let Some(row) = sqlx::query_as::<_, SaCredRow>(
        r#"
        SELECT c.id, c.service_account_id, c.secret_hash, c.expires_at, c.revoked_at,
               sa.org_id, sa.status, sa.name
        FROM service_account_credentials c
        JOIN service_accounts sa ON sa.id = c.service_account_id
        WHERE c.client_id = $1
        "#,
    )
    .bind(client_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup service account credential")?
    {
        if row.revoked_at.is_some() || row.expires_at < chrono::Utc::now() {
            return Err(ApiError::Unauthorized);
        }
        if row.status != "active" {
            return Err(ApiError::Unauthorized);
        }
        if !tokens_equal(&hash_token(secret), &row.secret_hash) {
            return Err(ApiError::Unauthorized);
        }
        let _ = sqlx::query("UPDATE service_account_credentials SET last_used_at = now() WHERE id = $1")
            .bind(row.id)
            .execute(&state.pool)
            .await;
        return Ok(MachineActor::ServiceAccount {
            id: row.service_account_id,
            org_id: row.org_id,
            name: row.name,
        });
    }

    // Device credential.
    if let Some(row) = sqlx::query_as::<_, DeviceCredRow>(
        r#"
        SELECT id, org_id, name, credential_hash, credential_expires_at, status
        FROM devices
        WHERE client_id = $1
        "#,
    )
    .bind(client_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup device credential")?
    {
        if row.status != "active" || row.credential_expires_at <= chrono::Utc::now() {
            return Err(ApiError::Unauthorized);
        }
        if !tokens_equal(&hash_token(secret), &row.credential_hash) {
            return Err(ApiError::Unauthorized);
        }
        let _ = sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1")
            .bind(row.id)
            .execute(&state.pool)
            .await;
        return Ok(MachineActor::Device {
            id: row.id,
            org_id: row.org_id,
            name: row.name,
        });
    }

    Err(ApiError::Unauthorized)
}

#[derive(sqlx::FromRow)]
struct SaCredRow {
    id: Uuid,
    service_account_id: Uuid,
    secret_hash: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    org_id: Uuid,
    status: String,
    name: String,
}

#[derive(sqlx::FromRow)]
struct DeviceCredRow {
    id: Uuid,
    org_id: Uuid,
    name: String,
    credential_hash: String,
    credential_expires_at: chrono::DateTime<chrono::Utc>,
    status: String,
}

// ------------------------------------------------------------------ helpers

fn validate_sa_name(name: &str) -> ApiResult<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::Validation("service account name must be between 1 and 100 characters".into()));
    }
    Ok(name.to_string())
}

async fn validate_role_for_org(state: &AppState, org_id: Uuid, role_id: Uuid) -> ApiResult<()> {
    let ok = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1 AND org_id = $2 AND NOT is_owner)",
    )
    .bind(role_id)
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("validate role")?;
    if !ok {
        return Err(ApiError::Validation("role does not belong to this organization".into()));
    }
    Ok(())
}

fn generate_credential(
    client_prefix: &str,
    secret_prefix: &str,
    ttl_days: i64,
) -> (String, secrecy::SecretString, String, String, chrono::DateTime<chrono::Utc>) {
    let client_id = format!("{client_prefix}_{}", new_id().simple());
    let secret = random_secret(secret_prefix);
    let secret_hash = hash_token(secret.expose_secret());
    let preview = secret_preview(secret.expose_secret());
    let expires_at = chrono::Utc::now() + chrono::Duration::days(ttl_days);
    (client_id, secret, secret_hash, preview, expires_at)
}
