//! OAuth 2.0 Device Authorization Grant (RFC 8628): CLI/device clients
//! obtain a user code, the user approves it in the browser, and the client
//! polls the token endpoint for tokens.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::Deserialize;
use std::collections::HashMap;
use uuid::Uuid;

use crate::audit::{self, ActorType, AuditEvent};
use crate::authn::Authed;
use crate::correlation::HttpMeta;
use crate::error::{ApiError, ApiResult, MapInternal};
use crate::ids::new_id;
use crate::rbac;
use crate::state::AppState;
use crate::tokens::{hash_token, random_token};

use super::token;

pub const DEVICE_CODE_TTL_SECS: i64 = 900; // 15 minutes
pub const POLL_INTERVAL_SECS: i64 = 5;

const RL_DEVICE_AUTH: (u32, u64) = (5, 3600); // 5 per hour per IP
const RL_DEVICE_APPROVE: (u32, u64) = (5, 60); // 5 per minute per IP
const RL_DEVICE_INFO: (u32, u64) = (10, 60); // 10 per minute per IP

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/oidc/device_authorization", post(device_authorization))
        .route("/api/oidc/device-info", get(device_info))
        .route("/api/oidc/device-approve", post(device_approve))
}

/// User codes are 8 characters from a unambiguous alphabet.
fn generate_user_code() -> String {
    const ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ23456789";
    let mut out = String::with_capacity(8);
    for _ in 0..8 {
        out.push(ALPHABET[rand::random_range(0..ALPHABET.len())] as char);
    }
    out
}

#[derive(sqlx::FromRow)]
pub struct DeviceAuthRow {
    pub id: Uuid,
    pub client_id: String,
    pub org_id: Option<Uuid>,
    pub scopes: serde_json::Value,
    pub status: String,
    pub user_id: Option<Uuid>,
    pub last_polled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Start a device authorization: returns device_code, user_code and the
/// verification URIs.
async fn device_authorization(
    State(state): State<AppState>,
    meta: HttpMeta,
    headers: axum::http::HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> ApiResult<Response> {
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state
        .rl
        .check("device-auth", &ip_key, RL_DEVICE_AUTH.0, RL_DEVICE_AUTH.1)
        .await
    {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    let client = super::authenticate_client(&state, &headers, &form).await?;
    let Some(org_id) = client.org_id else {
        return Err(super::oauth_token_error(
            "unauthorized_client",
            "application has no organization",
        ));
    };
    let scope = form
        .get("scope")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "openid profile email".into());
    let scopes = super::parse_scopes(&scope)?;

    let device_code = random_token();
    let user_code = generate_user_code();
    sqlx::query(
        r#"
        INSERT INTO device_authorizations
            (id, device_code_hash, user_code_hash, client_id, org_id, scopes, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7::int))
        "#,
    )
    .bind(new_id())
    .bind(hash_token(&device_code))
    .bind(hash_token(&user_code))
    .bind(&client.client_id)
    .bind(org_id)
    .bind(serde_json::to_value(&scopes).unwrap_or_else(|_| serde_json::json!([])))
    .bind(DEVICE_CODE_TTL_SECS)
    .execute(&state.pool)
    .await
    .map_internal("store device authorization")?;

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: "device.authorization_started",
            actor_type: ActorType::System,
            actor_id: None,
            org_id: Some(org_id),
            target_type: Some("client"),
            target_id: None,
            metadata: serde_json::json!({ "clientId": client.client_id }),
        },
    )
    .await;

    let verification_uri = format!("{}/device", state.config.web_origin);
    Ok(Json(serde_json::json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": format!("{verification_uri}?user_code={user_code}"),
        "expires_in": DEVICE_CODE_TTL_SECS,
        "interval": POLL_INTERVAL_SECS,
    }))
    .into_response())
}

#[derive(Deserialize)]
struct DeviceCodeReq {
    #[serde(rename = "user_code")]
    user_code: String,
}

/// What the user is being asked to approve.
async fn device_info(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    axum::extract::Query(req): axum::extract::Query<DeviceCodeReq>,
) -> ApiResult<Response> {
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state
        .rl
        .check("device-info", &ip_key, RL_DEVICE_INFO.0, RL_DEVICE_INFO.1)
        .await
    {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    let row = load_pending(&state, &req.user_code).await?;
    let Some(org_id) = row.org_id else {
        return Err(ApiError::Validation("application has no organization".into()));
    };
    if !rbac::is_active_member(&state.pool, authed.0.user.id, org_id).await? {
        return Err(ApiError::Forbidden);
    }

    let client_name: String = sqlx::query_scalar("SELECT name FROM oidc_clients WHERE client_id = $1")
        .bind(&row.client_id)
        .fetch_one(&state.pool)
        .await
        .map_internal("load client name")?;
    let scopes: Vec<String> = row
        .scopes
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(ToOwned::to_owned)).collect())
        .unwrap_or_default();

    Ok(Json(serde_json::json!({
        "client": { "name": client_name },
        "scopes": scopes,
    }))
    .into_response())
}

#[derive(Deserialize)]
struct DeviceApproveReq {
    #[serde(rename = "user_code")]
    user_code: String,
    decision: String, // "approve" | "deny"
}

/// Approve or deny a pending device authorization.
async fn device_approve(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Json(req): Json<DeviceApproveReq>,
) -> ApiResult<Response> {
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state
        .rl
        .check("device-approve", &ip_key, RL_DEVICE_APPROVE.0, RL_DEVICE_APPROVE.1)
        .await
    {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    let row = load_pending(&state, &req.user_code).await?;
    let Some(org_id) = row.org_id else {
        return Err(ApiError::Validation("application has no organization".into()));
    };
    if !rbac::is_active_member(&state.pool, authed.0.user.id, org_id).await? {
        return Err(ApiError::Forbidden);
    }
    if req.decision != "approve" && req.decision != "deny" {
        return Err(ApiError::Validation("decision must be approve or deny".into()));
    }

    let res = sqlx::query(
        r#"
        UPDATE device_authorizations
        SET status = CASE WHEN $1 = 'approve' THEN 'approved' ELSE 'denied' END,
            user_id = CASE WHEN $1 = 'approve' THEN $2 ELSE NULL END
        WHERE user_code_hash = $3 AND status = 'pending' AND expires_at > now()
        "#,
    )
    .bind(&req.decision)
    .bind(authed.0.user.id)
    .bind(hash_token(&req.user_code))
    .execute(&state.pool)
    .await
    .map_internal("record device decision")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::TokenInvalid);
    }

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: if req.decision == "approve" {
                "device.approved"
            } else {
                "device.denied"
            },
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("client"),
            target_id: None,
            metadata: serde_json::json!({ "clientId": row.client_id }),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

async fn load_pending(state: &AppState, user_code: &str) -> ApiResult<DeviceAuthRow> {
    sqlx::query_as::<_, DeviceAuthRow>(
        r#"
        SELECT id, client_id, org_id, scopes, status, user_id, last_polled_at, expires_at
        FROM device_authorizations
        WHERE user_code_hash = $1 AND status = 'pending' AND expires_at > now()
        "#,
    )
    .bind(hash_token(user_code))
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup device authorization")?
    .ok_or(ApiError::TokenInvalid)
}

/// The token-endpoint half of the grant: poll for tokens.
pub async fn token_device_code(
    state: &AppState,
    meta: &HttpMeta,
    headers: &axum::http::HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Response> {
    let client = super::authenticate_client(state, headers, form).await?;
    let device_code = form
        .get("device_code")
        .ok_or_else(|| super::oauth_token_error("invalid_request", "missing device_code"))?;

    let row = sqlx::query_as::<_, DeviceAuthRow>(
        r#"
        SELECT id, client_id, org_id, scopes, status, user_id, last_polled_at, expires_at
        FROM device_authorizations
        WHERE device_code_hash = $1
        "#,
    )
    .bind(hash_token(device_code))
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup device code")?
    .ok_or_else(|| super::oauth_token_error("invalid_grant", "invalid device_code"))?;

    if row.client_id != client.client_id {
        return Err(super::oauth_token_error(
            "invalid_grant",
            "device_code was issued to a different client",
        ));
    }
    if row.status == "expired" || row.expires_at < chrono::Utc::now() {
        return Err(super::oauth_token_error("expired_token", "device_code expired"));
    }

    match row.status.as_str() {
        "denied" => Err(super::oauth_token_error(
            "access_denied",
            "the user denied the device authorization",
        )),
        "approved" => {
            // Consume the approval exactly once.
            let consumed = sqlx::query(
                "UPDATE device_authorizations SET status = 'expired' WHERE id = $1 AND status = 'approved'",
            )
            .bind(row.id)
            .execute(&state.pool)
            .await
            .map_internal("consume device authorization")?;
            if consumed.rows_affected() == 0 {
                return Err(super::oauth_token_error("expired_token", "device_code already used"));
            }

            let user_id = row.user_id.ok_or_else(|| {
                super::oauth_token_error("invalid_grant", "device authorization has no user")
            })?;
            let Some(org_id) = row.org_id else {
                return Err(super::oauth_token_error(
                    "invalid_grant",
                    "application has no organization",
                ));
            };
            if !rbac::is_active_member(&state.pool, user_id, org_id).await? {
                return Err(super::oauth_token_error(
                    "invalid_grant",
                    "membership is not active",
                ));
            }
            let scopes: Vec<String> = row
                .scopes
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(ToOwned::to_owned)).collect())
                .unwrap_or_default();

            let user = sqlx::query_as::<_, crate::authn::UserRow>(
                "SELECT id, email, display_name, email_verified_at FROM users WHERE id = $1",
            )
            .bind(user_id)
            .fetch_one(&state.pool)
            .await
            .map_internal("load user for device token")?;

            let with_refresh = scopes.contains(&"offline_access".to_string());
            let treq = token::TokenRequest {
                actor_type: "user",
                actor_id: user_id,
                org_id: Some(org_id),
                client_id: row.client_id.clone(),
                scopes: scopes.clone(),
                user: Some(token::UserClaims {
                    sub: user_id,
                    name: user.display_name.clone(),
                    email: user.email.clone(),
                    email_verified: user.email_verified_at.is_some(),
                }),
                auth_time: Some(chrono::Utc::now().timestamp()),
                nonce: None,
            };
            let minted = token::mint_tokens(state, &treq, with_refresh).await?;

            audit::record(
                &state,
                meta,
                AuditEvent {
                    event_type: "device.token_issued",
                    actor_type: ActorType::User,
                    actor_id: Some(user_id),
                    org_id: Some(org_id),
                    target_type: Some("client"),
                    target_id: None,
                    metadata: serde_json::json!({ "clientId": row.client_id, "grant": "device_code" }),
                },
            )
            .await;

            Ok(super::token_response(minted))
        }
        _ => {
            // Pending: enforce the polling interval (RFC 8628 §3.5).
            let slow_down = row
                .last_polled_at
                .is_some_and(|t| chrono::Utc::now().signed_duration_since(t) < chrono::Duration::seconds(POLL_INTERVAL_SECS));
            let _ = sqlx::query("UPDATE device_authorizations SET last_polled_at = now() WHERE id = $1")
                .bind(row.id)
                .execute(&state.pool)
                .await;
            if slow_down {
                Err(super::oauth_token_error("slow_down", "polling too fast"))
            } else {
                Err(super::oauth_token_error(
                    "authorization_pending",
                    "the user has not completed the device authorization yet",
                ))
            }
        }
    }
}
