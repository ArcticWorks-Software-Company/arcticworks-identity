//! Outbound webhooks: org-scoped HTTPS endpoints that receive audit events
//! with HMAC-SHA256 request signatures. Delivery is asynchronous — the
//! audit insert never waits on a webhook — with one retry per event and a
//! delivery log per endpoint.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::audit::{self, ActorType, AuditEvent};
use crate::authn::Authed;
use crate::correlation::HttpMeta;
use crate::error::{ApiError, ApiResult, MapInternal};
use crate::ids::new_id;
use crate::rbac;
use crate::state::AppState;
use crate::totp::{decrypt_secret, encrypt_secret};
use crate::tokens::{random_secret, secret_preview};
use secrecy::ExposeSecret;

const RL_WEBHOOK_CREATE: (u32, u64) = (10, 3600); // 10 per hour per IP
const MAX_DELIVERY_ATTEMPTS: u32 = 2;
const DELIVERY_RETRY_DELAY_MS: u64 = 1000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/orgs/{org_id}/webhooks",
            get(list_webhooks).post(create_webhook),
        )
        .route(
            "/api/orgs/{org_id}/webhooks/{webhook_id}",
            axum::routing::patch(update_webhook).delete(delete_webhook),
        )
        .route(
            "/api/orgs/{org_id}/webhooks/{webhook_id}/rotate-secret",
            post(rotate_webhook_secret),
        )
        .route(
            "/api/orgs/{org_id}/webhooks/{webhook_id}/deliveries",
            get(list_deliveries),
        )
}

// ------------------------------------------------------------------ models

#[derive(Debug, sqlx::FromRow)]
struct WebhookRow {
    id: Uuid,
    org_id: Uuid,
    url: String,
    secret_nonce: String,
    secret_ciphertext: String,
    secret_preview: String,
    enabled: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookJson {
    id: Uuid,
    url: String,
    secret_preview: String,
    enabled: bool,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<WebhookRow> for WebhookJson {
    fn from(row: WebhookRow) -> Self {
        WebhookJson {
            id: row.id,
            url: row.url,
            secret_preview: row.secret_preview,
            enabled: row.enabled,
            created_at: row.created_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateWebhookReq {
    url: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateWebhookReq {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

// ---------------------------------------------------------------- validation

/// Webhook targets must be http(s) without embedded credentials, so secrets
/// are never logged as part of a URL.
fn validate_webhook_url(url: &str) -> ApiResult<String> {
    let parsed = url::Url::parse(url)
        .map_err(|_| ApiError::Validation("webhook URL must be a valid http(s) URL".into()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ApiError::Validation("webhook URL must use http or https".into()));
    }
    if parsed.host_str().is_none() {
        return Err(ApiError::Validation("webhook URL must include a host".into()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ApiError::Validation("webhook URL must not embed credentials".into()));
    }
    Ok(parsed.to_string())
}

async fn load_webhook(state: &AppState, org_id: Uuid, webhook_id: Uuid) -> ApiResult<WebhookRow> {
    sqlx::query_as::<_, WebhookRow>(
        "SELECT * FROM webhook_endpoints WHERE id = $1 AND org_id = $2",
    )
    .bind(webhook_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load webhook")?
    .ok_or(ApiError::NotFound)
}

// ----------------------------------------------------------------- handlers

/// List webhook endpoints of an organization.
async fn list_webhooks(
    State(state): State<AppState>,
    authed: Authed,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::WEBHOOKS_MANAGE).await?;
    let rows = sqlx::query_as::<_, WebhookRow>(
        "SELECT * FROM webhook_endpoints WHERE org_id = $1 ORDER BY created_at",
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list webhooks")?;
    let items: Vec<WebhookJson> = rows.into_iter().map(WebhookJson::from).collect();
    Ok(Json(serde_json::json!({ "webhooks": items })).into_response())
}

/// Register a webhook endpoint. The signing secret is returned exactly once.
async fn create_webhook(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(org_id): Path<Uuid>,
    Json(req): Json<CreateWebhookReq>,
) -> ApiResult<Response> {
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state
        .rl
        .check("webhook-create", &ip_key, RL_WEBHOOK_CREATE.0, RL_WEBHOOK_CREATE.1)
        .await
    {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::WEBHOOKS_MANAGE).await?;
    authed.0.require_reauth(&state.config)?;

    let url = validate_webhook_url(&req.url)?;
    let secret = random_secret("awwh");
    let secret_bytes = secret.expose_secret().as_bytes().to_vec();
    let (nonce, ciphertext) = encrypt_secret(&state.totp_key, &secret_bytes)?;

    let id = new_id();
    sqlx::query(
        r#"
        INSERT INTO webhook_endpoints
            (id, org_id, url, secret_nonce, secret_ciphertext, secret_preview, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(id)
    .bind(org_id)
    .bind(&url)
    .bind(&nonce)
    .bind(&ciphertext)
    .bind(secret_preview(secret.expose_secret()))
    .bind(authed.0.user.id)
    .execute(&state.pool)
    .await
    .map_internal("create webhook")?;

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: "webhook.created",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("webhook"),
            target_id: Some(id),
            metadata: serde_json::json!({ "url": url }),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "webhook": { "id": id, "url": url, "secretPreview": secret_preview(secret.expose_secret()), "enabled": true },
            "secret": secret.expose_secret(),
        })),
    )
        .into_response())
}

/// Update a webhook endpoint (URL or enabled state).
async fn update_webhook(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, webhook_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateWebhookReq>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::WEBHOOKS_MANAGE).await?;
    authed.0.require_reauth(&state.config)?;
    load_webhook(&state, org_id, webhook_id).await?;

    let url = req.url.as_deref().map(validate_webhook_url).transpose()?;
    let res = match (&url, req.enabled) {
        (Some(url), Some(enabled)) => {
            sqlx::query(
                "UPDATE webhook_endpoints SET url = $1, enabled = $2, updated_at = now() WHERE id = $3 AND org_id = $4",
            )
            .bind(url)
            .bind(enabled)
            .bind(webhook_id)
            .bind(org_id)
            .execute(&state.pool)
            .await
            .map_internal("update webhook")?
        }
        (Some(url), None) => {
            sqlx::query("UPDATE webhook_endpoints SET url = $1, updated_at = now() WHERE id = $2 AND org_id = $3")
                .bind(url)
                .bind(webhook_id)
                .bind(org_id)
                .execute(&state.pool)
                .await
                .map_internal("update webhook")?
        }
        (None, Some(enabled)) => {
            sqlx::query("UPDATE webhook_endpoints SET enabled = $1, updated_at = now() WHERE id = $2 AND org_id = $3")
                .bind(enabled)
                .bind(webhook_id)
                .bind(org_id)
                .execute(&state.pool)
                .await
                .map_internal("update webhook")?
        }
        (None, None) => {
            return Err(ApiError::Validation("nothing to update".into()));
        }
    };
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: "webhook.updated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("webhook"),
            target_id: Some(webhook_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

/// Delete a webhook endpoint.
async fn delete_webhook(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, webhook_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::WEBHOOKS_MANAGE).await?;
    authed.0.require_reauth(&state.config)?;
    let res = sqlx::query("DELETE FROM webhook_endpoints WHERE id = $1 AND org_id = $2")
        .bind(webhook_id)
        .bind(org_id)
        .execute(&state.pool)
        .await
        .map_internal("delete webhook")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: "webhook.deleted",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("webhook"),
            target_id: Some(webhook_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Rotate the signing secret; the previous one stops being used immediately.
async fn rotate_webhook_secret(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, webhook_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::WEBHOOKS_MANAGE).await?;
    authed.0.require_reauth(&state.config)?;
    load_webhook(&state, org_id, webhook_id).await?;

    let secret = random_secret("awwh");
    let (nonce, ciphertext) = encrypt_secret(&state.totp_key, secret.expose_secret().as_bytes())?;
    sqlx::query(
        r#"
        UPDATE webhook_endpoints
        SET secret_nonce = $1, secret_ciphertext = $2, secret_preview = $3, updated_at = now()
        WHERE id = $4 AND org_id = $5
        "#,
    )
    .bind(&nonce)
    .bind(&ciphertext)
    .bind(secret_preview(secret.expose_secret()))
    .bind(webhook_id)
    .bind(org_id)
    .execute(&state.pool)
    .await
    .map_internal("rotate webhook secret")?;

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: "webhook.secret_rotated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("webhook"),
            target_id: Some(webhook_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({
        "secret": secret.expose_secret(),
        "secretPreview": secret_preview(secret.expose_secret()),
    }))
    .into_response())
}

/// Recent delivery attempts for an endpoint.
async fn list_deliveries(
    State(state): State<AppState>,
    authed: Authed,
    Path((org_id, webhook_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::WEBHOOKS_MANAGE).await?;
    load_webhook(&state, org_id, webhook_id).await?;
    let rows = sqlx::query_as::<_, DeliveryRow>(
        r#"
        SELECT d.id, d.event_id, d.event_type, d.status, d.attempts, d.response_status, d.created_at
        FROM webhook_deliveries d
        WHERE d.endpoint_id = $1
        ORDER BY d.created_at DESC
        LIMIT 50
        "#,
    )
    .bind(webhook_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list webhook deliveries")?;
    Ok(Json(serde_json::json!({ "deliveries": rows })).into_response())
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct DeliveryRow {
    id: Uuid,
    event_id: Uuid,
    event_type: String,
    status: String,
    attempts: i32,
    response_status: Option<i32>,
    created_at: chrono::DateTime<chrono::Utc>,
}

// ----------------------------------------------------------------- delivery

/// Schedule asynchronous delivery of an org-scoped audit event.
pub fn schedule(state: &AppState, event_id: Uuid, org_id: Uuid) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = deliver_event(&state, org_id, event_id).await {
            tracing::warn!(error = %e, event_id = %event_id, "webhook dispatch failed");
        }
    });
}

async fn deliver_event(state: &AppState, org_id: Uuid, event_id: Uuid) -> ApiResult<()> {
    #[derive(sqlx::FromRow)]
    struct EventRow {
        correlation_id: Uuid,
        event_type: String,
        actor_type: String,
        actor_id: Option<Uuid>,
        org_id: Option<Uuid>,
        target_type: Option<String>,
        target_id: Option<Uuid>,
        ip: Option<String>,
        user_agent: Option<String>,
        metadata: serde_json::Value,
        occurred_at: chrono::DateTime<chrono::Utc>,
    }

    let event = sqlx::query_as::<_, EventRow>(
        r#"
        SELECT correlation_id, event_type, actor_type, actor_id, org_id,
               target_type, target_id, ip::text AS ip, user_agent, metadata, occurred_at
        FROM audit_events WHERE id = $1
        "#,
    )
    .bind(event_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load audit event for webhook")?
    .ok_or_else(|| ApiError::NotFound)?;

    let endpoints = sqlx::query_as::<_, WebhookRow>(
        "SELECT * FROM webhook_endpoints WHERE org_id = $1 AND enabled = true",
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("load webhook endpoints")?;
    if endpoints.is_empty() {
        return Ok(());
    }

    let payload = serde_json::to_string(&serde_json::json!({
        "eventId": event_id,
        "eventType": event.event_type,
        "occurredAt": event.occurred_at,
        "correlationId": event.correlation_id,
        "actorType": event.actor_type,
        "actorId": event.actor_id,
        "orgId": event.org_id,
        "targetType": event.target_type,
        "targetId": event.target_id,
        "ip": event.ip,
        "userAgent": event.user_agent,
        "metadata": event.metadata,
    }))
    .map_err(|e| ApiError::internal("serialize webhook payload", e))?;

    for endpoint in endpoints {
        let secret = decrypt_secret(
            &state.totp_key,
            &endpoint.secret_nonce,
            &endpoint.secret_ciphertext,
        )?;
        let (status, attempts, response_status) =
            deliver_once(state, &endpoint.url, &secret, &payload).await;
        sqlx::query(
            r#"
            INSERT INTO webhook_deliveries
                (id, endpoint_id, event_id, event_type, status, attempts, response_status)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(new_id())
        .bind(endpoint.id)
        .bind(event_id)
        .bind(&payload_event_type(&payload))
        .bind(status)
        .bind(attempts)
        .bind(response_status)
        .execute(&state.pool)
        .await
        .map_internal("record webhook delivery")?;
    }
    Ok(())
}

fn payload_event_type(payload: &str) -> String {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()
        .and_then(|v| v.get("eventType").and_then(|t| t.as_str()).map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

/// One endpoint delivery with a single retry. Returns
/// (status, attempts, optional response status).
async fn deliver_once(
    state: &AppState,
    url: &str,
    secret: &[u8],
    payload: &str,
) -> (&'static str, i32, Option<i32>) {
    let mut attempts = 0;
    loop {
        attempts += 1;
        let timestamp = chrono::Utc::now().timestamp();
        let signature = sign_payload(secret, timestamp, payload);
        let result = state
            .webhook_client
            .post(url)
            .header("content-type", "application/json")
            .header(
                "x-arcticworks-signature",
                format!("t={timestamp},v1={signature}"),
            )
            .header("user-agent", "ArcticWorks-Identity/0.1")
            .body(payload.to_string())
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                return ("success", attempts, Some(resp.status().as_u16() as i32));
            }
            Ok(resp) if attempts < MAX_DELIVERY_ATTEMPTS as i32 => {
                tracing::warn!(
                    url,
                    status = %resp.status(),
                    "webhook delivery failed; retrying"
                );
                tokio::time::sleep(std::time::Duration::from_millis(DELIVERY_RETRY_DELAY_MS)).await;
                continue;
            }
            Ok(resp) => {
                return ("failed", attempts, Some(resp.status().as_u16() as i32));
            }
            Err(e) if attempts < MAX_DELIVERY_ATTEMPTS as i32 => {
                tracing::warn!(url, error = %e, "webhook delivery error; retrying");
                tokio::time::sleep(std::time::Duration::from_millis(DELIVERY_RETRY_DELAY_MS)).await;
                continue;
            }
            Err(_) => {
                return ("failed", attempts, None);
            }
        }
    }
}

/// HMAC-SHA256 over `{timestamp}.{payload}`, hex-encoded (Slack-style).
pub fn sign_payload(secret: &[u8], timestamp: i64, payload: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(secret)
        .expect("hmac accepts any key length");
    mac.update(format!("{timestamp}.{payload}").as_bytes());
    let digest = mac.finalize().into_bytes();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify a signature (used by tests and by receiving implementations).
pub fn verify_signature(secret: &[u8], timestamp: i64, payload: &str, signature: &str) -> bool {
    let expected = sign_payload(secret, timestamp, payload);
    crate::tokens::tokens_equal(&expected, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_stable_and_verifiable() {
        let secret = b"0123456789abcdef";
        let sig = sign_payload(secret, 1_700_000_000, r#"{"eventType":"team.created"}"#);
        assert_eq!(sig.len(), 64);
        assert!(verify_signature(
            secret,
            1_700_000_000,
            r#"{"eventType":"team.created"}"#,
            &sig
        ));
        assert!(!verify_signature(
            secret,
            1_700_000_001,
            r#"{"eventType":"team.created"}"#,
            &sig
        ));
    }

    #[test]
    fn url_validation_rejects_non_http_and_credentials() {
        assert!(validate_webhook_url("https://hooks.example.com/x").is_ok());
        assert!(validate_webhook_url("http://localhost:9999/hook").is_ok());
        assert!(validate_webhook_url("file:///etc/passwd").is_err());
        assert!(validate_webhook_url("ftp://example.com/hook").is_err());
        assert!(validate_webhook_url("https://user:pass@example.com/hook").is_err());
        assert!(validate_webhook_url("not a url").is_err());
    }
}
