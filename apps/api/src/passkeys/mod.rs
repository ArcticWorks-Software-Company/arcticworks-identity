//! Passkey registration and authentication (WebAuthn).

use axum::extract::{Path, State};
use axum::http::header;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::audit::{self, ActorType, AuditEvent};
use crate::authn::{self, Authed};
use crate::correlation::HttpMeta;
use crate::error::{ApiError, ApiResult, MapInternal};
use crate::ids::new_id;
use crate::state::AppState;

pub mod webauthn;

const RL_AUTH_START: (u32, u64) = (10, 60); // 10 per minute per IP
const CHALLENGE_TTL_SECS: i64 = 300;

// ------------------------------------------------------------------- models

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyJson {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct PasskeyRow {
    id: Uuid,
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

// ------------------------------------------------------------------ requests

#[derive(Deserialize)]
pub struct RegisterFinishReq {
    #[serde(default)]
    pub name: Option<String>,
    /// Credential id (base64url).
    pub id: String,
    pub response: RegisterResponse,
}

#[derive(Deserialize)]
pub struct RegisterResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    #[serde(default)]
    pub transports: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct AuthFinishReq {
    /// Credential id (base64url).
    pub id: String,
    pub response: AuthResponse,
}

#[derive(Deserialize)]
pub struct AuthResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle", default)]
    pub user_handle: Option<String>,
}

#[derive(Deserialize)]
pub struct RenameReq {
    pub name: String,
}

// -------------------------------------------------------------------- routes

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/passkeys", get(list_passkeys))
        .route("/api/passkeys/register/start", post(register_start))
        .route("/api/passkeys/register/finish", post(register_finish))
        .route("/api/passkeys/auth/start", post(auth_start))
        .route("/api/passkeys/auth/finish", post(auth_finish))
        .route("/api/passkeys/{id}/rename", post(rename_passkey))
        .route("/api/passkeys/{id}", delete(delete_passkey))
}

// ---------------------------------------------------------------- handlers

async fn list_passkeys(State(state): State<AppState>, authed: Authed) -> ApiResult<Response> {
    let rows = sqlx::query_as::<_, PasskeyRow>(
        "SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(authed.0.user.id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list passkeys")?;
    Ok(Json(serde_json::json!({ "passkeys": rows })).into_response())
}

async fn register_start(State(state): State<AppState>, authed: Authed) -> ApiResult<Response> {
    let challenge = webauthn::new_challenge();
    store_challenge(&state, authed.0.user.id, "register", &challenge).await?;

    let excluded: Vec<String> = sqlx::query_scalar("SELECT credential_id FROM passkeys WHERE user_id = $1")
        .bind(authed.0.user.id)
        .fetch_all(&state.pool)
        .await
        .map_internal("load existing passkeys")?;

    let options = serde_json::json!({
        "rp": { "id": state.config.rp_id, "name": "ArcticWorks Identity" },
        "user": {
            "id": webauthn::b64url_encode(&webauthn::user_handle(authed.0.user.id)),
            "name": authed.0.user.email,
            "displayName": authed.0.user.display_name,
        },
        "challenge": challenge,
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -257 },
            { "type": "public-key", "alg": -8 }
        ],
        "timeout": webauthn::TIMEOUT_MS,
        "attestation": "none",
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "residentKey": "preferred",
            "userVerification": "preferred"
        },
        "excludeCredentials": excluded.iter().map(|id| serde_json::json!({ "type": "public-key", "id": id })).collect::<Vec<_>>()
    });

    Ok(Json(serde_json::json!({ "options": options })).into_response())
}

async fn register_finish(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Json(req): Json<RegisterFinishReq>,
) -> ApiResult<Response> {
    let client_data = webauthn::b64url_decode(&req.response.client_data_json)?;
    let attestation_object = webauthn::b64url_decode(&req.response.attestation_object)?;

    // Challenge must exist, be ours, and be unused.
    let challenge = extract_challenge(&client_data)?;
    let row = consume_challenge(&state, authed.0.user.id, "register", &challenge).await?;
    let challenge_value = row;

    webauthn::parse_client_data(
        &client_data,
        "webauthn.create",
        &challenge_value,
        &state.config.rp_origins_set(),
    )?;

    let auth_data = webauthn::parse_attestation_object(&attestation_object)?;
    let parsed = webauthn::parse_authenticator_data(&auth_data, &state.config.rp_id, true)?;
    let webauthn::ParsedAuthData {
        flags,
        counter,
        credential_id,
        cose_key,
    } = parsed;
    let Some(credential_id) = credential_id else {
        return Err(ApiError::Validation("missing credential id".into()));
    };
    let Some(cose_key) = &cose_key else {
        return Err(ApiError::Validation("missing COSE key".into()));
    };

    // The client-reported id must match the authenticator-provided one.
    let client_credential_id = webauthn::b64url_decode(&req.id)?;
    if client_credential_id != credential_id {
        return Err(ApiError::Validation("credential id mismatch".into()));
    }

    // Serialize the COSE key for storage.
    let cose_bytes = cose_key_to_bytes(cose_key)?;

    let passkey_id = new_id();
    let name = req
        .name
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| "Passkey".to_string())
        .trim()
        .chars()
        .take(64)
        .collect::<String>();

    let transports = req
        .response
        .transports
        .map(|t| serde_json::to_value(t).unwrap_or_else(|_| serde_json::json!([])))
        .unwrap_or_else(|| serde_json::json!([]));

    let inserted = sqlx::query(
        r#"
        INSERT INTO passkeys (id, user_id, name, credential_id, public_key, sign_count, transports, last_used_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)
        "#,
    )
    .bind(passkey_id)
    .bind(authed.0.user.id)
    .bind(&name)
    .bind(webauthn::b64url_encode(&credential_id))
    .bind(&cose_bytes)
    .bind(counter as i64)
    .bind(transports)
    .execute(&state.pool)
    .await;

    if let Err(e) = inserted {
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            return Err(ApiError::Conflict("this passkey is already registered".into()));
        }
        return Err(ApiError::internal("store passkey", e));
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "passkey.registered",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: Some("passkey"),
            target_id: Some(passkey_id),
            metadata: serde_json::json!({ "name": name, "uv": webauthn::user_verified(flags) }),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "passkey": { "id": passkey_id, "name": name, "createdAt": chrono::Utc::now() }
        })),
    )
        .into_response())
}

async fn auth_start(State(state): State<AppState>, meta: HttpMeta) -> ApiResult<Response> {
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("passkey-auth", &ip_key, RL_AUTH_START.0, RL_AUTH_START.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    let challenge = webauthn::new_challenge();
    store_challenge(&state, Uuid::nil(), "auth", &challenge).await?;

    let options = serde_json::json!({
        "challenge": challenge,
        "timeout": webauthn::TIMEOUT_MS,
        "rpId": state.config.rp_id,
        "allowCredentials": [],
        "userVerification": "preferred"
    });

    Ok(Json(serde_json::json!({ "options": options })).into_response())
}

async fn auth_finish(
    State(state): State<AppState>,
    meta: HttpMeta,
    Json(req): Json<AuthFinishReq>,
) -> ApiResult<Response> {
    let client_data = webauthn::b64url_decode(&req.response.client_data_json)?;
    let auth_data = webauthn::b64url_decode(&req.response.authenticator_data)?;
    let signature = webauthn::b64url_decode(&req.response.signature)?;

    let challenge = extract_challenge(&client_data)?;
    consume_challenge(&state, Uuid::nil(), "auth", &challenge).await?;

    webauthn::parse_client_data(&client_data, "webauthn.get", &challenge, &state.config.rp_origins_set())?;
    let parsed = webauthn::parse_authenticator_data(&auth_data, &state.config.rp_id, false)?;

    // Find the credential.
    let credential_id = webauthn::b64url_decode(&req.id)?;
    let cred = sqlx::query_as::<_, CredRow>(
        r#"
        SELECT p.id, p.user_id, p.credential_id, p.public_key, p.sign_count,
               u.email, u.display_name, u.email_verified_at
        FROM passkeys p
        JOIN users u ON u.id = p.user_id
        WHERE p.credential_id = $1
        "#,
    )
    .bind(webauthn::b64url_encode(&credential_id))
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup passkey")?;

    let Some(cred) = cred else {
        return Err(ApiError::TokenInvalid);
    };
    if cred.email_verified_at.is_none() {
        return Err(ApiError::EmailNotVerified);
    }

    // userHandle must match the credential owner when present.
    if let Some(handle) = &req.response.user_handle {
        let handle_bytes = webauthn::b64url_decode(handle)?;
        if handle_bytes != webauthn::user_handle(cred.user_id) {
            return Err(ApiError::Validation("user handle mismatch".into()));
        }
    }

    let cose_key = parse_cose_bytes(&cred.public_key)?;
    if let Err(e) = webauthn::verify_signature(&cose_key, &auth_data, &client_data, &signature) {
        tracing::warn!(
            error = %e,
            sign_count = cred.sign_count,
            key = %cred.public_key,
            sig_hex = %hex_encode(&signature),
            auth_data_hex = %hex_encode(&auth_data),
            client_data = %String::from_utf8_lossy(&client_data).chars().take(200).collect::<String>(),
            "passkey assertion verification failed"
        );
        return Err(e);
    }

    // Sign counter: detect clones. Allow counter == 0 (non-counting authenticators).
    if parsed.counter != 0 && (parsed.counter as i64) <= cred.sign_count {
        return Err(ApiError::Validation("passkey sign counter regression detected".into()));
    }

    sqlx::query("UPDATE passkeys SET sign_count = $1, last_used_at = now() WHERE id = $2")
        .bind(parsed.counter as i64)
        .bind(cred.id)
        .execute(&state.pool)
        .await
        .map_internal("update passkey usage")?;

    let (session, token) = authn::create_session(
        &state.pool,
        &state.config,
        cred.user_id,
        meta.ip.map(|ip| ip.to_string()),
        meta.user_agent.clone(),
    )
    .await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "auth.passkey_login",
            actor_type: ActorType::User,
            actor_id: Some(cred.user_id),
            org_id: None,
            target_type: Some("passkey"),
            target_id: Some(cred.id),
            metadata: serde_json::json!({ "uv": webauthn::user_verified(parsed.flags) }),
        },
    )
    .await;

    let user = crate::authn::UserRow {
        id: cred.user_id,
        email: cred.email,
        display_name: cred.display_name,
        email_verified_at: cred.email_verified_at,
    };
    let mut resp = Json(serde_json::json!({ "user": crate::accounts::UserJson::from(&user) })).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, authn::session_cookie_value(&state.config, &token));
    Ok(resp)
}

async fn rename_passkey(
    State(state): State<AppState>,
    authed: Authed,
    Path(id): Path<Uuid>,
    Json(req): Json<RenameReq>,
) -> ApiResult<Response> {
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiError::Validation("passkey name must be between 1 and 64 characters".into()));
    }
    let res = sqlx::query("UPDATE passkeys SET name = $1 WHERE id = $2 AND user_id = $3")
        .bind(name)
        .bind(id)
        .bind(authed.0.user.id)
        .execute(&state.pool)
        .await
        .map_internal("rename passkey")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

async fn delete_passkey(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    let res = sqlx::query("DELETE FROM passkeys WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(authed.0.user.id)
        .execute(&state.pool)
        .await
        .map_internal("delete passkey")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "passkey.deleted",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: None,
            target_type: Some("passkey"),
            target_id: Some(id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ------------------------------------------------------------------ helpers

#[derive(sqlx::FromRow)]
struct CredRow {
    id: Uuid,
    user_id: Uuid,
    credential_id: String,
    public_key: String,
    sign_count: i64,
    email: String,
    display_name: String,
    email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn store_challenge(
    state: &AppState,
    user_id: Uuid,
    purpose: &str,
    challenge: &str,
) -> ApiResult<()> {
    sqlx::query(
        r#"
        INSERT INTO webauthn_challenges (id, challenge, user_id, purpose, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(new_id())
    .bind(challenge)
    .bind(if user_id.is_nil() { None } else { Some(user_id) })
    .bind(purpose)
    .bind(chrono::Utc::now() + chrono::Duration::seconds(CHALLENGE_TTL_SECS))
    .execute(&state.pool)
    .await
    .map_internal("store webauthn challenge")?;
    Ok(())
}

async fn consume_challenge(
    state: &AppState,
    user_id: Uuid,
    purpose: &str,
    challenge: &str,
) -> ApiResult<String> {
    let bound_user = if user_id.is_nil() { None } else { Some(user_id) };
    let row = sqlx::query_as::<_, (String,)>(
        r#"
        SELECT challenge FROM webauthn_challenges
        WHERE challenge = $1 AND purpose = $2
          AND (user_id IS NOT DISTINCT FROM $3)
          AND expires_at > now()
        "#,
    )
    .bind(challenge)
    .bind(purpose)
    .bind(bound_user)
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup webauthn challenge")?;

    let Some((stored,)) = row else {
        return Err(ApiError::TokenInvalid);
    };

    sqlx::query("DELETE FROM webauthn_challenges WHERE challenge = $1")
        .bind(challenge)
        .execute(&state.pool)
        .await
        .map_internal("consume webauthn challenge")?;

    Ok(stored)
}

/// The challenge claim from clientDataJSON (base64url), used to look up the
/// stored challenge row.
fn extract_challenge(client_data_json: &[u8]) -> ApiResult<String> {
    let cd: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|_| ApiError::Validation("clientDataJSON is not valid JSON".into()))?;
    cd.get("challenge")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| ApiError::Validation("clientDataJSON missing challenge".into()))
}

/// Serialize a CoseKey back to raw COSE bytes for storage. We only ever
/// store keys we parsed from authenticators, so this is lossless for our
/// three supported key types.
pub(crate) fn cose_key_to_bytes(key: &webauthn::CoseKey) -> ApiResult<String> {
    use ciborium::value::Integer as CborInt;
    use ciborium::Value as V;
    let value: V = match key {
        webauthn::CoseKey::Ec2 { x, y, alg } => V::Map(vec![
            (V::Integer(CborInt::from(1)), V::Integer(CborInt::from(2))),
            (V::Integer(CborInt::from(3)), V::Integer(CborInt::from(alg_to_cose(*alg)))),
            (V::Integer(CborInt::from(-1)), V::Integer(CborInt::from(1))),
            (V::Integer(CborInt::from(-2)), V::Bytes(x.clone())),
            (V::Integer(CborInt::from(-3)), V::Bytes(y.clone())),
        ]),
        webauthn::CoseKey::Rsa { n, e, alg } => V::Map(vec![
            (V::Integer(CborInt::from(1)), V::Integer(CborInt::from(3))),
            (V::Integer(CborInt::from(3)), V::Integer(CborInt::from(alg_to_cose(*alg)))),
            (V::Integer(CborInt::from(-1)), V::Bytes(n.clone())),
            (V::Integer(CborInt::from(-2)), V::Bytes(e.clone())),
        ]),
        webauthn::CoseKey::Eddsa { x, alg } => V::Map(vec![
            (V::Integer(CborInt::from(1)), V::Integer(CborInt::from(1))),
            (V::Integer(CborInt::from(3)), V::Integer(CborInt::from(alg_to_cose(*alg)))),
            (V::Integer(CborInt::from(-1)), V::Integer(CborInt::from(6))),
            (V::Integer(CborInt::from(-2)), V::Bytes(x.clone())),
        ]),
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&value, &mut buf)
        .map_err(|_| ApiError::internal("serialize cose key", "ciborium encode failed"))?;
    Ok(webauthn::b64url_encode(&buf))
}

fn parse_cose_bytes(stored: &str) -> ApiResult<webauthn::CoseKey> {
    let bytes = webauthn::b64url_decode(stored)?;
    webauthn::parse_cose_key(&bytes)
}

fn alg_to_cose(alg: webauthn::Algorithm) -> i64 {
    match alg {
        webauthn::Algorithm::Es256 => -7,
        webauthn::Algorithm::Rs256 => -257,
        webauthn::Algorithm::EdDsa => -8,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
