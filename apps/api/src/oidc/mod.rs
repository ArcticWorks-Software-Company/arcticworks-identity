//! OIDC / OAuth 2.0 provider: discovery, JWKS, authorization + consent,
//! token endpoint (PKCE, refresh rotation, client credentials), userinfo,
//! RFC 7009 revocation, and OIDC client management (applications).

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use utoipa::ToSchema;

use crate::audit::{self, ActorType, AuditEvent};
use crate::authn::{self, Authed, OptAuthed};
use crate::correlation::HttpMeta;
use crate::error::{ApiError, ApiResult, MapInternal};
use crate::ids::new_id;
use crate::machine;
use crate::rbac;
use crate::state::AppState;
use crate::tokens::{hash_token, random_secret, random_token, secret_preview, tokens_equal};
use crate::util;
use base64::Engine;
use secrecy::ExposeSecret;

pub mod keys;
pub mod seed;
pub mod token;

const RL_TOKEN: (u32, u64) = (30, 60); // 30 per minute per IP
const RL_APP_CREATE: (u32, u64) = (10, 3600); // 10 per hour per IP
const SUPPORTED_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];

// ------------------------------------------------------------------- models

#[derive(Debug, sqlx::FromRow)]
pub struct OidcClientRow {
    pub id: Uuid,
    pub org_id: Option<Uuid>,
    pub name: String,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub secret_preview: String,
    pub redirect_uris: serde_json::Value,
    pub is_confidential: bool,
    pub application_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationJson {
    pub id: Uuid,
    pub name: String,
    pub client_id: String,
    pub is_confidential: bool,
    pub redirect_uris: Vec<String>,
    pub application_enabled: bool,
    pub secret_preview: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<OidcClientRow> for ApplicationJson {
    fn from(c: OidcClientRow) -> Self {
        ApplicationJson {
            id: c.id,
            name: c.name,
            client_id: c.client_id,
            is_confidential: c.is_confidential,
            redirect_uris: c
                .redirect_uris
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(ToOwned::to_owned)).collect())
                .unwrap_or_default(),
            application_enabled: c.application_enabled,
            secret_preview: c.secret_preview,
            created_at: c.created_at,
        }
    }
}

// ------------------------------------------------------------------ requests

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateApplicationReq {
    pub name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub is_confidential: bool,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateApplicationReq {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub application_enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct ConsentInfoReq {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

#[derive(Deserialize)]
pub struct ConsentReq {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    pub decision: String, // "approve" | "deny"
}

/// Authorization request parameters, shared by the authorize and consent
/// endpoints.
#[derive(Debug, Clone)]
struct AuthRequest {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    nonce: Option<String>,
    prompt: Option<String>,
}

// -------------------------------------------------------------------- routes

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/oidc/jwks.json", get(jwks_endpoint))
        .route("/oidc/authorize", get(authorize))
        .route("/api/oidc/consent-info", get(consent_info))
        .route("/oidc/consent", post(consent))
        .route("/oidc/token", post(token_endpoint))
        .route("/oidc/userinfo", get(userinfo))
        .route("/oidc/revoke", post(revoke))
        .route(
            "/api/orgs/{org_id}/applications",
            get(list_applications).post(create_application),
        )
        .route(
            "/api/orgs/{org_id}/applications/{client_id}",
            axum::routing::patch(update_application).delete(delete_application),
        )
        .route(
            "/api/orgs/{org_id}/applications/{client_id}/rotate-secret",
            post(rotate_client_secret),
        )
        .route("/api/account/applications", get(account_applications))
        .route(
            "/api/account/applications/{grant_id}/revoke",
            post(revoke_account_grant),
        )
}

// ------------------------------------------------------------- discovery/JWKS

async fn discovery(State(state): State<AppState>) -> ApiResult<Response> {
    let iss = state.config.issuer().to_string();
    let json = serde_json::json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/oidc/authorize"),
        "token_endpoint": format!("{iss}/oidc/token"),
        "userinfo_endpoint": format!("{iss}/oidc/userinfo"),
        "jwks_uri": format!("{iss}/oidc/jwks.json"),
        "revocation_endpoint": format!("{iss}/oidc/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "claims_supported": ["sub", "name", "email", "email_verified", "org"],
        "response_modes_supported": ["query"],
    });
    Ok(Json(json).into_response())
}

async fn jwks_endpoint(State(state): State<AppState>) -> ApiResult<Response> {
    let jwks = keys::jwks(&state.pool).await?;
    Ok(Json(jwks).into_response())
}

// -------------------------------------------------------------- authorization

async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    authed: OptAuthed,
) -> ApiResult<Response> {
    let Some(req) = parse_auth_request(&params) else {
        return Ok(Json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "missing or malformed authorization parameters",
        }))
        .into_response());
    };

    // Validate the client and redirect URI before anything else.
    let Some(client) = load_client(&state, &req.client_id).await? else {
        return Ok(client_error_page("invalid_client", "unknown client"));
    };
    if !client.application_enabled {
        return Ok(client_error_page("unauthorized_client", "application is disabled"));
    }
    if !redirect_registered(&client, &req.redirect_uri) {
        return Ok(client_error_page("invalid_request", "redirect_uri is not registered for this client"));
    }

    let fail = |error: &str, description: &str| {
        oauth_redirect_error(&req.redirect_uri, req.state.as_deref(), error, description)
    };

    if req.response_type != "code" {
        return Ok(fail("unsupported_response_type", "only response_type=code is supported"));
    }
    if req.code_challenge_method != "S256" || req.code_challenge.is_empty() {
        return Ok(fail("invalid_request", "PKCE with S256 is required"));
    }
    let scopes = parse_scopes(&req.scope)?;
    if !scopes.contains(&"openid".to_string()) {
        return Ok(fail("invalid_scope", "the openid scope is required"));
    }

    let user = match &authed.0 {
        Some(su) if req.prompt.as_deref() != Some("login") => su.clone(),
        _ => {
            // Not logged in (or forced re-login): send the user to the
            // Identity login page, returning to this exact authorize URL.
            let continue_url = build_authorize_url(&state, &req);
            return Ok(Redirect::to(&format!("{}/login?continue={}", state.config.web_origin, urlencode(&continue_url))).into_response());
        }
    };

    let org_id = client.org_id;
    let Some(org_id) = org_id else {
        return Ok(fail("unauthorized_client", "application has no organization"));
    };
    if !rbac::is_active_member(&state.pool, user.user.id, org_id).await? {
        return Ok(fail(
            "access_denied",
            &format!(
                "Your ArcticWorks Identity account is not an active member of the organization that owns {}. Ask an organization administrator to add your account, then try again.",
                client.name
            ),
        ));
    }

    // Consent: skip when the user already granted the same (or wider) scope set.
    let grant_ok = grant_covers(&state, &client.client_id, user.user.id, org_id, &scopes).await?;
    let needs_consent = req.prompt.as_deref() == Some("consent") || !grant_ok;
    tracing::debug!(
        grant_ok,
        needs_consent,
        user_id = %user.user.id,
        org_id = %org_id,
        scopes = ?scopes,
        "authorize consent decision"
    );

    if needs_consent {
        let consent_url = format!(
            "{}/authorize?client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256&nonce={}&org_id={}",
            state.config.web_origin,
            urlencode(&req.client_id),
            urlencode(&req.redirect_uri),
            urlencode(&req.scope),
            urlencode(req.state.as_deref().unwrap_or("")),
            urlencode(&req.code_challenge),
            urlencode(req.nonce.as_deref().unwrap_or("")),
            org_id,
        );
        return Ok(Redirect::to(&consent_url).into_response());
    }

    let code = issue_auth_code(&state, &client, user.user.id, org_id, &scopes, &req).await?;
    Ok(Redirect::to(&format!(
        "{}?code={}&state={}",
        req.redirect_uri,
        urlencode(&code),
        urlencode(req.state.as_deref().unwrap_or(""))
    ))
    .into_response())
}

async fn consent_info(
    State(state): State<AppState>,
    authed: Authed,
    Query(req): Query<ConsentInfoReq>,
) -> ApiResult<Response> {
    let Some(client) = load_client(&state, &req.client_id).await? else {
        return Err(ApiError::Validation("unknown client".into()));
    };
    if !redirect_registered(&client, &req.redirect_uri) {
        return Err(ApiError::Validation("redirect_uri is not registered".into()));
    }
    let scopes = parse_scopes(&req.scope)?;

    let org = sqlx::query_as::<_, (String, String)>(
        "SELECT name, slug FROM organizations WHERE id = $1",
    )
    .bind(client.org_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load organization")?
    .ok_or_else(|| ApiError::Validation("application has no organization".into()))?;

    Ok(Json(serde_json::json!({
        "client": { "clientId": client.client_id, "name": client.name },
        "organization": { "name": org.0, "slug": org.1 },
        "scopes": scopes,
        "redirectUri": req.redirect_uri,
        "state": req.state,
        "user": {
            "id": authed.0.user.id,
            "email": authed.0.user.email,
            "displayName": authed.0.user.display_name,
        },
    }))
    .into_response())
}

async fn consent(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Form(req): Form<ConsentReq>,
) -> ApiResult<Response> {
    let params: HashMap<String, String> = HashMap::from_iter(vec![
        ("client_id".into(), req.client_id.clone()),
        ("redirect_uri".into(), req.redirect_uri.clone()),
        ("response_type".into(), "code".into()),
        ("scope".into(), req.scope.clone()),
        ("state".into(), req.state.clone().unwrap_or_default()),
        ("code_challenge".into(), req.code_challenge.clone()),
        ("code_challenge_method".into(), req.code_challenge_method.clone().unwrap_or_else(|| "S256".into())),
        ("nonce".into(), req.nonce.clone().unwrap_or_default()),
    ]);
    let Some(areq) = parse_auth_request(&params) else {
        return Err(ApiError::Validation("malformed authorization parameters".into()));
    };

    let Some(client) = load_client(&state, &areq.client_id).await? else {
        return Err(ApiError::Validation("unknown client".into()));
    };
    if !client.application_enabled {
        return Err(ApiError::Validation("application is disabled".into()));
    }
    if !redirect_registered(&client, &areq.redirect_uri) {
        return Err(ApiError::Validation("redirect_uri is not registered".into()));
    }
    let scopes = parse_scopes(&areq.scope)?;
    let Some(org_id) = client.org_id else {
        return Err(ApiError::Validation("application has no organization".into()));
    };
    if !rbac::is_active_member(&state.pool, authed.0.user.id, org_id).await? {
        return Err(ApiError::Forbidden);
    }

    if req.decision == "deny" {
        audit::record(
            &state.pool,
            &meta,
            AuditEvent {
                event_type: "oauth.consent_denied",
                actor_type: ActorType::User,
                actor_id: Some(authed.0.user.id),
                org_id: Some(org_id),
                target_type: Some("client"),
                target_id: None,
                metadata: serde_json::json!({ "clientId": client.client_id }),
            },
        )
        .await;
        return Ok(oauth_redirect_error(
            &areq.redirect_uri,
            areq.state.as_deref(),
            "access_denied",
            "the user denied the request",
        )
        .into_response());
    }
    if req.decision != "approve" {
        return Err(ApiError::Validation("decision must be approve or deny".into()));
    }

    let code = issue_auth_code(&state, &client, authed.0.user.id, org_id, &scopes, &areq).await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "oauth.consent_granted",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("client"),
            target_id: None,
            metadata: serde_json::json!({ "clientId": client.client_id, "scopes": scopes }),
        },
    )
    .await;

    Ok(Redirect::to(&format!(
        "{}?code={}&state={}",
        areq.redirect_uri,
        urlencode(&code),
        urlencode(areq.state.as_deref().unwrap_or(""))
    ))
    .into_response())
}

async fn issue_auth_code(
    state: &AppState,
    client: &OidcClientRow,
    user_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
    req: &AuthRequest,
) -> ApiResult<String> {
    let code = random_token();
    sqlx::query(
        r#"
        INSERT INTO auth_codes (id, code_hash, client_id, user_id, org_id, scopes,
                                pkce_challenge, redirect_uri, nonce, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(new_id())
    .bind(hash_token(&code))
    .bind(&client.client_id)
    .bind(user_id)
    .bind(org_id)
    .bind(serde_json::to_value(scopes).unwrap_or_else(|_| serde_json::json!([])))
    .bind(&req.code_challenge)
    .bind(&req.redirect_uri)
    .bind(&req.nonce)
    .bind(chrono::Utc::now() + chrono::Duration::from_std(state.config.auth_code_ttl).unwrap_or_default())
    .execute(&state.pool)
    .await
    .map_internal("issue auth code")?;
    Ok(code)
}

/// Whether the user's stored grant already covers the requested scopes.
async fn grant_covers(
    state: &AppState,
    client_id: &str,
    user_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
) -> ApiResult<bool> {
    let grant = sqlx::query_as::<_, (Option<serde_json::Value>,)>(
        r#"
        SELECT scopes FROM oauth_grants
        WHERE client_id = $1 AND user_id = $2 AND org_id = $3 AND revoked_at IS NULL
        "#,
    )
    .bind(client_id)
    .bind(user_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load oauth grant")?;

    let Some((Some(stored),)) = grant else {
        return Ok(false);
    };
    let stored: Vec<String> = stored
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(ToOwned::to_owned)).collect())
        .unwrap_or_default();
    Ok(scopes.iter().all(|s| stored.contains(s)))
}

// ---------------------------------------------------------------- token

async fn token_endpoint(
    State(state): State<AppState>,
    meta: HttpMeta,
    headers: axum::http::HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> ApiResult<Response> {
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("token", &ip_key, RL_TOKEN.0, RL_TOKEN.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    let Some(grant_type) = form.get("grant_type") else {
        return Err(oauth_token_error("invalid_request", "missing grant_type"));
    };

    match grant_type.as_str() {
        "authorization_code" => token_auth_code(&state, &meta, &headers, &form).await,
        "refresh_token" => token_refresh(&state, &meta, &headers, &form).await,
        "client_credentials" => token_client_credentials(&state, &meta, &headers, &form).await,
        other => Err(oauth_token_error("unsupported_grant_type", &format!("{other} is not supported"))),
    }
}

#[derive(sqlx::FromRow)]
struct CodeRow {
    id: Uuid,
    client_id: String,
    user_id: Uuid,
    org_id: Uuid,
    scopes: serde_json::Value,
    pkce_challenge: String,
    redirect_uri: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    used_at: Option<chrono::DateTime<chrono::Utc>>,
    nonce: Option<String>,
}

async fn token_auth_code(
    state: &AppState,
    meta: &HttpMeta,
    headers: &axum::http::HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Response> {
    let client = authenticate_client(state, headers, form).await?;
    if !client.is_confidential && client.has_secret {
        return Err(oauth_token_error("invalid_client", "public clients must not present a secret"));
    }

    let code = form.get("code").ok_or_else(|| oauth_token_error("invalid_request", "missing code"))?;
    let code_row = sqlx::query_as::<_, CodeRow>(
        r#"
        SELECT id, client_id, user_id, org_id, scopes, pkce_challenge, redirect_uri,
               expires_at, used_at, nonce
        FROM auth_codes WHERE code_hash = $1
        "#,
    )
    .bind(hash_token(code))
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup auth code")?
    .ok_or_else(|| oauth_token_error("invalid_grant", "invalid authorization code"))?;

    if code_row.used_at.is_some() {
        return Err(oauth_token_error("invalid_grant", "authorization code already used"));
    }
    if code_row.expires_at < chrono::Utc::now() {
        return Err(oauth_token_error("invalid_grant", "authorization code expired"));
    }
    if code_row.client_id != client.client_id {
        return Err(oauth_token_error("invalid_grant", "authorization code was issued to a different client"));
    }
    if let Some(redirect_uri) = form.get("redirect_uri") {
        if redirect_uri != &code_row.redirect_uri {
            return Err(oauth_token_error("invalid_grant", "redirect_uri mismatch"));
        }
    }

    // PKCE verification (S256).
    let verifier = form.get("code_verifier").ok_or_else(|| oauth_token_error("invalid_grant", "code_verifier required"))?;
    let computed = token::sha256_b64url(verifier);
    if !tokens_equal(&computed, &code_row.pkce_challenge) {
        audit::record(
            &state.pool,
            meta,
            AuditEvent {
                event_type: "oauth.pkce_failed",
                actor_type: ActorType::User,
                actor_id: Some(code_row.user_id),
                org_id: Some(code_row.org_id),
                target_type: Some("client"),
                target_id: None,
                metadata: serde_json::json!({ "clientId": client.client_id }),
            },
        )
        .await;
        return Err(oauth_token_error("invalid_grant", "PKCE verification failed"));
    }

    // Single use.
    let consumed = sqlx::query("UPDATE auth_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL")
        .bind(code_row.id)
        .execute(&state.pool)
        .await
        .map_internal("consume auth code")?;
    if consumed.rows_affected() == 0 {
        return Err(oauth_token_error("invalid_grant", "authorization code already used"));
    }

    // Remember the grant for future silent approvals.
    let scopes: Vec<String> = code_row
        .scopes
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(ToOwned::to_owned)).collect())
        .unwrap_or_default();
    upsert_grant(&state, &client.client_id, code_row.user_id, code_row.org_id, &scopes).await?;

    let user = sqlx::query_as::<_, authn::UserRow>(
        "SELECT id, email, display_name, email_verified_at FROM users WHERE id = $1",
    )
    .bind(code_row.user_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("load user for token")?;

    let with_refresh = scopes.contains(&"offline_access".to_string());
    let treq = token::TokenRequest {
        actor_type: "user",
        actor_id: code_row.user_id,
        org_id: Some(code_row.org_id),
        client_id: client.client_id.clone(),
        scopes: scopes.clone(),
        user: Some(token::UserClaims {
            sub: code_row.user_id,
            name: user.display_name.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified_at.is_some(),
        }),
        auth_time: Some(chrono::Utc::now().timestamp()),
        nonce: code_row.nonce.clone(),
    };
    let minted = token::mint_tokens(state, &treq, with_refresh).await?;

    audit::record(
        &state.pool,
        meta,
        AuditEvent {
            event_type: "oauth.token_issued",
            actor_type: ActorType::User,
            actor_id: Some(code_row.user_id),
            org_id: Some(code_row.org_id),
            target_type: Some("client"),
            target_id: None,
            metadata: serde_json::json!({ "clientId": client.client_id, "grant": "authorization_code" }),
        },
    )
    .await;

    Ok(token_response(minted))
}

async fn token_refresh(
    state: &AppState,
    meta: &HttpMeta,
    headers: &axum::http::HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Response> {
    let client = authenticate_client(state, headers, form).await?;
    let refresh = form
        .get("refresh_token")
        .ok_or_else(|| oauth_token_error("invalid_request", "missing refresh_token"))?;

    let Some(row) = token::find_refresh_token(state, refresh).await? else {
        return Err(oauth_token_error("invalid_grant", "invalid refresh token"));
    };
    if row.client_id != client.client_id {
        return Err(oauth_token_error("invalid_grant", "refresh token was issued to a different client"));
    }
    if row.expires_at < chrono::Utc::now() {
        return Err(oauth_token_error("invalid_grant", "refresh token expired"));
    }

    // Rotation + reuse detection.
    let (new_refresh, actor_org) = if row.revoked_at.is_some() {
        // Reuse of a rotated token: revoke the whole family.
        token::revoke_family(state, row.family_id).await?;
        audit::record(
            &state.pool,
            meta,
            AuditEvent {
                event_type: "oauth.refresh_token_reuse",
                actor_type: ActorType::User,
                actor_id: Some(row.actor_id),
                org_id: row.org_id,
                target_type: None,
                target_id: None,
                metadata: serde_json::json!({ "clientId": client.client_id }),
            },
        )
        .await;
        return Err(oauth_token_error("invalid_grant", "refresh token reuse detected; family revoked"));
    } else {
        let new = token::rotate_refresh_token(state, &row).await?;
        (Some(new), row.org_id)
    };

    let scopes: Vec<String> = row
        .scopes
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(ToOwned::to_owned)).collect())
        .unwrap_or_default();

    let actor_type: &'static str = match row.actor_type.as_str() {
        "user" => "user",
        "service_account" => "service_account",
        _ => "device",
    };
    let mut treq = token::TokenRequest {
        actor_type,
        actor_id: row.actor_id,
        org_id: actor_org,
        client_id: client.client_id.clone(),
        scopes: scopes.clone(),
        user: None,
        auth_time: None,
        nonce: None,
    };

    if row.actor_type == "user" {
        if let Ok(user) = sqlx::query_as::<_, authn::UserRow>(
            "SELECT id, email, display_name, email_verified_at FROM users WHERE id = $1",
        )
        .bind(row.actor_id)
        .fetch_one(&state.pool)
        .await
        {
            treq.user = Some(token::UserClaims {
                sub: row.actor_id,
                name: user.display_name.clone(),
                email: user.email.clone(),
                email_verified: user.email_verified_at.is_some(),
            });
        }
    }

    let minted = token::mint_tokens(state, &treq, false).await?;

    audit::record(
        &state.pool,
        meta,
        AuditEvent {
            event_type: "oauth.token_refreshed",
            actor_type: ActorType::User,
            actor_id: Some(row.actor_id),
            org_id: row.org_id,
            target_type: Some("client"),
            target_id: None,
            metadata: serde_json::json!({ "clientId": client.client_id }),
        },
    )
    .await;

    Ok(token_response(token::MintedTokens {
        refresh_token: new_refresh,
        ..minted
    }))
}

async fn token_client_credentials(
    state: &AppState,
    meta: &HttpMeta,
    headers: &axum::http::HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Response> {
    // Authenticate as a machine (service account or device).
    let (client_id, secret) = extract_client_credentials(headers, form)?;
    let actor = machine::authenticate_machine(state, &client_id, &secret).await?;

    let org_id = actor.org_id();
    let treq = token::TokenRequest {
        actor_type: actor.actor_type().as_str(),
        actor_id: actor.id(),
        org_id: Some(org_id),
        client_id: client_id.clone(),
        scopes: vec!["openid".to_string()],
        user: None,
        auth_time: None,
        nonce: None,
    };
    let minted = token::mint_tokens(state, &treq, false).await?;

    audit::record(
        &state.pool,
        meta,
        AuditEvent {
            event_type: match actor.actor_type() {
                ActorType::ServiceAccount => "sa.token_issued",
                _ => "device.token_issued",
            },
            actor_type: actor.actor_type(),
            actor_id: Some(actor.id()),
            org_id: Some(org_id),
            target_type: None,
            target_id: None,
            metadata: serde_json::json!({ "clientId": client_id }),
        },
    )
    .await;

    Ok(token_response(minted))
}

// ----------------------------------------------------------------- userinfo

async fn userinfo(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> ApiResult<Response> {
    let token_str = bearer_token(&headers).ok_or(ApiError::Unauthorized)?;
    let tok = token::validate_access_token(&state, &token_str, None).await?;
    if tok.actor_type != "user" {
        return Err(ApiError::Forbidden);
    }

    let user = sqlx::query_as::<_, authn::UserRow>(
        "SELECT id, email, display_name, email_verified_at FROM users WHERE id = $1",
    )
    .bind(tok.actor_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("load user for userinfo")?;

    let wants = |s: &str| tok.scopes.iter().any(|x| x == s);
    let mut claims = serde_json::json!({ "sub": user.id });
    if wants("profile") {
        claims["name"] = serde_json::Value::String(user.display_name);
    }
    if wants("email") {
        claims["email"] = serde_json::Value::String(user.email);
        claims["email_verified"] = serde_json::Value::Bool(user.email_verified_at.is_some());
    }
    if let Some(org) = tok.org_id {
        claims["org"] = serde_json::Value::String(org.to_string());
    }
    Ok(Json(claims).into_response())
}

// ------------------------------------------------------------------ revoke

async fn revoke(
    State(state): State<AppState>,
    meta: HttpMeta,
    headers: axum::http::HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> ApiResult<Response> {
    let Some(token_str) = form.get("token") else {
        return Err(oauth_token_error("invalid_request", "missing token"));
    };

    // RFC 7009: the client presenting the token must be its owner.
    let client = match authenticate_client(&state, &headers, &form).await {
        Ok(c) => c,
        Err(_) => {
            return Ok(StatusCode::OK.into_response());
        }
    };

    // Refresh token?
    if let Some(row) = token::find_refresh_token(&state, token_str).await? {
        if row.client_id == client.client_id && row.revoked_at.is_none() {
            sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1")
                .bind(row.id)
                .execute(&state.pool)
                .await
                .map_internal("revoke refresh token")?;
            audit::record(
                &state.pool,
                &meta,
                AuditEvent {
                    event_type: "oauth.token_revoked",
                    actor_type: ActorType::User,
                    actor_id: Some(row.actor_id),
                    org_id: row.org_id,
                    target_type: Some("client"),
                    target_id: None,
                    metadata: serde_json::json!({ "clientId": client.client_id, "kind": "refresh_token" }),
                },
            )
            .await;
        }
        return Ok(StatusCode::OK.into_response());
    }

    // Access token: accept either a bare jti (uuid) or a full JWT (jti claim
    // extracted from the payload without signature verification — we are
    // revoking, not trusting, the presented token).
    let jti: Option<uuid::Uuid> = Uuid::parse_str(token_str)
        .ok()
        .or_else(|| jwt_jti(token_str));
    if let Some(jti) = jti {
        let res = sqlx::query("UPDATE access_token_records SET revoked_at = now() WHERE jti = $1 AND revoked_at IS NULL")
            .bind(jti)
            .execute(&state.pool)
            .await
            .map_internal("revoke access token")?;
        if res.rows_affected() > 0 {
            audit::record(
                &state.pool,
                &meta,
                AuditEvent {
                    event_type: "oauth.token_revoked",
                    actor_type: ActorType::System,
                    actor_id: None,
                    org_id: None,
                    target_type: Some("client"),
                    target_id: None,
                    metadata: serde_json::json!({ "clientId": client.client_id, "kind": "access_token" }),
                },
            )
            .await;
        }
    }

    // Always 200 per RFC 7009.
    Ok(StatusCode::OK.into_response())
}

// ------------------------------------------------------- application management

/// List OIDC applications of an organization (requires `org.apps.read`).
#[utoipa::path(
    get,
    path = "/api/orgs/{org_id}/applications",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    responses(
        (status = 200, description = "List of applications", body = inline(crate::openapi::ApplicationsResponse)),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn list_applications(
    State(state): State<AppState>,
    authed: Authed,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::APPS_READ).await?;
    let clients = sqlx::query_as::<_, OidcClientRow>(
        r#"
        SELECT * FROM oidc_clients WHERE org_id = $1 ORDER BY created_at
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list applications")?;
    let apps: Vec<ApplicationJson> = clients.into_iter().map(ApplicationJson::from).collect();
    Ok(Json(serde_json::json!({ "applications": apps })).into_response())
}

/// Register an OIDC client (requires `org.apps.manage`). Redirect URIs must
/// be https (http allowed only for loopback). The client secret is returned
/// once, at creation.
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/applications",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    request_body = CreateApplicationReq,
    responses(
        (status = 201, description = "Application created; clientSecret returned once"),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn create_application(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(org_id): Path<Uuid>,
    Json(req): Json<CreateApplicationReq>,
) -> ApiResult<Response> {
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("app-create", &ip_key, RL_APP_CREATE.0, RL_APP_CREATE.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::APPS_MANAGE).await?;

    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::Validation("application name must be between 1 and 100 characters".into()));
    }
    let redirect_uris = validate_redirect_uris(&req.redirect_uris)?;

    let client_id = format!("awapp_{}", new_id().simple());
    let (secret_hash, secret_preview_val, secret) = if req.is_confidential {
        let s = random_secret("awcs");
        (Some(hash_token(s.expose_secret())), secret_preview(s.expose_secret()), Some(s))
    } else {
        (None, String::new(), None)
    };

    let id = new_id();
    sqlx::query(
        r#"
        INSERT INTO oidc_clients (id, org_id, name, client_id, client_secret_hash,
                                  secret_preview, redirect_uris, is_confidential, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(id)
    .bind(org_id)
    .bind(name)
    .bind(&client_id)
    .bind(&secret_hash)
    .bind(&secret_preview_val)
    .bind(serde_json::to_value(&redirect_uris).unwrap_or_else(|_| serde_json::json!([])))
    .bind(req.is_confidential)
    .bind(authed.0.user.id)
    .execute(&state.pool)
    .await
    .map_internal("create application")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "app.created",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("client"),
            target_id: Some(id),
            metadata: serde_json::json!({ "name": name, "clientId": client_id }),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "application": {
                "id": id, "name": name, "clientId": client_id,
                "isConfidential": req.is_confidential,
                "redirectUris": redirect_uris,
            },
            "clientSecret": secret.as_ref().map(|s| s.expose_secret().clone()),
        })),
    )
        .into_response())
}

/// Update an application: name, redirect URIs, enabled state
/// (requires `org.apps.manage`).
#[utoipa::path(
    patch,
    path = "/api/orgs/{org_id}/applications/{client_id}",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("client_id" = String, Path, description = "OIDC client id")
    ),
    request_body = UpdateApplicationReq,
    responses(
        (status = 200, description = "Application updated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Application not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn update_application(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, client_id)): Path<(Uuid, String)>,
    Json(req): Json<UpdateApplicationReq>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::APPS_MANAGE).await?;

    let mut changes: Vec<String> = Vec::new();
    let mut bind_idx = 1usize;
    let mut sql = String::from("UPDATE oidc_clients SET ");
    if let Some(name) = &req.name {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Err(ApiError::Validation("application name must be between 1 and 100 characters".into()));
        }
        sql.push_str(&format!("name = ${bind_idx}, "));
        bind_idx += 1;
        changes.push(name.to_string());
    }
    if let Some(uris) = &req.redirect_uris {
        let uris = validate_redirect_uris(uris)?;
        sql.push_str(&format!("redirect_uris = ${bind_idx}, "));
        bind_idx += 1;
        changes.push(serde_json::to_string(&uris).unwrap_or_else(|_| "[]".into()));
    }
    if let Some(enabled) = req.application_enabled {
        sql.push_str(&format!("application_enabled = ${bind_idx}, "));
        bind_idx += 1;
        changes.push(if enabled { "true".into() } else { "false".into() });
    }
    sql.push_str("updated_at = now() WHERE client_id = $");
    sql.push_str(&bind_idx.to_string());
    sql.push_str(" AND org_id = $");
    sql.push_str(&(bind_idx + 1).to_string());

    let mut q = sqlx::query(&sql);
    for c in &changes {
        q = q.bind(c);
    }
    q = q.bind(&client_id).bind(org_id);
    let res = q.execute(&state.pool).await.map_internal("update application")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "app.updated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("client"),
            target_id: None,
            metadata: serde_json::json!({ "clientId": client_id }),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

/// Rotate a confidential client's secret (requires `org.apps.manage` +
/// reauthentication). The previous secret is revoked; the new one is
/// returned once.
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/applications/{client_id}/rotate-secret",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("client_id" = String, Path, description = "OIDC client id")
    ),
    responses(
        (status = 200, description = "New client secret (returned once)"),
        (status = 403, description = "Insufficient permissions or reauthentication required"),
        (status = 404, description = "Application not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn rotate_client_secret(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, client_id)): Path<(Uuid, String)>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::APPS_MANAGE).await?;

    let client = sqlx::query_as::<_, OidcClientRow>(
        "SELECT * FROM oidc_clients WHERE client_id = $1 AND org_id = $2",
    )
    .bind(&client_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load application")?
    .ok_or(ApiError::NotFound)?;

    if !client.is_confidential {
        return Err(ApiError::Validation("public clients have no secret".into()));
    }

    let secret = random_secret("awcs");
    let preview = secret_preview(secret.expose_secret());

    let mut tx = state.pool.begin().await.map_internal("begin secret rotation")?;
    if let Some(old_hash) = &client.client_secret_hash {
        sqlx::query(
            "INSERT INTO oidc_client_secrets (id, client_id, secret_hash, preview, revoked_at) VALUES ($1, $2, $3, $4, now())",
        )
        .bind(new_id())
        .bind(&client_id)
        .bind(old_hash)
        .bind(&client.secret_preview)
        .execute(&mut *tx)
        .await
        .map_internal("archive old secret")?;
    }
    sqlx::query(
        "UPDATE oidc_clients SET client_secret_hash = $1, secret_preview = $2, updated_at = now() WHERE client_id = $3",
    )
    .bind(hash_token(secret.expose_secret()))
    .bind(&preview)
    .bind(&client_id)
    .execute(&mut *tx)
    .await
    .map_internal("update client secret")?;
    tx.commit().await.map_internal("commit secret rotation")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "app.secret_rotated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("client"),
            target_id: None,
            metadata: serde_json::json!({ "clientId": client_id }),
        },
    )
    .await;

    Ok(Json(serde_json::json!({
        "clientId": client_id,
        "clientSecret": secret.expose_secret(),
    }))
    .into_response())
}

/// Delete an application and all of its grants (requires `org.apps.manage`
/// + reauthentication).
#[utoipa::path(
    delete,
    path = "/api/orgs/{org_id}/applications/{client_id}",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("client_id" = String, Path, description = "OIDC client id")
    ),
    responses(
        (status = 204, description = "Application deleted"),
        (status = 403, description = "Insufficient permissions or reauthentication required"),
        (status = 404, description = "Application not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn delete_application(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, client_id)): Path<(Uuid, String)>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::APPS_MANAGE).await?;
    let res = sqlx::query("DELETE FROM oidc_clients WHERE client_id = $1 AND org_id = $2")
        .bind(&client_id)
        .bind(org_id)
        .execute(&state.pool)
        .await
        .map_internal("delete application")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "app.deleted",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("client"),
            target_id: None,
            metadata: serde_json::json!({ "clientId": client_id }),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ------------------------------------------------------- account applications

async fn account_applications(State(state): State<AppState>, authed: Authed) -> ApiResult<Response> {
    let grants = sqlx::query_as::<_, GrantRow>(
        r#"
        SELECT g.id, g.client_id, c.name, g.scopes, g.created_at, g.org_id
        FROM oauth_grants g
        JOIN oidc_clients c ON c.client_id = g.client_id
        WHERE g.user_id = $1 AND g.revoked_at IS NULL
        ORDER BY g.created_at DESC
        "#,
    )
    .bind(authed.0.user.id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list account applications")?;

    let org_names: Vec<(Uuid, String)> = sqlx::query_as("SELECT id, name FROM organizations")
        .fetch_all(&state.pool)
        .await
        .map_internal("load organizations")?;

    let items: Vec<serde_json::Value> = grants
        .into_iter()
        .map(|g| {
            serde_json::json!({
                "id": g.id,
                "clientId": g.client_id,
                "name": g.name,
                "scopes": g.scopes,
                "orgName": org_names.iter().find(|(id, _)| *id == g.org_id).map(|(_, n)| n),
                "grantedAt": g.created_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "applications": items })).into_response())
}

#[derive(sqlx::FromRow)]
struct GrantRow {
    id: Uuid,
    client_id: String,
    name: String,
    scopes: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    org_id: Uuid,
}

async fn revoke_account_grant(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(grant_id): Path<Uuid>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    let grant = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT client_id, org_id FROM oauth_grants WHERE id = $1 AND user_id = $2",
    )
    .bind(grant_id)
    .bind(authed.0.user.id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load grant")?
    .ok_or(ApiError::NotFound)?;

    let (client_id, org_id) = grant;
    let mut tx = state.pool.begin().await.map_internal("begin grant revoke")?;
    sqlx::query("UPDATE oauth_grants SET revoked_at = now() WHERE id = $1")
        .bind(grant_id)
        .execute(&mut *tx)
        .await
        .map_internal("revoke grant")?;
    // Revoke all refresh tokens minted under this grant.
    sqlx::query(
        r#"
        UPDATE refresh_tokens SET revoked_at = now()
        WHERE client_id = $1 AND actor_type = 'user' AND actor_id = $2 AND org_id = $3 AND revoked_at IS NULL
        "#,
    )
    .bind(&client_id)
    .bind(authed.0.user.id)
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .map_internal("revoke grant refresh tokens")?;
    tx.commit().await.map_internal("commit grant revoke")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "app.grant_revoked",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("client"),
            target_id: None,
            metadata: serde_json::json!({ "clientId": client_id }),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ------------------------------------------------------------------ helpers

#[derive(Debug)]
struct AuthedClient {
    client_id: String,
    is_confidential: bool,
    has_secret: bool,
    name: String,
}

async fn load_client(state: &AppState, client_id: &str) -> ApiResult<Option<OidcClientRow>> {
    let client = sqlx::query_as::<_, OidcClientRow>("SELECT * FROM oidc_clients WHERE client_id = $1")
        .bind(client_id)
        .fetch_optional(&state.pool)
        .await
        .map_internal("load oidc client")?;
    Ok(client)
}

fn redirect_registered(client: &OidcClientRow, redirect_uri: &str) -> bool {
    client
        .redirect_uris
        .as_array()
        .map(|a| a.iter().any(|v| v.as_str() == Some(redirect_uri)))
        .unwrap_or(false)
}

fn parse_auth_request(params: &HashMap<String, String>) -> Option<AuthRequest> {
    Some(AuthRequest {
        client_id: params.get("client_id")?.clone(),
        redirect_uri: params.get("redirect_uri")?.clone(),
        response_type: params.get("response_type").cloned().unwrap_or_default(),
        scope: params.get("scope").cloned().unwrap_or_default(),
        state: params.get("state").cloned().filter(|s| !s.is_empty()),
        code_challenge: params.get("code_challenge").cloned().unwrap_or_default(),
        code_challenge_method: params
            .get("code_challenge_method")
            .cloned()
            .unwrap_or_else(|| "S256".into()),
        nonce: params.get("nonce").cloned().filter(|s| !s.is_empty()),
        prompt: params.get("prompt").cloned().filter(|s| !s.is_empty()),
    })
}

fn parse_scopes(scope: &str) -> ApiResult<Vec<String>> {
    let scopes: Vec<String> = scope
        .split_whitespace()
        .map(ToOwned::to_owned)
        .filter(|s| SUPPORTED_SCOPES.contains(&s.as_str()))
        .collect();
    if scopes.is_empty() {
        return Err(ApiError::Validation("no supported scopes requested".into()));
    }
    Ok(scopes)
}

/// RFC 6749 §4.1.2.1 error response via redirect.
fn oauth_redirect_error(
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    description: &str,
) -> Response {
    let mut url = format!("{redirect_uri}?error={error}");
    if let Some(state) = state {
        url.push_str(&format!("&state={}", urlencode(state)));
    }
    if !description.is_empty() {
        url.push_str(&format!("&error_description={}", urlencode(description)));
    }
    Redirect::to(&url).into_response()
}

fn oauth_token_error(error: &str, description: &str) -> ApiError {
    ApiError::Validation(format!("{error}: {description}"))
}

fn token_response(minted: token::MintedTokens) -> Response {
    let mut body = serde_json::json!({
        "access_token": minted.access_token,
        "token_type": "Bearer",
        "expires_in": minted.expires_in,
    });
    if let Some(id_token) = minted.id_token {
        body["id_token"] = serde_json::Value::String(id_token);
    }
    if let Some(refresh_token) = minted.refresh_token {
        body["refresh_token"] = serde_json::Value::String(refresh_token);
    }
    Json(body).into_response()
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(ToOwned::to_owned)
}

fn extract_client_credentials(
    headers: &axum::http::HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<(String, String)> {
    // Basic auth takes precedence, then form fields.
    if let Some(basic) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(encoded) = basic.strip_prefix("Basic ") {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                if let Ok(credentials) = String::from_utf8(decoded) {
                    if let Some((id, secret)) = credentials.split_once(':') {
                        return Ok((id.to_string(), secret.to_string()));
                    }
                }
            }
        }
    }
    let id = form
        .get("client_id")
        .ok_or_else(|| ApiError::Validation("client authentication required".into()))?;
    let secret = form.get("client_secret").cloned().unwrap_or_default();
    Ok((id.clone(), secret))
}

async fn authenticate_client(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<AuthedClient> {
    let (client_id, presented_secret) = extract_client_credentials(headers, form)?;
    let Some(client) = load_client(state, &client_id).await? else {
        return Err(ApiError::Validation("invalid client credentials".into()));
    };

    if client.is_confidential {
        let Some(stored) = &client.client_secret_hash else {
            return Err(ApiError::Validation("invalid client credentials".into()));
        };
        if !tokens_equal(&hash_token(&presented_secret), stored) {
            return Err(ApiError::Validation("invalid client credentials".into()));
        }
        Ok(AuthedClient {
            client_id,
            is_confidential: true,
            has_secret: !presented_secret.is_empty(),
            name: client.name,
        })
    } else {
        Ok(AuthedClient {
            client_id,
            is_confidential: false,
            has_secret: !presented_secret.is_empty(),
            name: client.name,
        })
    }
}

fn validate_redirect_uris(uris: &[String]) -> ApiResult<Vec<String>> {
    if uris.is_empty() {
        return Err(ApiError::Validation("at least one redirect URI is required".into()));
    }
    for uri in uris {
        if !util::is_valid_redirect_uri(uri) {
            return Err(ApiError::Validation(format!("invalid redirect URI: {uri}")));
        }
    }
    Ok(uris.to_vec())
}

fn build_authorize_url(state: &AppState, req: &AuthRequest) -> String {
    let mut url = format!(
        "{}/oidc/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}",
        state.config.public_base_url,
        urlencode(&req.client_id),
        urlencode(&req.redirect_uri),
        urlencode(&req.scope),
    );
    if let Some(state_val) = &req.state {
        url.push_str(&format!("&state={}", urlencode(state_val)));
    }
    url.push_str(&format!(
        "&code_challenge={}&code_challenge_method={}",
        urlencode(&req.code_challenge),
        urlencode(&req.code_challenge_method)
    ));
    if let Some(nonce) = &req.nonce {
        url.push_str(&format!("&nonce={}", urlencode(nonce)));
    }
    url
}

fn client_error_page(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

/// Upsert an oauth grant, merging requested scopes into the stored set.
async fn upsert_grant(
    state: &AppState,
    client_id: &str,
    user_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
) -> ApiResult<()> {
    let existing: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT scopes FROM oauth_grants WHERE client_id = $1 AND user_id = $2 AND org_id = $3",
    )
    .bind(client_id)
    .bind(user_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load existing grant")?;

    let mut merged: Vec<String> = scopes.to_vec();
    if let Some(existing) = existing {
        if let Some(list) = existing.as_array() {
            for v in list {
                if let Some(s) = v.as_str() {
                    if !merged.contains(&s.to_string()) {
                        merged.push(s.to_string());
                    }
                }
            }
        }
    }

    if merged == scopes {
        sqlx::query(
            r#"
            INSERT INTO oauth_grants (id, client_id, user_id, org_id, scopes)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (client_id, user_id, org_id) DO NOTHING
            "#,
        )
        .bind(new_id())
        .bind(client_id)
        .bind(user_id)
        .bind(org_id)
        .bind(serde_json::to_value(&merged).unwrap_or_else(|_| serde_json::json!([])))
        .execute(&state.pool)
        .await
        .map_internal("insert oauth grant")?;
    } else {
        sqlx::query(
            r#"
            UPDATE oauth_grants SET scopes = $1
            WHERE client_id = $2 AND user_id = $3 AND org_id = $4
            "#,
        )
        .bind(serde_json::to_value(&merged).unwrap_or_else(|_| serde_json::json!([])))
        .bind(client_id)
        .bind(user_id)
        .bind(org_id)
        .execute(&state.pool)
        .await
        .map_internal("update oauth grant")?;
    }
    Ok(())
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

/// Extract the `jti` claim from an unverified JWT payload.
fn jwt_jti(token: &str) -> Option<Uuid> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1)?;
    let normalized = payload.replace('-', "+").replace('_', "/");
    let padded = format!("{normalized}{}", "=".repeat((4 - normalized.len() % 4) % 4));
    let bytes = base64::engine::general_purpose::STANDARD.decode(padded).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get("jti")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
}
