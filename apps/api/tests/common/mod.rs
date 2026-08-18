//! Shared test fixture: fresh database per test (sqlx::test), in-memory
//! rate limiting, console email fallback. HTTP flows run through the real
//! router via `Router::oneshot`.

#![allow(dead_code)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, Response, StatusCode};
use axum::Router;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use identity_api::accounts::hash_password;
use identity_api::config::Config;
use identity_api::email::Mailer;
use identity_api::ratelimit::RateLimiter;
use identity_api::state::AppState;
use secrecy::ExposeSecret;

pub fn test_config() -> Config {
    // Defaults in config.rs already point at the local dev database and
    // in-memory rate limiting; pin the stable identity of the test issuer.
    // SAFETY: tests run single-threaded during setup; no other code reads
    // these variables concurrently.
    unsafe {
        std::env::set_var("PUBLIC_BASE_URL", "http://identity.test");
        std::env::set_var("WEB_ORIGIN", "http://localhost:5173");
        std::env::set_var("RP_ID", "localhost");
        std::env::set_var("RP_ORIGINS", "http://localhost:5173");
        std::env::set_var("REDIS_URL", "");
    }
    Config::from_env().expect("test config")
}

pub async fn test_state(pool: PgPool) -> AppState {
    let config = test_config();
    // Surface handler logs in test output (respects RUST_LOG).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("identity_api=error")),
        )
        .with_test_writer()
        .try_init();
    AppState {
        config: Arc::new(config),
        pool,
        rl: Arc::new(RateLimiter::connect(&test_config()).await),
        mailer: Arc::new(Mailer::new(test_config().smtp)),
        totp_key: Arc::new(identity_api::totp::cipher_from_config(&test_config())),
        metrics: Arc::new(identity_api::metrics::Metrics::default()),
    }
}

pub fn router(state: AppState) -> Router {
    identity_api::app(state)
}

/// Send a request through the router without any session.
pub async fn request(router: &Router, method: &str, path: &str, body: Option<Value>) -> Response<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(body) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        let bytes = serde_json::to_vec(&body).unwrap();
        router
            .clone()
            .oneshot(
                builder
                    .body(Body::from(bytes))
                    .expect("request body"),
            )
            .await
            .expect("router response")
    } else {
        router
            .clone()
            .oneshot(builder.body(Body::empty()).expect("request body"))
            .await
            .expect("router response")
    }
}

/// Request with a session cookie.
pub async fn request_as(
    router: &Router,
    method: &str,
    path: &str,
    session: &str,
    body: Option<Value>,
) -> Response<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, format!("aw_session={session}"));
    if let Some(body) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        let bytes = serde_json::to_vec(&body).unwrap();
        router
            .clone()
            .oneshot(builder.body(Body::from(bytes)).expect("request body"))
            .await
            .expect("router response")
    } else {
        router
            .clone()
            .oneshot(builder.body(Body::empty()).expect("request body"))
            .await
            .expect("router response")
    }
}

/// Request with an `application/x-www-form-urlencoded` body.
pub async fn request_form(
    router: &Router,
    method: &str,
    path: &str,
    fields: &[(&str, &str)],
) -> Response<Body> {
    request_form_as(router, method, path, None, fields).await
}

/// Form request with an optional session cookie.
pub async fn request_form_as(
    router: &Router,
    method: &str,
    path: &str,
    session: Option<&str>,
    fields: &[(&str, &str)],
) -> Response<Body> {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(session) = session {
        builder = builder.header(header::COOKIE, format!("aw_session={session}"));
    }
    router
        .clone()
        .oneshot(builder.body(Body::from(body)).expect("request body"))
        .await
        .expect("router response")
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Request with an Authorization: Bearer token.
pub async fn request_bearer(
    router: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> Response<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if let Some(body) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        let bytes = serde_json::to_vec(&body).unwrap();
        router
            .clone()
            .oneshot(builder.body(Body::from(bytes)).expect("request body"))
            .await
            .expect("router response")
    } else {
        router
            .clone()
            .oneshot(builder.body(Body::empty()).expect("request body"))
            .await
            .expect("router response")
    }
}

pub async fn body_json(response: Response<Body>) -> Value {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "body_json: status={status} body={:?} err={e}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

pub fn session_cookie(response: &Response<Body>) -> String {
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("set-cookie header")
        .to_str()
        .unwrap();
    set_cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("aw_session=")
        .unwrap()
        .to_string()
}

/// Create a verified user directly (bypasses registration rate limits).
/// Returns the user id.
pub async fn create_user(pool: &PgPool, email: &str, password: &str) -> Uuid {
    let id = Uuid::now_v7();
    let password_hash = hash_password(password).expect("hash password");
    sqlx::query(
        "INSERT INTO users (id, email, display_name, password_hash, email_verified_at) VALUES ($1, $2, $3, $4, now())",
    )
    .bind(id)
    .bind(email)
    .bind("Test User")
    .bind(&password_hash)
    .execute(pool)
    .await
    .expect("insert user");
    id
}

/// Create an organization with the given owner and built-in roles.
/// Returns the org id.
pub async fn create_org(pool: &PgPool, name: &str, slug: &str, owner_id: Uuid) -> Uuid {
    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, name, slug, owner_id) VALUES ($1, $2, $3, $4)")
        .bind(org_id)
        .bind(name)
        .bind(slug)
        .bind(owner_id)
        .execute(pool)
        .await
        .expect("insert org");
    let mut conn = pool.acquire().await.expect("acquire");
    identity_api::rbac::seed_org_roles(&mut *conn, org_id).await.expect("seed roles");
    let owner_role = identity_api::rbac::find_org_role(&mut *conn, org_id, "Owner")
        .await
        .expect("find owner role")
        .expect("owner role exists");
    sqlx::query("INSERT INTO org_memberships (id, org_id, user_id, role_id) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::now_v7())
        .bind(org_id)
        .bind(owner_id)
        .bind(owner_role)
        .execute(pool)
        .await
        .expect("insert owner membership");
    org_id
}

/// Add a member with the given built-in role name.
pub async fn add_member(pool: &PgPool, org_id: Uuid, user_id: Uuid, role_name: &str) {
    let mut conn = pool.acquire().await.expect("acquire");
    let role = identity_api::rbac::find_org_role(&mut *conn, org_id, role_name)
        .await
        .expect("find role")
        .expect("role exists");
    sqlx::query("INSERT INTO org_memberships (id, org_id, user_id, role_id) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::now_v7())
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .execute(pool)
        .await
        .expect("insert membership");
}

/// Register + login a fresh user over HTTP, verifying by direct DB update
/// (the verification flow itself is covered by `register_verify_login`).
/// Uses unique emails so registration rate limits never trigger.
pub async fn register_login(router: &Router, pool: &PgPool, email: &str, password: &str) -> String {
    let resp = request(
        router,
        "POST",
        "/api/auth/register",
        Some(serde_json::json!({ "email": email, "password": password, "displayName": "T" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED, "register {}", email);

    sqlx::query("UPDATE users SET email_verified_at = now() WHERE email = $1")
        .bind(email)
        .execute(pool)
        .await
        .expect("mark verified");

    let resp = request(
        router,
        "POST",
        "/api/auth/login",
        Some(serde_json::json!({ "email": email, "password": password })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "login {}", email);
    session_cookie(&resp)
}

/// Full registration + verification flow over HTTP (tests verification).
pub async fn register_verify_login(
    router: &Router,
    pool: &PgPool,
    email: &str,
    password: &str,
) -> String {
    let resp = request(
        router,
        "POST",
        "/api/auth/register",
        Some(serde_json::json!({ "email": email, "password": password })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // The verification token cannot be recovered (hashed), so drive the flow
    // by inserting a token we control directly.
    let token = identity_api::tokens::random_token();
    let user_id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(pool)
        .await
        .expect("user id");
    sqlx::query(
        "INSERT INTO email_verifications (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, now() + interval '1 hour')",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(identity_api::tokens::hash_token(&token))
    .execute(pool)
    .await
    .expect("insert verification");

    let resp = request(
        router,
        "POST",
        "/api/auth/verify-email",
        Some(serde_json::json!({ "token": token })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "verify email");

    let resp = request(
        router,
        "POST",
        "/api/auth/login",
        Some(serde_json::json!({ "email": email, "password": password })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    session_cookie(&resp)
}
