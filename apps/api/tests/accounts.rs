//! Accounts: registration, verification, login, password reset, recovery
//! codes, reauthentication and session management.

mod common;

use axum::http::StatusCode;
use sqlx::PgPool;

use common::*;

#[sqlx::test(migrations = "./migrations")]
async fn register_verify_login_flow(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);

    // Login before verification is refused.
    let resp = request(
        &router,
        "POST",
        "/api/auth/register",
        Some(serde_json::json!({ "email": "alice@example.com", "password": "correct-horse-123" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = request(
        &router,
        "POST",
        "/api/auth/login",
        Some(serde_json::json!({ "email": "alice@example.com", "password": "correct-horse-123" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["error"]["code"], "email_not_verified");

    // Duplicate registration is refused without revealing anything.
    let resp = request(
        &router,
        "POST",
        "/api/auth/register",
        Some(serde_json::json!({ "email": "alice@example.com", "password": "correct-horse-123" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // A second account goes through the full verify flow.
    let session = register_verify_login(&router, &pool, "alice2@example.com", "correct-horse-123").await;

    let resp = request_as(&router, "GET", "/api/auth/me", &session, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["user"]["email"], "alice2@example.com");
    assert_eq!(body["user"]["emailVerified"], true);
    assert_eq!(body["memberships"].as_array().unwrap().len(), 0);

    // Wrong password gets a generic message.
    let resp = request(
        &router,
        "POST",
        "/api/auth/login",
        Some(serde_json::json!({ "email": "alice@example.com", "password": "wrong-password" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_json(resp).await;
    assert_eq!(body["error"]["code"], "validation_failed");
}

#[sqlx::test(migrations = "./migrations")]
async fn password_reset_is_enumeration_safe_and_revokes_sessions(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);
    create_user(&pool, "bob@example.com", "old-password-1").await;

    // Same response whether or not the account exists.
    let existing = request(
        &router,
        "POST",
        "/api/auth/forgot-password",
        Some(serde_json::json!({ "email": "bob@example.com" })),
    )
    .await;
    let missing = request(
        &router,
        "POST",
        "/api/auth/forgot-password",
        Some(serde_json::json!({ "email": "nobody@example.com" })),
    )
    .await;
    assert_eq!(existing.status(), StatusCode::OK);
    assert_eq!(missing.status(), StatusCode::OK);

    // Create a session with the old password, then reset it.
    let session = login_existing(&router, "bob@example.com", "old-password-1").await;

    let token = identity_api::tokens::random_token();
    let bob_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email = 'bob@example.com'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let org = create_org(&pool, "Bob Org", "bob-org", bob_id).await;
    sqlx::query(
        r#"
        INSERT INTO oidc_clients (id, org_id, name, client_id, redirect_uris)
        VALUES ($1, $2, 'Test', 'awapp_reset_test', '[]'::jsonb)
        "#,
    )
    .bind(uuid::Uuid::now_v7())
    .bind(org)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens
            (id, token_hash, family_id, client_id, actor_type, actor_id, org_id, scopes, expires_at)
        VALUES ($1, $2, $3, 'awapp_reset_test', 'user', $4, $5, '[]'::jsonb, now() + interval '1 day')
        "#,
    )
    .bind(uuid::Uuid::now_v7())
    .bind(identity_api::tokens::hash_token("reset-refresh-token"))
    .bind(uuid::Uuid::now_v7())
    .bind(bob_id)
    .bind(org)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO access_token_records (jti, actor_type, actor_id, org_id, client_id, expires_at)
        VALUES ($1, 'user', $2, $3, 'awapp_reset_test', now() + interval '15 minutes')
        "#,
    )
    .bind(uuid::Uuid::now_v7())
    .bind(bob_id)
    .bind(org)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO password_resets (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, now() + interval '30 minutes')",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(bob_id)
    .bind(identity_api::tokens::hash_token(&token))
    .execute(&pool)
    .await
    .unwrap();

    let resp = request(
        &router,
        "POST",
        "/api/auth/reset-password",
        Some(serde_json::json!({ "token": token, "password": "brand-new-password-9" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let live_oauth_tokens: i64 = sqlx::query_scalar(
        r#"
        SELECT
            (SELECT count(*) FROM refresh_tokens WHERE actor_id = $1 AND revoked_at IS NULL)
          + (SELECT count(*) FROM access_token_records WHERE actor_id = $1 AND revoked_at IS NULL)
        "#,
    )
    .bind(bob_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(live_oauth_tokens, 0, "password reset revokes OAuth tokens");

    // All previous sessions are dead.
    let resp = request_as(&router, "GET", "/api/auth/me", &session, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Old password fails, new password works.
    login_existing(&router, "bob@example.com", "brand-new-password-9").await;
    let resp = request(
        &router,
        "POST",
        "/api/auth/login",
        Some(serde_json::json!({ "email": "bob@example.com", "password": "old-password-1" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // The reset token is single-use.
    let resp = request(
        &router,
        "POST",
        "/api/auth/reset-password",
        Some(serde_json::json!({ "token": token, "password": "yet-another-password-1" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn recovery_codes_require_reauth_and_unlock_login(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);
    create_user(&pool, "carol@example.com", "password-123").await;
    let session = login_existing(&router, "carol@example.com", "password-123").await;

    // Sensitive action without reauthentication.
    let resp = request_as(&router, "GET", "/api/account/recovery-codes", &session, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["error"]["code"], "reauth_required");

    // Reauthenticate, then generate codes.
    let resp = request_as(
        &router,
        "POST",
        "/api/auth/reauth",
        &session,
        Some(serde_json::json!({ "password": "password-123" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = request_as(&router, "GET", "/api/account/recovery-codes", &session, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let codes: Vec<String> = body["codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(codes.len(), 8);

    // Codes only exist hashed.
    let plaintext_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM recovery_codes WHERE code_hash IN (SELECT unnest($1::text[]))")
            .bind(&codes)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(plaintext_count, 0);

    // Log out and log back in with a recovery code.
    let resp = request_as(&router, "POST", "/api/auth/logout", &session, None).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = request(
        &router,
        "POST",
        "/api/auth/recovery",
        Some(serde_json::json!({ "email": "carol@example.com", "code": codes[0] })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let session2 = session_cookie(&resp);

    let resp = request_as(&router, "GET", "/api/auth/me", &session2, None).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // A code is single-use.
    let resp = request(
        &router,
        "POST",
        "/api/auth/recovery",
        Some(serde_json::json!({ "email": "carol@example.com", "code": codes[0] })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn session_listing_and_revocation(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);
    create_user(&pool, "dave@example.com", "password-123").await;

    let session_a = login_existing(&router, "dave@example.com", "password-123").await;
    let session_b = login_existing(&router, "dave@example.com", "password-123").await;

    let resp = request_as(&router, "GET", "/api/account/sessions", &session_a, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);

    // Revoking session B requires reauthentication.
    let resp = request_as(&router, "POST", "/api/account/sessions/revoke-others", &session_a, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Reauth, then revoke the other session by id.
    request_as(
        &router,
        "POST",
        "/api/auth/reauth",
        &session_a,
        Some(serde_json::json!({ "password": "password-123" })),
    )
    .await;

    let target_id = sessions
        .iter()
        .find(|s| s["isCurrent"] == false)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/account/sessions/{target_id}/revoke"),
        &session_a,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = request_as(&router, "GET", "/api/auth/me", &session_b, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Session A is untouched.
    let resp = request_as(&router, "GET", "/api/auth/me", &session_a, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn reauthentication_is_rate_limited_per_account(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);
    create_user(&pool, "erin@example.com", "password-123").await;
    let session = login_existing(&router, "erin@example.com", "password-123").await;

    for _ in 0..10 {
        let resp = request_as(
            &router,
            "POST",
            "/api/auth/reauth",
            &session,
            Some(serde_json::json!({ "password": "wrong-password" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    let resp = request_as(
        &router,
        "POST",
        "/api/auth/reauth",
        &session,
        Some(serde_json::json!({ "password": "password-123" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key("retry-after"));
}

#[sqlx::test(migrations = "./migrations")]
async fn totp_mfa_flow(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);
    create_user(&pool, "mfa@example.com", "password-123").await;
    let session = login_existing(&router, "mfa@example.com", "password-123").await;

    // Setup requires reauthentication.
    let resp = request_as(&router, "POST", "/api/account/totp/setup", &session, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    request_as(
        &router,
        "POST",
        "/api/auth/reauth",
        &session,
        Some(serde_json::json!({ "password": "password-123" })),
    )
    .await;

    let resp = request_as(&router, "POST", "/api/account/totp/setup", &session, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let secret_b32 = body["secret"].as_str().unwrap().to_string();
    assert!(body["otpauthUri"].as_str().unwrap().starts_with("otpauth://totp/"));

    // The secret is stored encrypted, never as the returned base32 string.
    let row: (String, String) = sqlx::query_as(
        "SELECT nonce, ciphertext FROM totp_secrets WHERE user_id = (SELECT id FROM users WHERE email = 'mfa@example.com')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!row.0.is_empty() && !row.1.is_empty());
    assert!(!row.1.contains(&secret_b32), "seed must not be stored in the clear");

    // Compute the current code from the returned secret (RFC 6238).
    let secret = identity_api::totp::base32_decode(&secret_b32).unwrap();
    let counter = chrono::Utc::now().timestamp().max(0) as u64 / 30;
    let code = format!("{:06}", identity_api::totp::totp_value(&secret, counter, 6));

    // A wrong code does not enable the factor.
    let resp = request_as(
        &router,
        "POST",
        "/api/account/totp/verify",
        &session,
        Some(serde_json::json!({ "code": "000000" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // The correct code enables it.
    let resp = request_as(
        &router,
        "POST",
        "/api/account/totp/verify",
        &session,
        Some(serde_json::json!({ "code": code })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["enabled"], true);

    // Password login now demands the second factor and sets no session.
    let resp = request(
        &router,
        "POST",
        "/api/auth/login",
        Some(serde_json::json!({ "email": "mfa@example.com", "password": "password-123" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("set-cookie").is_none(), "no session before MFA");
    let body = body_json(resp).await;
    assert_eq!(body["mfaRequired"], true);
    let mfa_token = body["mfaToken"].as_str().unwrap().to_string();

    // A wrong code keeps the challenge alive.
    let resp = request(
        &router,
        "POST",
        "/api/auth/mfa",
        Some(serde_json::json!({ "token": mfa_token, "code": "000000" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // The correct code completes the login.
    let counter = chrono::Utc::now().timestamp().max(0) as u64 / 30;
    let code = format!("{:06}", identity_api::totp::totp_value(&secret, counter, 6));
    let resp = request(
        &router,
        "POST",
        "/api/auth/mfa",
        Some(serde_json::json!({ "token": mfa_token, "code": code })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let session2 = session_cookie(&resp);
    let resp = request_as(&router, "GET", "/api/auth/me", &session2, None).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // The challenge is single-use.
    let resp = request(
        &router,
        "POST",
        "/api/auth/mfa",
        Some(serde_json::json!({ "token": mfa_token, "code": code })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Disabling requires reauthentication; afterwards login is single-factor.
    let resp = request_as(&router, "DELETE", "/api/account/totp", &session2, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    request_as(
        &router,
        "POST",
        "/api/auth/reauth",
        &session2,
        Some(serde_json::json!({ "password": "password-123" })),
    )
    .await;
    let resp = request_as(&router, "DELETE", "/api/account/totp", &session2, None).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = request(
        &router,
        "POST",
        "/api/auth/login",
        Some(serde_json::json!({ "email": "mfa@example.com", "password": "password-123" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("set-cookie").is_some(), "single-factor login restored");

    // Audit trail covers the lifecycle.
    for event in ["totp.setup_initiated", "totp.enabled", "auth.mfa_required", "auth.login_mfa", "totp.disabled"] {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE event_type = $1")
            .bind(event)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(count >= 1, "missing audit event {event}");
    }
}

pub async fn login_existing(router: &axum::Router, email: &str, password: &str) -> String {
    let resp = request(
        router,
        "POST",
        "/api/auth/login",
        Some(serde_json::json!({ "email": email, "password": password })),
    )
    .await;
    if resp.status() != StatusCode::OK {
        let body = body_json(resp).await;
        panic!("login {email} failed: {:?}", body);
    }
    session_cookie(&resp)
}
