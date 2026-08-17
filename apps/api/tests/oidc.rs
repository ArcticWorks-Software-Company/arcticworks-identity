//! OIDC: authorization code + PKCE, exact redirect URI matching, refresh
//! token rotation with reuse detection, RFC 7009 revocation, and the
//! permission-check API.

mod common;

use axum::http::StatusCode;
use sqlx::PgPool;

use common::*;

const REDIRECT: &str = "http://localhost:5174/callback";

struct Flow {
    code: String,
    session: String,
    verifier: String,
    challenge: String,
}

/// Full authorization-code flow: login, (optional) consent, code, tokens.
/// `expect_consent` is false when a stored grant makes consent unnecessary.
async fn full_flow(
    router: &axum::Router,
    _pool: &PgPool,
    org_id: uuid::Uuid,
    user_session: &str,
    client_id: &str,
    client_secret: &str,
    expect_consent: bool,
) -> (serde_json::Value, Flow) {
    let verifier = "test-verifier-".to_string() + &identity_api::tokens::random_token();
    let challenge = identity_api::oidc::token::sha256_b64url(&verifier);

    let resp = request_as(
        router,
        "GET",
        &format!(
            "/oidc/authorize?client_id={client_id}&redirect_uri={REDIRECT}&response_type=code&scope=openid%20profile%20email%20offline_access&state=st123&code_challenge={challenge}&code_challenge_method=S256"
        ),
        user_session,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize redirects: {:?}", resp.headers().get("location"));
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();

    let code = if expect_consent {
        assert!(location.contains("/authorize?"), "consent page: {location}");
        let resp = request_form_as(
            router,
            "POST",
            "/oidc/consent",
            Some(user_session),
            &[
                ("client_id", client_id),
                ("redirect_uri", REDIRECT),
                ("scope", "openid profile email offline_access"),
                ("state", "st123"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("decision", "approve"),
            ],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "consent redirects with code");
        let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
        assert!(location.starts_with(&format!("{REDIRECT}?code=")), "callback: {location}");
        assert!(location.contains("state=st123"), "state round-trips");
        location.split("code=").nth(1).unwrap().split('&').next().unwrap().to_string()
    } else {
        assert!(location.starts_with(&format!("{REDIRECT}?code=")), "silent consent callback: {location}");
        location.split("code=").nth(1).unwrap().split('&').next().unwrap().to_string()
    };

    let tokens = request_form(
        router,
        "POST",
        "/oidc/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code_verifier", &verifier),
        ],
    )
    .await;
    assert_eq!(tokens.status(), StatusCode::OK, "token exchange");
    let tokens = body_json(tokens).await;

    assert!(tokens["access_token"].as_str().is_some());
    assert!(tokens["id_token"].as_str().is_some());
    assert!(tokens["refresh_token"].as_str().is_some());
    assert_eq!(tokens["token_type"], "Bearer");

    (tokens, Flow {
        code,
        session: user_session.to_string(),
        verifier,
        challenge,
    })
}

async fn insert_client(pool: &PgPool, org_id: uuid::Uuid, client_id: &str, secret: &str) {
    sqlx::query(
        r#"
        INSERT INTO oidc_clients (id, org_id, name, client_id, client_secret_hash,
                                  secret_preview, redirect_uris, post_logout_redirect_uris, is_confidential)
        VALUES ($1, $2, 'Test app', $3, $4, '…x', $5, $6, true)
        "#,
    )
    .bind(uuid::Uuid::now_v7())
    .bind(org_id)
    .bind(client_id)
    .bind(identity_api::tokens::hash_token(secret))
    .bind(serde_json::json!([REDIRECT]))
    .bind(serde_json::json!(["http://localhost:5174/logout"]))
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn authorization_code_flow_with_pkce(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);

    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    let session = login_existing(&router, "owner@example.com", "password-123").await;
    insert_client(&pool, org, "awapp_test", "test-secret-1").await;

    let (tokens, flow) = full_flow(&router, &pool, org, &session, "awapp_test", "test-secret-1", true).await;

    // userinfo with the access token.
    let access = tokens["access_token"].as_str().unwrap();
    let resp = request_bearer(&router, "GET", "/oidc/userinfo", access, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["sub"], owner.to_string());
    assert_eq!(body["email"], "owner@example.com");
    assert_eq!(body["email_verified"], true);
    assert_eq!(body["org"], org.to_string());

    // Wrong PKCE verifier is rejected.
    let resp = request_form(
        &router,
        "POST",
        "/oidc/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &flow.code),
            ("redirect_uri", REDIRECT),
            ("client_id", "awapp_test"),
            ("client_secret", "test-secret-1"),
            ("code_verifier", "wrong-verifier-value"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // The code is single-use — but it was already consumed; reuse fails.
    let resp = request_form(
        &router,
        "POST",
        "/oidc/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &flow.code),
            ("redirect_uri", REDIRECT),
            ("client_id", "awapp_test"),
            ("client_secret", "test-secret-1"),
            ("code_verifier", &flow.verifier),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY, "code reuse rejected");

    // Bad client secret is rejected. Consent is skipped: the grant already exists.
    let (_, flow2) = full_flow(&router, &pool, org, &session, "awapp_test", "test-secret-1", false).await;
    let resp = request_form(
        &router,
        "POST",
        "/oidc/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &flow2.code),
            ("client_id", "awapp_test"),
            ("client_secret", "wrong-secret"),
            ("code_verifier", &flow2.verifier),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY, "bad client secret rejected");

    // Second consent is skipped (grant exists) — authorize redirects straight
    // to the callback.
    let resp = request_as(
        &router,
        "GET",
        &format!(
            "/oidc/authorize?client_id=awapp_test&redirect_uri={REDIRECT}&response_type=code&scope=openid%20profile&state=s2&code_challenge={}&code_challenge_method=S256",
            identity_api::oidc::token::sha256_b64url("some-other-verifier")
        ),
        &session,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(location.starts_with(&format!("{REDIRECT}?code=")), "silent consent: {location}");
}

#[sqlx::test(migrations = "./migrations")]
async fn redirect_uri_must_match_exactly(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);

    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    let session = login_existing(&router, "owner@example.com", "password-123").await;
    insert_client(&pool, org, "awapp_test", "test-secret-1").await;

    let challenge = identity_api::oidc::token::sha256_b64url("v");

    // Unregistered redirect URI: no redirect, plain error.
    for evil in [
        "https://evil.example.com/callback",
        "http://localhost:9999/callback",
        &format!("{REDIRECT}/extra"),
    ] {
        let resp = request_as(
            &router,
            "GET",
            &format!(
                "/oidc/authorize?client_id=awapp_test&redirect_uri={evil}&response_type=code&scope=openid&code_challenge={challenge}&code_challenge_method=S256"
            ),
            &session,
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "reject {evil}");
        let body = body_json(resp).await;
        assert_eq!(body["error"], "invalid_request");
    }

    // Unknown client: no redirect.
    let resp = request_as(
        &router,
        "GET",
        &format!(
            "/oidc/authorize?client_id=awapp_unknown&redirect_uri={REDIRECT}&response_type=code&scope=openid&code_challenge={challenge}"
        ),
        &session,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn refresh_token_rotation_and_reuse_detection(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);

    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    let session = login_existing(&router, "owner@example.com", "password-123").await;
    insert_client(&pool, org, "awapp_test", "test-secret-1").await;

    let (tokens, _flow) = full_flow(&router, &pool, org, &session, "awapp_test", "test-secret-1", true).await;
    let refresh_r1 = tokens["refresh_token"].as_str().unwrap().to_string();

    // Concurrent use has exactly one winner. The losing request is detected
    // as reuse and revokes the winner's replacement token family.
    let (resp_a, resp_b) = tokio::join!(
        refresh_tokens(&router, &refresh_r1),
        refresh_tokens(&router, &refresh_r1),
    );
    let (ok, rejected) = if resp_a.status() == StatusCode::OK {
        (resp_a, resp_b)
    } else {
        (resp_b, resp_a)
    };
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_json(ok).await;
    let refresh_r2 = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(refresh_r1, refresh_r2, "refresh token rotated");

    let resp = refresh_tokens(&router, &refresh_r2).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY, "family revoked");

    let successors: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE rotated_from_id = (SELECT id FROM refresh_tokens WHERE token_hash = $1)",
    )
    .bind(identity_api::tokens::hash_token(&refresh_r1))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(successors, 1, "only one successor may be minted");

    // The reuse event is in the audit log; each reuse attempt is recorded.
    let reuse_events: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE event_type = 'oauth.refresh_token_reuse'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(reuse_events >= 1, "reuse attempts must be audited");
}

#[sqlx::test(migrations = "./migrations")]
async fn rfc7009_revocation_works(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);

    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    let session = login_existing(&router, "owner@example.com", "password-123").await;
    insert_client(&pool, org, "awapp_test", "test-secret-1").await;

    let (tokens, _flow) = full_flow(&router, &pool, org, &session, "awapp_test", "test-secret-1", true).await;
    let access = tokens["access_token"].as_str().unwrap().to_string();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();

    // Revoke the access token.
    let resp = request_form(
        &router,
        "POST",
        "/oidc/revoke",
        &[
            ("token", &access),
            ("client_id", "awapp_test"),
            ("client_secret", "test-secret-1"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = request_bearer(&router, "GET", "/oidc/userinfo", &access, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "revoked access token rejected");

    // Revoke the refresh token.
    let resp = request_form(
        &router,
        "POST",
        "/oidc/revoke",
        &[
            ("token", &refresh),
            ("client_id", "awapp_test"),
            ("client_secret", "test-secret-1"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = request_form(
        &router,
        "POST",
        "/oidc/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", "awapp_test"),
            ("client_secret", "test-secret-1"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY, "revoked refresh token rejected");

    let reuse_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE event_type = 'oauth.refresh_token_reuse'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reuse_events, 0, "explicit revocation is not token reuse");
}

#[sqlx::test(migrations = "./migrations")]
async fn suspended_members_cannot_use_or_refresh_tokens(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);
    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let member = create_user(&pool, "member@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    add_member(&pool, org, member, "Member").await;
    insert_client(&pool, org, "awapp_test", "test-secret-1").await;

    let owner_session = login_existing(&router, "owner@example.com", "password-123").await;
    let member_session = login_existing(&router, "member@example.com", "password-123").await;
    let (tokens, _) = full_flow(
        &router,
        &pool,
        org,
        &member_session,
        "awapp_test",
        "test-secret-1",
        true,
    )
    .await;
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();

    request_as(
        &router,
        "POST",
        "/api/auth/reauth",
        &owner_session,
        Some(serde_json::json!({ "password": "password-123" })),
    )
    .await;
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/members/{member}/suspend"),
        &owner_session,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = request_bearer(&router, "GET", "/oidc/userinfo", access, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = refresh_tokens(&router, refresh).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let live_access: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM access_token_records WHERE actor_id = $1 AND org_id = $2 AND revoked_at IS NULL",
    )
    .bind(member)
    .bind(org)
    .fetch_one(&pool)
    .await
    .unwrap();
    let live_refresh: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE actor_id = $1 AND org_id = $2 AND revoked_at IS NULL",
    )
    .bind(member)
    .bind(org)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((live_access, live_refresh), (0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn signing_key_rotation_keeps_in_flight_tokens_valid(pool: PgPool) {
    let state = test_state(pool.clone()).await;
    let router = router(state.clone());
    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    let session = login_existing(&router, "owner@example.com", "password-123").await;
    insert_client(&pool, org, "awapp_test", "test-secret-1").await;

    let (tokens, _) = full_flow(
        &router,
        &pool,
        org,
        &session,
        "awapp_test",
        "test-secret-1",
        true,
    )
    .await;
    let old_access = tokens["access_token"].as_str().unwrap();
    let old_kid = jsonwebtoken::decode_header(old_access).unwrap().kid.unwrap();

    let new_key = identity_api::oidc::keys::rotate_key(&pool).await.unwrap();
    assert_ne!(old_kid, new_key.kid);
    let resp = request_bearer(&router, "GET", "/oidc/userinfo", old_access, None).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let refreshed = refresh_tokens(&router, tokens["refresh_token"].as_str().unwrap()).await;
    assert_eq!(refreshed.status(), StatusCode::OK);
    let new_access = body_json(refreshed).await["access_token"].as_str().unwrap().to_string();
    assert_eq!(jsonwebtoken::decode_header(&new_access).unwrap().kid.as_deref(), Some(new_key.kid.as_str()));
}

#[sqlx::test(migrations = "./migrations")]
async fn device_enrollment_and_permission_check(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);

    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let member = create_user(&pool, "member@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    add_member(&pool, org, member, "Member").await;
    let session_owner = login_existing(&router, "owner@example.com", "password-123").await;

    // Create an enrollment token (single-use, expiring).
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/enrollment-tokens"),
        &session_owner,
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let token = body_json(resp).await["token"].as_str().unwrap().to_string();

    // Enroll a device.
    let resp = request(
        &router,
        "POST",
        "/api/enroll",
        Some(serde_json::json!({ "token": token, "name": "sensor-01" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let device_id = body["device"]["id"].as_str().unwrap().to_string();
    let dev_client = body["clientId"].as_str().unwrap().to_string();
    let dev_secret = body["clientSecret"].as_str().unwrap().to_string();

    let persisted_expiry: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT credential_expires_at FROM devices WHERE id = $1",
    )
    .bind(device_id.parse::<uuid::Uuid>().unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(persisted_expiry > chrono::Utc::now());

    // The token is single-use.
    let resp = request(
        &router,
        "POST",
        "/api/enroll",
        Some(serde_json::json!({ "token": token, "name": "sensor-02" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "enrollment token is single-use");

    sqlx::query("UPDATE devices SET credential_expires_at = now() - interval '1 minute' WHERE id = $1")
        .bind(device_id.parse::<uuid::Uuid>().unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let resp = request_form(
        &router,
        "POST",
        "/oidc/token",
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &dev_client),
            ("client_secret", &dev_secret),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "expired device credential rejected");
    sqlx::query("UPDATE devices SET credential_expires_at = now() + interval '1 day' WHERE id = $1")
        .bind(device_id.parse::<uuid::Uuid>().unwrap())
        .execute(&pool)
        .await
        .unwrap();

    // The device authenticates via client_credentials.
    let resp = request_form(
        &router,
        "POST",
        "/oidc/token",
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &dev_client),
            ("client_secret", &dev_secret),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let dev_token = body_json(resp).await["access_token"].as_str().unwrap().to_string();

    // The device checks permissions through the documented endpoint.
    let resp = request_bearer(
        &router,
        "POST",
        "/api/v1/authorize/check",
        &dev_token,
        Some(serde_json::json!({ "organizationId": org, "userId": member, "permission": "continuity.document.read" })),
    )
    .await;
    let body = body_json(resp).await;
    assert_eq!(body["allowed"], false, "Member has no product permission by default: {body:?}");

    // Grant the permission via a custom role.
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/roles"),
        &session_owner,
        Some(serde_json::json!({
            "name": "Document Reader",
            "permissions": ["continuity.document.read"],
        })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let role_id = body_json(resp).await["role"]["id"].as_str().unwrap().to_string();

    request_as(
        &router,
        "POST",
        "/api/auth/reauth",
        &session_owner,
        Some(serde_json::json!({ "password": "password-123" })),
    )
    .await;
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/members/{member}/role"),
        &session_owner,
        Some(serde_json::json!({ "roleId": role_id })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = request_bearer(
        &router,
        "POST",
        "/api/v1/authorize/check",
        &dev_token,
        Some(serde_json::json!({ "organizationId": org, "userId": member, "permission": "continuity.document.read" })),
    )
    .await;
    let body = body_json(resp).await;
    assert_eq!(body["allowed"], true, "role-granted permission allowed");

    // The owner reauthenticated earlier in this test (role assignment), so
    // the sensitive revocation succeeds within the reauth window.
    let resp = request_as(
        &router,
        "DELETE",
        &format!("/api/orgs/{org}/devices/{device_id}"),
        &session_owner,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "device revoked");

    let resp = request_bearer(
        &router,
        "POST",
        "/api/v1/authorize/check",
        &dev_token,
        Some(serde_json::json!({ "organizationId": org, "userId": member, "permission": "continuity.document.read" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "revoked device access token rejected");

    // A revoked device can no longer mint tokens.
    let resp = request_form(
        &router,
        "POST",
        "/oidc/token",
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &dev_client),
            ("client_secret", &dev_secret),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "revoked device credential rejected");

    // Audit trail: enrollment + revocation recorded.
    let enroll: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE event_type = 'device.enrolled'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let revoke: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE event_type = 'device.revoked'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(enroll, 1);
    assert_eq!(revoke, 1);
}

// ------------------------------------------------------------------ helpers

#[sqlx::test(migrations = "./migrations")]
async fn rp_initiated_logout_ends_the_browser_session(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);
    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    let session = login_existing(&router, "owner@example.com", "password-123").await;
    insert_client(&pool, org, "awapp_test", "test-secret-1").await;

    let (tokens, _) = full_flow(
        &router,
        &pool,
        org,
        &session,
        "awapp_test",
        "test-secret-1",
        true,
    )
    .await;
    let id_token = tokens["id_token"].as_str().unwrap();

    // Registered post-logout URI: 303 with state, and the session ends.
    let resp = request_as(
        &router,
        "GET",
        &format!(
            "/oidc/end-session?id_token_hint={id_token}&post_logout_redirect_uri=http://localhost:5174/logout&state=bye"
        ),
        &session,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("http://localhost:5174/logout"), "{location}");
    assert!(location.contains("state=bye"), "{location}");

    let resp = request_as(&router, "GET", "/api/auth/me", &session, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "RP logout ended the session");

    // New session: an unregistered post-logout URI must not redirect.
    let session2 = login_existing(&router, "owner@example.com", "password-123").await;
    let (tokens2, _) = full_flow(
        &router,
        &pool,
        org,
        &session2,
        "awapp_test",
        "test-secret-1",
        false,
    )
    .await;
    let id2 = tokens2["id_token"].as_str().unwrap();
    let resp = request_as(
        &router,
        "GET",
        &format!(
            "/oidc/end-session?id_token_hint={id2}&post_logout_redirect_uri=https://evil.example.com/out"
        ),
        &session2,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // An invalid id_token_hint is rejected outright, even with a valid
    // redirect target.
    let resp = request_as(
        &router,
        "GET",
        "/oidc/end-session?id_token_hint=garbage.token.value&post_logout_redirect_uri=http://localhost:5174/logout",
        &session2,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Each successful logout (both the registered-redirect call and the
    // unregistered-redirect call, which still ends the session before
    // refusing the redirect) is audited; the invalid-hint call is not.
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE event_type = 'auth.logout_rp'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 2);
}

async fn refresh_tokens(router: &axum::Router, token: &str) -> axum::response::Response<axum::body::Body> {
    request_form(
        router,
        "POST",
        "/oidc/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", "awapp_test"),
            ("client_secret", "test-secret-1"),
        ],
    )
    .await
}

pub async fn login_existing(router: &axum::Router, email: &str, password: &str) -> String {
    let resp = request(
        router,
        "POST",
        "/api/auth/login",
        Some(serde_json::json!({ "email": email, "password": password })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "login {email}");
    session_cookie(&resp)
}
