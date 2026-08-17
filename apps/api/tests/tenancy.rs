//! Tenant isolation and privilege escalation: org-scoped authorization,
//! suspended members, role-based permission checks, invitation flows.

mod common;

use axum::http::StatusCode;
use sqlx::PgPool;
use secrecy::ExposeSecret;

use common::*;

#[sqlx::test(migrations = "./migrations")]
async fn cross_org_access_is_denied(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);

    let owner_a = create_user(&pool, "a@example.com", "password-123").await;
    let owner_b = create_user(&pool, "b@example.com", "password-123").await;
    let org_a = create_org(&pool, "Org A", "org-a", owner_a).await;
    create_org(&pool, "Org B", "org-b", owner_b).await;

    let session_b = login_existing(&router, "b@example.com", "password-123").await;

    // Every org-owned read and write from another tenant is forbidden.
    let checks: [(&str, &str); 5] = [
        ("GET", &format!("/api/orgs/{org_a}/members")),
        ("GET", &format!("/api/orgs/{org_a}/teams")),
        ("GET", &format!("/api/orgs/{org_a}/audit-log")),
        ("GET", &format!("/api/orgs/{org_a}/applications")),
        ("GET", &format!("/api/orgs/{org_a}/service-accounts")),
    ];
    for (method, path) in checks {
        let resp = request_as(&router, method, path, &session_b, None).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method} {path} must be forbidden cross-tenant");
    }

    let resp = request_as(
        &router,
        "PATCH",
        &format!("/api/orgs/{org_a}"),
        &session_b,
        Some(serde_json::json!({ "name": "hacked", "slug": "hacked" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "cross-tenant org update");

    // Switch attempts to the other org also fail.
    let resp = request_as(&router, "POST", &format!("/api/orgs/{org_a}/switch"), &session_b, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
async fn privilege_escalation_is_denied_and_roles_apply(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);

    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let viewer = create_user(&pool, "viewer@example.com", "password-123").await;
    let member = create_user(&pool, "member@example.com", "password-123").await;
    let outsider = create_user(&pool, "outsider@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    add_member(&pool, org, viewer, "Viewer").await;
    add_member(&pool, org, member, "Member").await;

    let session_viewer = login_existing(&router, "viewer@example.com", "password-123").await;
    let session_member = login_existing(&router, "member@example.com", "password-123").await;
    let session_owner = login_existing(&router, "owner@example.com", "password-123").await;
    let session_outsider = login_existing(&router, "outsider@example.com", "password-123").await;

    // Viewer cannot perform any administrative action.
    let escalation_attempts: Vec<(String, String, Option<serde_json::Value>)> = vec![
        (
            "POST".into(),
            format!("/api/orgs/{org}/members/{member}/role"),
            Some(serde_json::json!({ "roleId": "00000000-0000-7000-8000-000000000099" })),
        ),
        ("POST".into(), format!("/api/orgs/{org}/members/{member}/suspend"), None),
        ("DELETE".into(), format!("/api/orgs/{org}/members/{viewer}"), None),
        (
            "POST".into(),
            format!("/api/orgs/{org}/invitations"),
            Some(serde_json::json!({ "email": "x@example.com", "roleId": "00000000-0000-7000-8000-000000000099" })),
        ),
        (
            "POST".into(),
            format!("/api/orgs/{org}/teams"),
            Some(serde_json::json!({ "name": "Team" })),
        ),
        (
            "POST".into(),
            format!("/api/orgs/{org}/applications"),
            Some(serde_json::json!({ "name": "App", "redirectUris": ["https://app.example.com/cb"] })),
        ),
        (
            "POST".into(),
            format!("/api/orgs/{org}/service-accounts"),
            Some(serde_json::json!({ "name": "sa", "roleId": "00000000-0000-7000-8000-000000000099" })),
        ),
        ("POST".into(), format!("/api/orgs/{org}/enrollment-tokens"), Some(serde_json::json!({}))),
    ];
    for (method, path, body) in escalation_attempts {
        let resp = request_as(&router, &method, &path, &session_viewer, body).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method} {path} must be forbidden for Viewer");
    }

    // A non-member cannot even switch into the org.
    let resp = request_as(&router, "POST", &format!("/api/orgs/{org}/switch"), &session_outsider, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Member role cannot create teams (needs org.teams.manage).
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/teams"),
        &session_member,
        Some(serde_json::json!({ "name": "Squad" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Owner creates a custom role and grants it to the member: the member
    // gains exactly the granted permission and nothing else.
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/roles"),
        &session_owner,
        Some(serde_json::json!({
            "name": "Team Lead",
            "permissions": ["org.teams.manage"],
        })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let role_id = body_json(resp).await["role"]["id"].as_str().unwrap().to_string();

    let member_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email = 'member@example.com'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/members/{member_id}/role"),
        &session_owner,
        Some(serde_json::json!({ "roleId": role_id })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/teams"),
        &session_member,
        Some(serde_json::json!({ "name": "Squad" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED, "member with granted role can create teams");

    // Still cannot suspend members (not granted).
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/members/{viewer}/suspend"),
        &session_member,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // The Owner role cannot be assigned via the role endpoint.
    let owner_role: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM roles WHERE org_id = $1 AND name = 'Owner'",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .unwrap();
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/members/{member_id}/role"),
        &session_owner,
        Some(serde_json::json!({ "roleId": owner_role })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[sqlx::test(migrations = "./migrations")]
async fn suspended_members_lose_all_access(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);

    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let victim = create_user(&pool, "victim@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    add_member(&pool, org, victim, "Member").await;

    let session_owner = login_existing(&router, "owner@example.com", "password-123").await;
    let session_victim = login_existing(&router, "victim@example.com", "password-123").await;

    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/members/{victim}/suspend"),
        &session_owner,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Suspended member: no reads, no switches, no org context at all.
    let resp = request_as(&router, "GET", &format!("/api/orgs/{org}/teams"), &session_victim, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = request_as(&router, "POST", &format!("/api/orgs/{org}/switch"), &session_victim, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Permission checks treat a suspended member as denied.
    let sa_token = create_service_account_token(&router, &pool, org, "backoffice").await;
    let resp = request(
        &router,
        "POST",
        "/api/v1/authorize/check",
        Some(serde_json::json!({ "organizationId": org, "userId": victim, "permission": "org.teams.read" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "missing bearer must fail");
    let resp = request_bearer(
        &router,
        "POST",
        "/api/v1/authorize/check",
        &sa_token,
        Some(serde_json::json!({ "organizationId": org, "userId": victim, "permission": "org.teams.read" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["allowed"], false, "suspended member is denied by default");

    // Same check for the owner is allowed.
    let resp = request_bearer(
        &router,
        "POST",
        "/api/v1/authorize/check",
        &sa_token,
        Some(serde_json::json!({ "organizationId": org, "userId": owner, "permission": "org.teams.read" })),
    )
    .await;
    let body = body_json(resp).await;
    assert_eq!(body["allowed"], true, "owner is allowed");

    // A service account can never check another organization.
    let other_org = create_org(&pool, "Elsewhere", "elsewhere", owner).await;
    let resp = request_bearer(
        &router,
        "POST",
        "/api/v1/authorize/check",
        &sa_token,
        Some(serde_json::json!({ "organizationId": other_org, "userId": owner, "permission": "org.teams.read" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "tenant isolation on the check endpoint");
}

#[sqlx::test(migrations = "./migrations")]
async fn invitation_flow_is_role_bounded_and_audited(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);

    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    let session_owner = login_existing(&router, "owner@example.com", "password-123").await;

    let member_role: uuid::Uuid = sqlx::query_scalar("SELECT id FROM roles WHERE org_id = $1 AND name = 'Member'")
        .bind(org)
        .fetch_one(&pool)
        .await
        .unwrap();

    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/invitations"),
        &session_owner,
        Some(serde_json::json!({ "email": "invitee@example.com", "roleId": member_role })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // The invitee registers and accepts.
    let invitee_session = register_verify_login(&router, &pool, "invitee@example.com", "password-123").await;

    // Token is hashed at rest; retrieve the plaintext path by inserting our own.
    let token = identity_api::tokens::random_token();
    sqlx::query(
        "UPDATE invitations SET token_hash = $1 WHERE email = 'invitee@example.com'",
    )
    .bind(identity_api::tokens::hash_token(&token))
    .execute(&pool)
    .await
    .unwrap();

    // Someone else cannot accept the invitation.
    let other = create_user(&pool, "other@example.com", "password-123").await;
    let session_other = login_existing(&router, "other@example.com", "password-123").await;
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/invitations/{token}/accept"),
        &session_other,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "invitation is bound to the invited email");
    let _ = other;

    let resp = request_as(
        &router,
        "POST",
        &format!("/api/invitations/{token}/accept"),
        &invitee_session,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["organization"]["slug"], "acme");

    // The invitee now has the Member role: read-only.
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/teams"),
        &invitee_session,
        Some(serde_json::json!({ "name": "Nope" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // The token is single-use.
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/invitations/{token}/accept"),
        &invitee_session,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::GONE);

    // Audit trail contains the invitation events.
    let resp = request_as(&router, "GET", &format!("/api/orgs/{org}/audit-log"), &session_owner, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let events: Vec<String> = body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["eventType"].as_str().unwrap().to_string())
        .collect();
    assert!(events.contains(&"invite.created".to_string()), "events: {events:?}");
    assert!(events.contains(&"invite.accepted".to_string()), "events: {events:?}");
}

// ------------------------------------------------------------------ helpers

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

/// Insert a service account with a known credential and return its bearer
/// token via the client_credentials grant.
pub async fn create_service_account_token(
    router: &axum::Router,
    pool: &PgPool,
    org_id: uuid::Uuid,
    name: &str,
) -> String {
    let sa_id = uuid::Uuid::now_v7();
    let client_id = format!("awsa_test_{name}");
    let secret = identity_api::tokens::random_secret("awsec");
    let mut conn = pool.acquire().await.unwrap();
    let role = identity_api::rbac::find_org_role(&mut *conn, org_id, "Member")
        .await
        .unwrap()
        .unwrap();
    sqlx::query(
        "INSERT INTO service_accounts (id, org_id, name, role_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(sa_id)
    .bind(org_id)
    .bind(name)
    .bind(role)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO service_account_credentials
            (id, service_account_id, client_id, secret_hash, preview, expires_at)
        VALUES ($1, $2, $3, $4, '…x', now() + interval '90 days')
        "#,
    )
    .bind(uuid::Uuid::now_v7())
    .bind(sa_id)
    .bind(&client_id)
    .bind(identity_api::tokens::hash_token(secret.expose_secret()))
    .execute(pool)
    .await
    .unwrap();

    let resp = request_form(
        router,
        "POST",
        "/oidc/token",
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", secret.expose_secret()),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "client_credentials grant");
    body_json(resp).await["access_token"].as_str().unwrap().to_string()
}
