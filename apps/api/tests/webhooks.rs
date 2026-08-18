//! Webhooks: CRUD, signature verification and asynchronous delivery of
//! org-scoped audit events to a real local HTTP listener.

mod common;

use axum::http::StatusCode;
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use common::*;

/// Bind a local listener that accepts up to two HTTP requests, captures the
/// raw headers and body of each, and responds 200.
async fn spin_listener() -> (u16, tokio::sync::mpsc::Receiver<(String, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        for _ in 0..2 {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buffer.extend_from_slice(&chunk[..n]);
                if let Some(header_end) = find_header_end(&buffer) {
                    let content_length = parse_content_length(&buffer[..header_end]);
                    let total = header_end + 4 + content_length;
                    if buffer.len() >= total {
                        break;
                    }
                }
            }
            let header_end = find_header_end(&buffer).unwrap();
            let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
            let body = buffer[header_end + 4..].to_vec();
            let _ = tx.send((headers, body)).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        }
    });
    (port, rx)
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

#[sqlx::test(migrations = "./migrations")]
async fn webhook_crud_and_delivery(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);
    let owner = create_user(&pool, "owner@example.com", "password-123").await;
    let viewer = create_user(&pool, "viewer@example.com", "password-123").await;
    let org = create_org(&pool, "Acme", "acme", owner).await;
    add_member(&pool, org, viewer, "Viewer").await;
    let session = login_existing(&router, "owner@example.com", "password-123").await;
    let session_viewer = login_existing(&router, "viewer@example.com", "password-123").await;

    let (port, mut received) = spin_listener().await;
    let url = format!("http://127.0.0.1:{port}/hook");

    // Viewers cannot manage webhooks.
    let resp = request_as(
        &router,
        "GET",
        &format!("/api/orgs/{org}/webhooks"),
        &session_viewer,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Invalid URLs are rejected.
    request_as(
        &router,
        "POST",
        "/api/auth/reauth",
        &session,
        Some(serde_json::json!({ "password": "password-123" })),
    )
    .await;
    for bad in ["file:///etc/passwd", "https://user:pass@example.com/hook", "not a url"] {
        let resp = request_as(
            &router,
            "POST",
            &format!("/api/orgs/{org}/webhooks"),
            &session,
            Some(serde_json::json!({ "url": bad })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }

    // Create (reauth window is still valid from above).
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/webhooks"),
        &session,
        Some(serde_json::json!({ "url": url })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let webhook_id = body["webhook"]["id"].as_str().unwrap().to_string();
    let secret = body["secret"].as_str().unwrap().to_string();
    assert!(secret.starts_with("awwh_"));

    // The secret is stored encrypted, never in the clear.
    let row: (String, String) = sqlx::query_as(
        "SELECT secret_nonce, secret_ciphertext FROM webhook_endpoints WHERE id = $1",
    )
    .bind(webhook_id.parse::<uuid::Uuid>().unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!row.1.contains(&secret), "webhook secret must be encrypted at rest");

    // Trigger an org-scoped audit event: creating a team.
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/teams"),
        &session,
        Some(serde_json::json!({ "name": "Platform" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // The delivery lands asynchronously; poll the delivery log for it.
    let delivery_id: Option<uuid::Uuid> = {
        let mut found: Option<uuid::Uuid> = None;
        for _ in 0..40 {
            let id = sqlx::query_scalar::<_, uuid::Uuid>(
                "SELECT id FROM webhook_deliveries WHERE event_type = 'team.created' ORDER BY created_at DESC LIMIT 1",
            )
            .fetch_optional(&pool)
            .await
            .unwrap();
            if id.is_some() {
                found = id;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        found
    };
    assert!(delivery_id.is_some(), "webhook delivery must be recorded");

    // The receiver got the deliveries; the first is the creation event
    // itself, the second is the team event. Verify the team event and its
    // signature with the returned secret.
    let mut received_events = Vec::new();
    for _ in 0..2 {
        match tokio::time::timeout(std::time::Duration::from_secs(5), received.recv()).await {
            Ok(Some(event)) => received_events.push(event),
            _ => break,
        }
    }
    let (headers, body) = received_events
        .into_iter()
        .find(|(_, body)| {
            serde_json::from_slice::<serde_json::Value>(body)
                .map(|v| v["eventType"] == "team.created")
                .unwrap_or(false)
        })
        .expect("the team.created event must be delivered");

    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["eventType"], "team.created");
    assert_eq!(payload["orgId"], org.to_string());
    assert_eq!(payload["actorId"], owner.to_string());

    let signature_header = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("x-arcticworks-signature") {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .expect("signature header");
    let (t_part, v1_part) = signature_header.split_once(',').unwrap();
    let timestamp: i64 = t_part.strip_prefix("t=").unwrap().parse().unwrap();
    let signature = v1_part.trim().strip_prefix("v1=").unwrap();
    assert!(
        identity_api::webhooks::verify_signature(secret.as_bytes(), timestamp, &payload.to_string(), signature),
        "delivery signature must verify with the returned secret"
    );

    // List + deliveries endpoint.
    let resp = request_as(&router, "GET", &format!("/api/orgs/{org}/webhooks"), &session, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["webhooks"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["webhooks"][0]["secretPreview"],
        format!("…{}", &secret[secret.len() - 4..])
    );

    let resp = request_as(
        &router,
        "GET",
        &format!("/api/orgs/{org}/webhooks/{webhook_id}/deliveries"),
        &session,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let deliveries = body["deliveries"].as_array().unwrap();
    let team_delivery = deliveries
        .iter()
        .find(|d| d["eventType"] == "team.created")
        .expect("team.created delivery");
    assert_eq!(team_delivery["status"], "success");
    assert_eq!(team_delivery["attempts"], 1);

    // Rotate the secret (reauth window still valid).
    let resp = request_as(
        &router,
        "POST",
        &format!("/api/orgs/{org}/webhooks/{webhook_id}/rotate-secret"),
        &session,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let new_secret = body_json(resp).await["secret"].as_str().unwrap().to_string();
    assert_ne!(new_secret, secret);

    // Disable + delete.
    let resp = request_as(
        &router,
        "PATCH",
        &format!("/api/orgs/{org}/webhooks/{webhook_id}"),
        &session,
        Some(serde_json::json!({ "enabled": false })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = request_as(
        &router,
        "DELETE",
        &format!("/api/orgs/{org}/webhooks/{webhook_id}"),
        &session,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Audit trail covers the lifecycle.
    for event in ["webhook.created", "webhook.secret_rotated", "webhook.updated", "webhook.deleted"] {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE event_type = $1")
            .bind(event)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(count >= 1, "missing audit event {event}");
    }
}

async fn login_existing(router: &axum::Router, email: &str, password: &str) -> String {
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
