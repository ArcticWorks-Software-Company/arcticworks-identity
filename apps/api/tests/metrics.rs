//! Metrics endpoint: Prometheus-text exposition with request counters and
//! database pool gauges.

mod common;

use axum::http::StatusCode;
use sqlx::PgPool;

use common::*;

#[sqlx::test(migrations = "./migrations")]
async fn metrics_endpoint_exposes_counters(pool: PgPool) {
    let router = router(test_state(pool.clone()).await);

    let resp = request(&router, "GET", "/healthz", None).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = request(&router, "GET", "/metrics", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body = String::from_utf8_lossy(&bytes).to_string();

    assert!(body.starts_with("# HELP http_requests_total"), "{body}");
    assert!(body.contains("# TYPE http_requests_total counter"));
    // The /metrics request cannot count itself (the counter increments after
    // the body is rendered), but earlier requests must be visible.
    assert!(body.contains(r#"http_requests_total{method="GET",path="/healthz",status="200"} 1"#), "{body}");
    assert!(body.contains("# TYPE db_pool_connections gauge"));
    assert!(body.contains(r#"db_pool_connections{state="idle"}"#));
}
