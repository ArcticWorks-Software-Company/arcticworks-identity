//! ArcticWorks Identity API.
//!
//! Modular monolith: HTTP handlers are thin adapters over domain modules
//! (`accounts`, `orgs`, `rbac`, `oidc`, `machine`, ...). Domain logic never
//! depends on HTTP types; database access lives in the same crate but behind
//! module boundaries so it can be swapped later.

pub mod accounts;
pub mod audit;
pub mod authn;
pub mod config;
pub mod correlation;
pub mod email;
pub mod error;
pub mod ids;
pub mod machine;
pub mod openapi;
pub mod orgs;
pub mod oidc;
pub mod passkeys;
pub mod ratelimit;
pub mod rbac;
pub mod state;
pub mod tokens;
pub mod totp;
pub mod util;

use axum::http::header;
use axum::http::Method;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

pub async fn run_migrations(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

pub fn app(state: state::AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(state.config.allowed_origins_header_values())
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PATCH])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            "x-correlation-id".parse().unwrap(),
        ]);

    let api = Router::new()
        .merge(accounts::routes())
        .merge(orgs::routes())
        .merge(machine::routes())
        .merge(oidc::routes())
        .merge(passkeys::routes())
        .merge(rbac::routes())
        .merge(totp::routes())
        .merge(if state.config.docs_enabled {
            openapi::routes()
        } else {
            Router::new()
        });

    Router::new()
        .route("/healthz", get(healthz))
        .route("/healthz/ready", get(ready))
        .merge(api)
        .layer(cors)
        .layer(CatchPanicLayer::custom(LogPanicHandler))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(correlation::correlation_middleware))
        .with_state(state)
}

/// Log handler panics (with the panic payload) before returning 500.
#[derive(Clone)]
struct LogPanicHandler;

impl tower_http::catch_panic::ResponseForPanic for LogPanicHandler {
    type ResponseBody = axum::body::Body;

    fn response_for_panic(
        &mut self,
        err: std::boxed::Box<dyn std::any::Any + Send + 'static>,
    ) -> axum::response::Response<Self::ResponseBody> {
        let message = if let Some(s) = err.downcast_ref::<&'static str>() {
            (*s).to_string()
        } else if let Some(s) = err.downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };
        tracing::error!(panic = %message, "handler panicked");
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "error": { "code": "internal", "message": "internal server error" }
            })),
        )
            .into_response()
    }
}

async fn healthz() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "arcticworks-identity",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Readiness: verifies database connectivity (the rate-limit store is
/// optional and falls back to in-memory).
async fn ready(axum::extract::State(state): axum::extract::State<state::AppState>) -> impl axum::response::IntoResponse {
    let db_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    (
        if db_ok {
            axum::http::StatusCode::OK
        } else {
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        },
        axum::Json(serde_json::json!({
            "status": if db_ok { "ready" } else { "degraded" },
            "database": db_ok,
        })),
    )
}
