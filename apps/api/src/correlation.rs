//! Correlation-ID middleware and per-request HTTP metadata.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;
use uuid::Uuid;

use crate::ids::new_correlation_id;

pub const CORRELATION_HEADER: &str = "x-correlation-id";

#[derive(Debug, Clone, Copy)]
pub struct CorrelationId(pub Uuid);

/// HTTP metadata captured for audit logging: correlation ID, client IP and
/// user agent. Never contains request bodies or credentials.
#[derive(Debug, Clone)]
pub struct HttpMeta {
    pub correlation_id: Uuid,
    pub ip: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
}

/// Extract the correlation id, client IP and user agent from the request.
/// This extractor never fails.
pub async fn http_meta(parts: &mut Parts) -> HttpMeta {
    let correlation_id = parts
        .extensions
        .get::<CorrelationId>()
        .map(|c| c.0)
        .unwrap_or_else(new_correlation_id);

    let user_agent = parts
        .headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());

    HttpMeta {
        correlation_id,
        ip,
        user_agent,
    }
}

impl FromRequestParts<crate::state::AppState> for HttpMeta {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &crate::state::AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(http_meta(parts).await)
    }
}

pub async fn correlation_middleware(
    req: Request,
    next: Next,
) -> Response {
    let incoming = req
        .headers()
        .get(CORRELATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(new_correlation_id);

    let span = tracing::info_span!("request", correlation_id = %incoming);
    let mut req = req;
    req.extensions_mut().insert(CorrelationId(incoming));

    let mut response: Response = async { next.run(req).await }.instrument(span).await;

    if let Ok(v) = HeaderValue::from_str(&incoming.to_string()) {
        response.headers_mut().insert(CORRELATION_HEADER, v);
    }
    response
}
