//! Correlation-ID middleware and per-request HTTP metadata.

use std::net::{IpAddr, SocketAddr};

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
pub fn http_meta(parts: &mut Parts, trust_proxy: bool) -> HttpMeta {
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

    let peer_ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let ip = if trust_proxy {
        parts
            .headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.rsplit(',').next())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
            .or(peer_ip)
    } else {
        peer_ip
    };

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
        state: &crate::state::AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(http_meta(parts, state.config.trust_proxy))
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn request_parts(forwarded_for: Option<&str>) -> Parts {
        let mut request = Request::builder();
        if let Some(value) = forwarded_for {
            request = request.header("x-forwarded-for", value);
        }
        let (mut parts, _) = request.body(()).unwrap().into_parts();
        parts.extensions.insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 2], 1234))));
        parts
    }

    #[test]
    fn forwarded_ip_is_used_only_for_trusted_proxy() {
        let mut parts = request_parts(Some("198.51.100.7, 203.0.113.9"));
        assert_eq!(http_meta(&mut parts, true).ip, Some("203.0.113.9".parse().unwrap()));

        let mut parts = request_parts(Some("198.51.100.7"));
        assert_eq!(http_meta(&mut parts, false).ip, Some("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn malformed_forwarded_ip_falls_back_to_peer() {
        let mut parts = request_parts(Some("not-an-ip"));
        assert_eq!(http_meta(&mut parts, true).ip, Some("10.0.0.2".parse().unwrap()));
    }
}
