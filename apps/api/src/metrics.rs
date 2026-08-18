//! Prometheus-text metrics: per-route request counters and database pool
//! gauges. Kept dependency-free on purpose — the exposition format is
//! stable enough to hand-roll for this small surface.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use dashmap::DashMap;

#[derive(Default)]
pub struct Metrics {
    counters: DashMap<String, u64>,
}

impl Metrics {
    fn key(name: &str, labels: &[(&str, &str)]) -> String {
        if labels.is_empty() {
            return name.to_string();
        }
        let rendered: Vec<String> = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect();
        format!("{name}{{{}}}", rendered.join(","))
    }

    pub fn increment(&self, name: &str, labels: &[(&str, &str)], value: u64) {
        let key = Self::key(name, labels);
        *self.counters.entry(key).or_insert(0) += value;
    }

    pub fn render(&self) -> String {
        let mut entries: Vec<(String, u64)> = self
            .counters
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut out = String::new();
        out.push_str("# HELP http_requests_total Total HTTP requests handled.\n");
        out.push_str("# TYPE http_requests_total counter\n");
        for (key, value) in entries {
            out.push_str(&format!("{key} {value}\n"));
        }
        out
    }
}

/// Middleware counting requests by method, route pattern and status class.
pub async fn middleware(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    state.metrics.increment(
        "http_requests_total",
        &[("method", &method), ("path", &path), ("status", &status.to_string())],
        1,
    );
    response
}

pub async fn endpoint(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
) -> Response {
    let mut body = state.metrics.render();
    let idle = state.pool.num_idle();
    let size = state.pool.size() as usize;
    body.push_str("# HELP db_pool_connections Current database connection pool usage.\n");
    body.push_str("# TYPE db_pool_connections gauge\n");
    body.push_str(&format!("db_pool_connections{{state=\"idle\"}} {idle}\n"));
    body.push_str(&format!(
        "db_pool_connections{{state=\"used\"}} {}\n",
        size.saturating_sub(idle)
    ));

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    let mut response = Response::new(axum::body::Body::from(body));
    *response.status_mut() = axum::http::StatusCode::OK;
    *response.headers_mut() = headers;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_sorted_prometheus_lines() {
        let metrics = Metrics::default();
        metrics.increment("http_requests_total", &[("method", "GET"), ("status", "200")], 3);
        metrics.increment("http_requests_total", &[("method", "POST"), ("status", "401")], 1);
        let rendered = metrics.render();
        assert!(rendered.contains(r#"http_requests_total{method="GET",status="200"} 3"#));
        assert!(rendered.contains(r#"http_requests_total{method="POST",status="401"} 1"#));
        assert!(rendered.starts_with("# HELP http_requests_total"));
    }

    #[test]
    fn label_values_are_escaped() {
        let metrics = Metrics::default();
        metrics.increment("x", &[("path", "/a\"b")], 1);
        assert!(metrics.render().contains(r#"x{path="/a\"b"} 1"#));
    }
}
