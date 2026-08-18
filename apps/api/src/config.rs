//! Environment-based configuration. All values are read from the process
//! environment (optionally loaded from a `.env` file at startup).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    None,
    StartTls,
    Tls,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: Option<String>,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub tls: SmtpTls,
}

impl SmtpConfig {
    pub fn is_configured(&self) -> bool {
        self.host.as_deref().is_some_and(|h| !h.is_empty())
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: Option<String>,
    pub api_bind: SocketAddr,

    /// Base URL of the API as seen by clients; used as the OIDC issuer and
    /// for building absolute links.
    pub public_base_url: String,
    /// Origin of the Identity web application (email links, CORS).
    pub web_origin: String,
    pub allowed_origins: Vec<String>,

    pub secure_cookies: bool,
    pub session_cookie_name: String,
    pub session_max_age: Duration,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub reauth_window: Duration,
    pub auth_code_ttl: Duration,
    pub invite_ttl: Duration,
    pub verify_ttl: Duration,
    pub reset_ttl: Duration,
    pub enrollment_ttl: Duration,

    /// WebAuthn relying party.
    pub rp_id: String,
    pub rp_origins: Vec<String>,

    pub smtp: SmtpConfig,
    /// Trust X-Forwarded-For when behind a reverse proxy (production).
    pub trust_proxy: bool,
    /// Base64-encoded 32-byte key encrypting TOTP secrets at rest.
    pub totp_enc_key: Option<String>,
    /// Run database migrations at startup (development convenience).
    pub auto_migrate: bool,
    /// Serve the Swagger/OpenAPI UI at /api/docs.
    pub docs_enabled: bool,
    /// Serve the Prometheus-text metrics endpoint at /metrics.
    pub metrics_enabled: bool,
    pub log_format: LogFormat,

    pub seed_admin_email: String,
    pub seed_admin_password: String,
    /// Resetting the admin password on every seed run is a production
    /// footgun; only do it when explicitly requested.
    pub seed_reset_admin_password: bool,
    pub seed_member_emails: Vec<String>,
    pub seed_org_name: String,

    /// Registration attempts per IP per hour (security default: 3).
    pub register_rate_limit_per_hour: u32,
}

fn get(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn get_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(default)
}

fn get_minutes(name: &str, default_minutes: u64) -> Duration {
    Duration::from_secs(
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(default_minutes)
            * 60,
    )
}

fn get_days(name: &str, default_days: u64) -> Duration {
    Duration::from_secs(
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(default_days)
            * 86400,
    )
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let api_bind = get("API_BIND", "0.0.0.0:8080");
        let log_format = match get("LOG_FORMAT", "text").as_str() {
            "json" => LogFormat::Json,
            _ => LogFormat::Text,
        };

        let smtp = SmtpConfig {
            host: std::env::var("SMTP_HOST").ok().filter(|h| !h.is_empty()),
            port: std::env::var("SMTP_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1025),
            username: std::env::var("SMTP_USERNAME").ok(),
            password: std::env::var("SMTP_PASSWORD").ok(),
            from: get("SMTP_FROM", "ArcticWorks Identity <identity@arcticworks.dev>"),
            tls: match get("SMTP_TLS", "none").as_str() {
                "starttls" => SmtpTls::StartTls,
                "tls" => SmtpTls::Tls,
                _ => SmtpTls::None,
            },
        };

        let web_origin = get("WEB_ORIGIN", "http://localhost:5173");
        let mock_origin = get("MOCK_ORIGIN", "http://localhost:5174");
        let allowed_origins = std::env::var("ALLOWED_ORIGINS").ok().map_or_else(
            || vec![web_origin.clone(), mock_origin.clone()],
            |v| split_list(&v),
        );

        let cfg = Config {
            database_url: get("DATABASE_URL", "postgres://identity:identity@localhost:5433/identity"),
            redis_url: std::env::var("REDIS_URL").ok().filter(|v| !v.is_empty()),
            api_bind: SocketAddr::from_str(&api_bind).map_err(|e| anyhow::anyhow!("invalid API_BIND: {e}"))?,
            public_base_url: get("PUBLIC_BASE_URL", "http://localhost:8080"),
            web_origin,
            allowed_origins,
            secure_cookies: get_bool("SECURE_COOKIES", false),
            session_cookie_name: get("SESSION_COOKIE_NAME", "aw_session"),
            session_max_age: get_days("SESSION_MAX_AGE_DAYS", 30),
            access_token_ttl: get_minutes("ACCESS_TOKEN_TTL_MINUTES", 15),
            refresh_token_ttl: get_days("REFRESH_TOKEN_TTL_DAYS", 30),
            reauth_window: get_minutes("REAUTH_WINDOW_MINUTES", 10),
            auth_code_ttl: get_minutes("AUTH_CODE_TTL_MINUTES", 5),
            invite_ttl: get_days("INVITE_TTL_DAYS", 7),
            verify_ttl: get_days("VERIFY_TTL_HOURS", 24) * 3600 / 86400 * 86400,
            reset_ttl: get_minutes("RESET_TTL_MINUTES", 30),
            enrollment_ttl: get_days("ENROLLMENT_TTL_HOURS", 24) * 3600 / 86400 * 86400,
            rp_id: get("RP_ID", "localhost"),
            rp_origins: split_list(&get("RP_ORIGINS", "http://localhost:5173")),
            smtp,
            trust_proxy: get_bool("TRUST_PROXY", false),
            totp_enc_key: std::env::var("TOTP_ENC_KEY")
                .ok()
                .filter(|v| !v.is_empty()),
            auto_migrate: get_bool("AUTO_MIGRATE", true),
            docs_enabled: get_bool("DOCS_ENABLED", true),
            metrics_enabled: get_bool("METRICS_ENABLED", true),
            log_format,
            seed_admin_email: get("SEED_ADMIN_EMAIL", "admin@arcticworks.dev"),
            seed_admin_password: get("SEED_ADMIN_PASSWORD", "ChangeMe-1234"),
            seed_reset_admin_password: get_bool("SEED_RESET_ADMIN_PASSWORD", false),
            seed_member_emails: split_list(&get("SEED_MEMBER_EMAILS", "")),
            seed_org_name: get("SEED_ORG_NAME", "ArcticWorks"),
            register_rate_limit_per_hour: std::env::var("REGISTER_RATE_LIMIT_PER_HOUR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
        };

        Ok(cfg)
    }

    /// OIDC issuer identifier (the API base URL).
    pub fn issuer(&self) -> &str {
        &self.public_base_url
    }

    pub fn allowed_origins_header_values(&self) -> Vec<axum::http::HeaderValue> {
        self.allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect()
    }

    pub fn rp_origins_set(&self) -> Arc<HashSet<String>> {
        Arc::new(self.rp_origins.iter().cloned().collect())
    }

    pub fn secure_cookie(&self) -> bool {
        self.secure_cookies
    }
}
