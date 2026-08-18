//! Shared application state.

use std::sync::Arc;

use aes_gcm::Aes256Gcm;
use sqlx::PgPool;

use crate::config::Config;
use crate::email::Mailer;
use crate::ratelimit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: PgPool,
    pub rl: Arc<RateLimiter>,
    pub mailer: Arc<Mailer>,
    /// Key encrypting TOTP secrets and webhook signing secrets at rest.
    pub totp_key: Arc<Aes256Gcm>,
    /// HTTP client for outbound webhook delivery.
    pub webhook_client: Arc<reqwest::Client>,
}

impl AppState {
    pub async fn from_config(config: Config) -> anyhow::Result<Self> {
        let pool = PgPool::connect(&config.database_url)
            .await
            .map_err(|e| anyhow::anyhow!("database connection failed: {e}"))?;

        let rl = RateLimiter::connect(&config).await;
        let mailer = Arc::new(Mailer::new(config.smtp.clone()));
        let totp_key = Arc::new(crate::totp::cipher_from_config(&config));
        let webhook_client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| anyhow::anyhow!("webhook client init failed: {e}"))?,
        );

        Ok(AppState {
            config: Arc::new(config),
            pool,
            rl: Arc::new(rl),
            mailer,
            totp_key,
            webhook_client,
        })
    }
}
