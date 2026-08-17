//! Shared application state.

use std::sync::Arc;

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
}

impl AppState {
    pub async fn from_config(config: Config) -> anyhow::Result<Self> {
        let pool = PgPool::connect(&config.database_url)
            .await
            .map_err(|e| anyhow::anyhow!("database connection failed: {e}"))?;

        let rl = RateLimiter::connect(&config).await;
        let mailer = Arc::new(Mailer::new(config.smtp.clone()));

        Ok(AppState {
            config: Arc::new(config),
            pool,
            rl: Arc::new(rl),
            mailer,
        })
    }
}
