//! Rate limiting. Valkey/Redis-backed fixed-window counters for production;
//! in-memory fallback when no Redis is configured (tests, minimal dev).
//! Used for login, registration, password reset and enrollment endpoints.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use redis::aio::ConnectionManager;

use crate::config::Config;

const SCRIPT: &str = r#"
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local count = redis.call('INCR', key)
if count == 1 then
  redis.call('EXPIRE', key, window)
end
if count > limit then
  local ttl = redis.call('TTL', key)
  return {0, ttl}
end
return {1, 0}
"#;

#[derive(Clone, Copy)]
struct MemCell {
    count: u32,
    window_start: std::time::Instant,
}

pub struct RateLimiter {
    redis: Option<ConnectionManager>,
    mem: Arc<DashMap<String, MemCell>>,
}

impl RateLimiter {
    pub async fn connect(config: &Config) -> Self {
        let redis = match &config.redis_url {
            Some(url) => match redis::Client::open(url.clone()) {
                Ok(client) => match ConnectionManager::new(client).await {
                    Ok(cm) => {
                        tracing::info!("rate limiter using redis");
                        Some(cm)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "redis unavailable; falling back to in-memory rate limiting");
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "invalid REDIS_URL; falling back to in-memory rate limiting");
                    None
                }
            },
            None => None,
        };
        RateLimiter {
            redis,
            mem: Arc::new(DashMap::new()),
        }
    }

    /// Check a fixed-window limit. Returns `Err(retry_after_secs)` when the
    /// limit is exceeded.
    pub async fn check(
        &self,
        scope: &str,
        key: &str,
        limit: u32,
        window_secs: u64,
    ) -> Result<(), u64> {
        if let Some(redis) = &self.redis {
            let mut conn = redis.clone();
            let redis_key = format!("rl:{scope}:{key}");
            let result: redis::RedisResult<(i64, i64)> = redis::cmd("EVAL")
                .arg(SCRIPT)
                .arg(1)
                .arg(&redis_key)
                .arg(limit)
                .arg(window_secs)
                .query_async(&mut conn)
                .await;
            match result {
                Ok((1, _)) => Ok(()),
                Ok((_, ttl)) => Err(ttl.max(1) as u64),
                Err(error) => {
                    tracing::warn!(%error, scope, "redis rate-limit check failed; using in-memory fallback");
                    self.check_mem(scope, key, limit, window_secs)
                }
            }
        } else {
            self.check_mem(scope, key, limit, window_secs)
        }
    }

    fn check_mem(&self, scope: &str, key: &str, limit: u32, window_secs: u64) -> Result<(), u64> {
        let map_key = format!("{scope}:{key}");
        let now = std::time::Instant::now();
        let window = Duration::from_secs(window_secs);

        let mut entry = self.mem.entry(map_key).or_insert(MemCell {
            count: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start) >= window {
            entry.window_start = now;
            entry.count = 0;
        }
        entry.count += 1;
        if entry.count > limit {
            let elapsed = now.duration_since(entry.window_start).as_secs();
            return Err((window_secs.saturating_sub(elapsed)).max(1));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_limiter_enforces_window() {
        let config = Config::from_env().unwrap();
        let rl = RateLimiter::connect(&config).await;
        assert!(rl.redis.is_none()); // no REDIS_URL in test env

        let key = "test-key";
        for _ in 0..3 {
            assert!(rl.check("test", key, 3, 60).await.is_ok());
        }
        assert!(rl.check("test", key, 3, 60).await.is_err());

        // Different scope/key are independent.
        assert!(rl.check("test", "other-key", 3, 60).await.is_ok());
    }
}
