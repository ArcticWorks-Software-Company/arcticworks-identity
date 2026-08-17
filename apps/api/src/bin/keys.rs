//! OIDC signing key operations.
//! Usage: `cargo run --bin keys -- rotate|show`

use identity_api::config::Config;
use identity_api::oidc::keys;
use identity_api::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let config = Config::from_env()?;
    let state = AppState::from_config(config).await?;

    match std::env::args().nth(1).as_deref() {
        Some("rotate") => {
            let key = keys::rotate_key(&state.pool).await?;
            println!("rotated signing key kid={}", key.kid);
        }
        Some("show") => {
            let key = keys::ensure_active_key(&state.pool).await?;
            println!("active signing key kid={} created={}", key.kid, key.created_at);
        }
        other => {
            println!("usage: keys <rotate|show> (got {other:?})");
        }
    }
    Ok(())
}
