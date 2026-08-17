//! Seed development data: administrator account, demo organization with
//! built-in roles, a test OIDC client and a demo service account.
//! Idempotent: safe to run repeatedly.

use identity_api::config::Config;
use identity_api::{run_migrations, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let config = Config::from_env()?;
    let state = AppState::from_config(config).await?;
    run_migrations(&state.pool).await?;

    identity_api::accounts::seed::seed(&state).await?;
    identity_api::orgs::seed::seed(&state).await?;
    identity_api::oidc::seed::seed(&state).await?;
    identity_api::machine::seed::seed(&state).await?;
    println!("seed complete");
    Ok(())
}
