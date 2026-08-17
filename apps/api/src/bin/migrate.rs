//! Apply database migrations.

use identity_api::{config::Config, run_migrations};
use sqlx::PgPool;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let config = Config::from_env()?;
    let pool = PgPool::connect(&config.database_url).await?;
    run_migrations(&pool).await?;
    println!("migrations applied");
    Ok(())
}
