//! ArcticWorks Identity API — HTTP entry point.

use identity_api::{app, config::Config, run_migrations, state::AppState};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let config = Config::from_env()?;
    init_tracing(&config);

    let state = AppState::from_config(config).await?;

    if state.config.auto_migrate {
        run_migrations(&state.pool).await?;
        tracing::info!("database migrations applied");
    }

    let listener = tokio::net::TcpListener::bind(state.config.api_bind).await?;
    tracing::info!(bind = %state.config.api_bind, issuer = %state.config.public_base_url, "identity api listening");

    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn init_tracing(config: &Config) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info,sqlx=warn"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(true);
    match config.log_format {
        identity_api::config::LogFormat::Json => {
            builder.json().init();
        }
        identity_api::config::LogFormat::Text => {
            builder.init();
        }
    }
}
