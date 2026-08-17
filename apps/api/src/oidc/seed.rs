//! Development seed data for OIDC: the confidential test client used by the
//! mock Continuity application.

use crate::ids::new_id;
use crate::state::AppState;
use crate::tokens::{hash_token, random_secret, secret_preview};
use secrecy::ExposeSecret;

pub const TEST_CLIENT_ID: &str = "awapp_continuity_mock";

pub async fn seed(state: &AppState) -> anyhow::Result<()> {
    let org_slug = state.config.seed_org_name.to_lowercase();
    let org_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM organizations WHERE slug = $1")
        .bind(&org_slug)
        .fetch_optional(&state.pool)
        .await?;
    let Some(org_id) = org_id else {
        anyhow::bail!("seeded organization not found — run orgs seed first");
    };

    let exists = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM oidc_clients WHERE client_id = $1)")
        .bind(TEST_CLIENT_ID)
        .fetch_one(&state.pool)
        .await?;

    if exists {
        // Do not rotate on re-seed: the printed secret must stay stable for
        // the mock app and e2e tests.
        let secret_hash: String = sqlx::query_scalar("SELECT client_secret_hash FROM oidc_clients WHERE client_id = $1")
            .bind(TEST_CLIENT_ID)
            .fetch_one(&state.pool)
            .await?;
        println!("seeded oidc client: {TEST_CLIENT_ID} (already exists)");
        println!("  client secret is stored hashed; cannot be re-shown");
        let _ = secret_hash;
        return Ok(());
    }

    let secret = random_secret("awcs");
    let redirect_uris = serde_json::json!(["http://localhost:5174/callback"]);

    sqlx::query(
        r#"
        INSERT INTO oidc_clients (id, org_id, name, client_id, client_secret_hash,
                                  secret_preview, redirect_uris, is_confidential, created_by)
        VALUES ($1, $2, 'Continuity (mock)', $3, $4, $5, $6, true, NULL)
        "#,
    )
    .bind(new_id())
    .bind(org_id)
    .bind(TEST_CLIENT_ID)
    .bind(hash_token(secret.expose_secret()))
    .bind(secret_preview(secret.expose_secret()))
    .bind(redirect_uris)
    .execute(&state.pool)
    .await?;

    println!("seeded oidc client: {TEST_CLIENT_ID}");
    println!("  client_secret = {}", secret.expose_secret());
    Ok(())
}
