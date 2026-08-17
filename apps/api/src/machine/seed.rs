//! Development seed data for machine identities: a demo service account.

use crate::ids::new_id;
use crate::machine;
use crate::rbac;
use crate::state::AppState;
use crate::tokens::{hash_token, random_secret, secret_preview};
use secrecy::ExposeSecret;

pub async fn seed(state: &AppState) -> anyhow::Result<()> {
    let org_slug = state.config.seed_org_name.to_lowercase();
    let org_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM organizations WHERE slug = $1")
        .bind(&org_slug)
        .fetch_optional(&state.pool)
        .await?;
    let Some(org_id) = org_id else {
        anyhow::bail!("seeded organization not found — run orgs seed first");
    };

    let existing = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM service_accounts WHERE org_id = $1 AND name = 'continuity-backend')",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await?;
    if existing {
        println!("seeded service account: continuity-backend (already exists)");
        return Ok(());
    }

    let mut conn = state.pool.acquire().await?;
    let member_role = rbac::find_org_role(&mut *conn, org_id, rbac::ROLE_MEMBER)
        .await
        .map_err(|e| anyhow::anyhow!("find member role: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("member role not seeded"))?;

    let sa_id = new_id();
    let secret = random_secret("awsec");
    let client_id = format!("awsa_{}", new_id().simple());
    let expires_at = chrono::Utc::now() + chrono::Duration::days(machine::SA_CRED_TTL_DAYS);

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO service_accounts (id, org_id, name, description, role_id, created_by) VALUES ($1, $2, 'continuity-backend', 'Seeded demo service account for the mock Continuity app.', $3, NULL)",
    )
    .bind(sa_id)
    .bind(org_id)
    .bind(member_role)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO service_account_credentials
            (id, service_account_id, client_id, secret_hash, preview, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(new_id())
    .bind(sa_id)
    .bind(&client_id)
    .bind(hash_token(secret.expose_secret()))
    .bind(secret_preview(secret.expose_secret()))
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    println!("seeded service account: continuity-backend");
    println!("  client_id = {client_id}");
    println!("  client_secret = {}", secret.expose_secret());
    println!("  expires_at = {expires_at}");
    Ok(())
}
