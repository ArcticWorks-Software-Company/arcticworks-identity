//! Development seed data for accounts: the administrator user.

use crate::accounts::{hash_password, UserJson};
use crate::ids::new_id;
use crate::state::AppState;

pub async fn seed(state: &AppState) -> anyhow::Result<()> {
    let email = state.config.seed_admin_email.clone();
    let password = state.config.seed_admin_password.clone();

    let existing = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)",
    )
    .bind(&email)
    .fetch_one(&state.pool)
    .await?;

    if existing {
        // Keep the dev admin usable: refresh password and ensure verification.
        let user_id = sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM users WHERE email = $1")
            .bind(&email)
            .fetch_one(&state.pool)
            .await?;
        let password_hash = hash_password(&password).map_err(|e| anyhow::anyhow!("hash password: {e}"))?;
        sqlx::query(
            "UPDATE users SET password_hash = $1, email_verified_at = COALESCE(email_verified_at, now()) WHERE id = $2",
        )
        .bind(&password_hash)
        .bind(user_id)
        .execute(&state.pool)
        .await?;
    } else {
        let user_id = new_id();
        let password_hash = hash_password(&password).map_err(|e| anyhow::anyhow!("hash password: {e}"))?;
        sqlx::query(
            "INSERT INTO users (id, email, display_name, password_hash, email_verified_at) VALUES ($1, $2, $3, $4, now())",
        )
        .bind(user_id)
        .bind(&email)
        .bind("ArcticWorks Admin")
        .bind(&password_hash)
        .execute(&state.pool)
        .await?;
    }

    let user = sqlx::query_as::<_, crate::authn::UserRow>(
        "SELECT id, email, display_name, email_verified_at FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_one(&state.pool)
    .await?;
    let json = UserJson::from(&user);
    println!("seeded admin: {} ({})", json.email, json.id);
    Ok(())
}
