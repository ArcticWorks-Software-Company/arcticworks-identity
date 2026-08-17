//! Development seed data for organizations: the demo organization owned by
//! the seeded administrator.

use crate::ids::new_id;
use crate::rbac;
use crate::state::AppState;

pub async fn seed(state: &AppState) -> anyhow::Result<()> {
    let admin_email = state.config.seed_admin_email.clone();
    let org_name = state.config.seed_org_name.clone();
    let slug = org_name.to_lowercase();

    let admin_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&admin_email)
        .fetch_optional(&state.pool)
        .await?;
    let Some(admin_id) = admin_id else {
        anyhow::bail!("admin user not found — run accounts seed first");
    };

    let org_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM organizations WHERE slug = $1")
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await?;

    let org_id = match org_id {
        Some(id) => id,
        None => {
            let id = new_id();
            sqlx::query("INSERT INTO organizations (id, name, slug, owner_id) VALUES ($1, $2, $3, $4)")
                .bind(id)
                .bind(&org_name)
                .bind(&slug)
                .bind(admin_id)
                .execute(&state.pool)
                .await?;
            id
        }
    };

    // Built-in roles (idempotent).
    let mut conn = state.pool.acquire().await?;
    rbac::seed_org_roles(&mut *conn, org_id)
        .await
        .map_err(|e| anyhow::anyhow!("seed roles: {e}"))?;

    // Ensure the admin is the owner.
    let member: Option<(uuid::Uuid, Option<uuid::Uuid>)> =
        sqlx::query_as("SELECT id, role_id FROM org_memberships WHERE org_id = $1 AND user_id = $2")
            .bind(org_id)
            .bind(admin_id)
            .fetch_optional(&state.pool)
            .await?;

    let owner_role = rbac::find_org_role(&mut *conn, org_id, rbac::ROLE_OWNER)
        .await
        .map_err(|e| anyhow::anyhow!("find owner role: {e}"))?;

    match member {
        Some((_id, Some(_))) => {}
        Some((id, None)) => {
            sqlx::query("UPDATE org_memberships SET role_id = $1 WHERE id = $2")
                .bind(owner_role)
                .bind(id)
                .execute(&state.pool)
                .await?;
        }
        None => {
            sqlx::query(
                "INSERT INTO org_memberships (id, org_id, user_id, role_id) VALUES ($1, $2, $3, $4)",
            )
            .bind(new_id())
            .bind(org_id)
            .bind(admin_id)
            .bind(owner_role)
            .execute(&state.pool)
            .await?;
        }
    }

    // Extra members (SEED_MEMBER_EMAILS): created as verified users if
    // missing, joined to the org with the demo "Document Reader" role so the
    // mock Continuity permission check allows continuity.document.read.
    let member_role = rbac::find_org_role(&mut *conn, org_id, "Document Reader").await;
    let member_role = match member_role {
        Ok(Some(id)) => id,
        _ => {
            let id = new_id();
            sqlx::query(
                "INSERT INTO roles (id, org_id, name, is_system, is_owner, description) VALUES ($1, $2, 'Document Reader', false, false, 'Seeded demo role with product read permission.')",
            )
            .bind(id)
            .bind(org_id)
            .execute(&state.pool)
            .await?;
            sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ($1, 'continuity.document.read')")
                .bind(id)
                .execute(&state.pool)
                .await?;
            id
        }
    };

    for email in &state.config.seed_member_emails {
        let user_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&state.pool)
            .await?;
        let user_id = match user_id {
            Some(id) => id,
            None => {
                let id = new_id();
                let password_hash = crate::accounts::hash_password(&state.config.seed_admin_password)
                    .map_err(|e| anyhow::anyhow!("hash password: {e}"))?;
                sqlx::query(
                    "INSERT INTO users (id, email, display_name, password_hash, email_verified_at) VALUES ($1, $2, $3, $4, now())",
                )
                .bind(id)
                .bind(email)
                .bind(email.split('@').next().unwrap_or("Member"))
                .bind(&password_hash)
                .execute(&state.pool)
                .await?;
                id
            }
        };

        let already = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM org_memberships WHERE org_id = $1 AND user_id = $2)",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;
        if !already {
            sqlx::query(
                "INSERT INTO org_memberships (id, org_id, user_id, role_id) VALUES ($1, $2, $3, $4)",
            )
            .bind(new_id())
            .bind(org_id)
            .bind(user_id)
            .bind(member_role)
            .execute(&state.pool)
            .await?;
            println!("seeded member: {email} -> {org_name} ({slug})");
        } else {
            println!("seeded member: {email} (already a member)");
        }
    }

    println!("seeded organization: {org_name} ({slug}) id={org_id}");
    Ok(())
}
