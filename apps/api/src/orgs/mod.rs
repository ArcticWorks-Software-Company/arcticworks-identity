//! Organizations: orgs, memberships, invitations, teams, switching.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use utoipa::ToSchema;

use crate::audit::{self, ActorType, AuditEvent};
use crate::authn::Authed;
use crate::correlation::HttpMeta;
use crate::error::{ApiError, ApiResult, MapInternal};
use crate::ids::new_id;
use crate::rbac;
use crate::state::AppState;
use crate::tokens::{hash_token, random_token};
use crate::util;

pub mod seed;

const RL_ORG_CREATE: (u32, u64) = (5, 3600); // 5 per hour per IP
const RL_INVITE: (u32, u64) = (10, 3600); // 10 per hour per IP

// ------------------------------------------------------------------- models

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct OrgJson {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub owner_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MembershipJson {
    pub org_id: Uuid,
    pub org_name: String,
    pub org_slug: String,
    pub role_id: Option<Uuid>,
    pub role_name: String,
    pub is_owner: bool,
    pub status: String,
    pub is_current: bool,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
struct MembershipRow {
    org_id: Uuid,
    org_name: String,
    org_slug: String,
    role_id: Option<Uuid>,
    role_name: Option<String>,
    is_owner: bool,
    status: String,
    joined_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_memberships(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    current_org_id: Option<Uuid>,
) -> ApiResult<Vec<MembershipJson>> {
    let rows = sqlx::query_as::<_, MembershipRow>(
        r#"
        SELECT o.id AS org_id, o.name AS org_name, o.slug AS org_slug,
               m.role_id, r.name AS role_name, COALESCE(r.is_owner, false) AS is_owner,
               m.status, m.joined_at
        FROM org_memberships m
        JOIN organizations o ON o.id = m.org_id
        LEFT JOIN roles r ON r.id = m.role_id
        WHERE m.user_id = $1
        ORDER BY m.joined_at
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_internal("list memberships")?;

    Ok(rows
        .into_iter()
        .map(|r| MembershipJson {
            org_id: r.org_id,
            org_name: r.org_name,
            org_slug: r.org_slug,
            role_id: r.role_id,
            role_name: r.role_name.unwrap_or_default(),
            is_owner: r.is_owner,
            status: r.status,
            is_current: current_org_id == Some(r.org_id),
            joined_at: r.joined_at,
        })
        .collect())
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MemberJson {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role_id: Option<Uuid>,
    pub role_name: String,
    pub is_owner: bool,
    pub status: String,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InvitationJson {
    pub id: Uuid,
    pub email: String,
    pub role_id: Option<Uuid>,
    pub role_name: String,
    pub status: String,
    pub invited_by: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamJson {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ------------------------------------------------------------------ requests

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrgReq {
    pub name: String,
    pub slug: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOrgReq {
    pub name: String,
    pub slug: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TransferReq {
    pub new_owner_user_id: Uuid,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateInvitationReq {
    pub email: String,
    pub role_id: Uuid,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetRoleReq {
    pub role_id: Uuid,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateTeamReq {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTeamReq {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddTeamMemberReq {
    pub user_id: Uuid,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// -------------------------------------------------------------------- routes

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/orgs", get(list_orgs).post(create_org))
        .route("/api/orgs/{org_id}", get(get_org).patch(update_org))
        .route("/api/orgs/{org_id}/switch", post(switch_org))
        .route("/api/orgs/{org_id}/transfer", post(transfer_ownership))
        .route("/api/orgs/{org_id}/members", get(list_members))
        .route(
            "/api/orgs/{org_id}/members/{user_id}",
            delete(remove_member),
        )
        .route("/api/orgs/{org_id}/members/{user_id}/role", post(set_member_role))
        .route(
            "/api/orgs/{org_id}/members/{user_id}/suspend",
            post(suspend_member),
        )
        .route(
            "/api/orgs/{org_id}/members/{user_id}/unsuspend",
            post(unsuspend_member),
        )
        .route("/api/orgs/{org_id}/invitations", get(list_invitations).post(create_invitation))
        .route(
            "/api/orgs/{org_id}/invitations/{invite_id}/revoke",
            post(revoke_invitation),
        )
        .route("/api/invitations/{token}/accept", post(accept_invitation))
        .route("/api/orgs/{org_id}/teams", get(list_teams).post(create_team))
        .route(
            "/api/orgs/{org_id}/teams/{team_id}",
            patch(update_team).delete(delete_team),
        )
        .route(
            "/api/orgs/{org_id}/teams/{team_id}/members",
            get(list_team_members).post(add_team_member),
        )
        .route(
            "/api/orgs/{org_id}/teams/{team_id}/members/{user_id}",
            delete(remove_team_member),
        )
        .route("/api/orgs/{org_id}/audit-log", get(audit_log))
}

// ---------------------------------------------------------------- handlers

/// Create an organization. The creator becomes the Owner.
#[utoipa::path(
    post,
    path = "/api/orgs",
    request_body = CreateOrgReq,
    responses(
        (status = 201, description = "Organization created"),
        (status = 409, description = "Slug already taken"),
        (status = 429, description = "Rate limited")
    ),
    security(("sessionCookie" = []))
)]
pub async fn create_org(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Json(req): Json<CreateOrgReq>,
) -> ApiResult<Response> {
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("org-create", &ip_key, RL_ORG_CREATE.0, RL_ORG_CREATE.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }

    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::Validation("organization name must be between 1 and 100 characters".into()));
    }
    let slug = req.slug.trim().to_lowercase();
    if !util::is_valid_slug(&slug) {
        return Err(ApiError::Validation(
            "slug must be 3-63 lowercase letters, digits and hyphens".into(),
        ));
    }

    let org_id = new_id();
    let mut tx = state.pool.begin().await.map_internal("begin org tx")?;

    let inserted = sqlx::query(
        "INSERT INTO organizations (id, name, slug, owner_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(org_id)
    .bind(name)
    .bind(&slug)
    .bind(authed.0.user.id)
    .execute(&mut *tx)
    .await;
    if let Err(e) = inserted {
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            return Err(ApiError::Conflict("an organization with this slug already exists".into()));
        }
        return Err(ApiError::internal("create organization", e));
    }

    rbac::seed_org_roles(&mut *tx, org_id).await?;
    let owner_role = rbac::find_org_role(&mut *tx, org_id, rbac::ROLE_OWNER)
        .await?
        .ok_or_else(|| ApiError::internal("missing owner role", "owner role not seeded"))?;

    sqlx::query(
        "INSERT INTO org_memberships (id, org_id, user_id, role_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(new_id())
    .bind(org_id)
    .bind(authed.0.user.id)
    .bind(owner_role)
    .execute(&mut *tx)
    .await
    .map_internal("insert owner membership")?;

    sqlx::query("UPDATE sessions SET current_org_id = $1 WHERE id = $2")
        .bind(org_id)
        .bind(authed.0.session.id)
        .execute(&mut *tx)
        .await
        .map_internal("set current org")?;

    tx.commit().await.map_internal("commit org tx")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "org.created",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("organization"),
            target_id: Some(org_id),
            metadata: serde_json::json!({ "slug": slug }),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "organization": { "id": org_id, "name": name, "slug": slug, "ownerId": authed.0.user.id }
        })),
    )
        .into_response())
}

async fn list_orgs(
    State(state): State<AppState>,
    authed: Authed,
) -> ApiResult<Response> {
    let memberships = list_memberships(&state.pool, authed.0.user.id, authed.0.session.current_org_id).await?;
    Ok(Json(serde_json::json!({ "memberships": memberships })).into_response())
}

/// Organization details for the current principal (requires membership).
#[utoipa::path(
    get,
    path = "/api/orgs/{org_id}",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    responses(
        (status = 200, description = "Organization and principal context"),
        (status = 403, description = "Not a member")
    ),
    security(("sessionCookie" = []))
)]
pub async fn get_org(
    State(state): State<AppState>,
    authed: Authed,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Response> {
    let principal = rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::OVERVIEW_READ).await?;
    let org = sqlx::query_as::<_, OrgJson>(
        "SELECT id, name, slug, owner_id, created_at FROM organizations WHERE id = $1",
    )
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("load organization")?;
    Ok(Json(serde_json::json!({ "organization": org, "principal": principal })).into_response())
}

/// Update organization name/slug (requires `org.settings.manage`).
#[utoipa::path(
    patch,
    path = "/api/orgs/{org_id}",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    request_body = UpdateOrgReq,
    responses(
        (status = 200, description = "Organization updated"),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn update_org(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(org_id): Path<Uuid>,
    Json(req): Json<UpdateOrgReq>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::SETTINGS_MANAGE).await?;

    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::Validation("organization name must be between 1 and 100 characters".into()));
    }
    let slug = req.slug.trim().to_lowercase();
    if !util::is_valid_slug(&slug) {
        return Err(ApiError::Validation("invalid slug".into()));
    }

    let res = sqlx::query(
        "UPDATE organizations SET name = $1, slug = $2, updated_at = now() WHERE id = $3",
    )
    .bind(name)
    .bind(&slug)
    .bind(org_id)
    .execute(&state.pool)
    .await;
    if let Err(e) = res {
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            return Err(ApiError::Conflict("an organization with this slug already exists".into()));
        }
        return Err(ApiError::internal("update organization", e));
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "org.updated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("organization"),
            target_id: Some(org_id),
            metadata: serde_json::json!({ "name": name, "slug": slug }),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

async fn switch_org(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Response> {
    let principal = rbac::load_principal(&state.pool, authed.0.user.id, org_id).await?;
    let Some(principal) = principal else {
        return Err(ApiError::Forbidden);
    };
    if !principal.is_active() {
        return Err(ApiError::Forbidden);
    }

    sqlx::query("UPDATE sessions SET current_org_id = $1 WHERE id = $2")
        .bind(org_id)
        .bind(authed.0.session.id)
        .execute(&state.pool)
        .await
        .map_internal("switch org")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "org.switched",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: None,
            target_id: None,
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "currentOrgId": org_id })).into_response())
}

/// Transfer organization ownership (Owner only, reauthentication required).
/// The new owner must be an active member; the previous owner becomes an
/// Administrator.
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/transfer",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    request_body = TransferReq,
    responses(
        (status = 200, description = "Ownership transferred"),
        (status = 403, description = "Not the owner or reauthentication required")
    ),
    security(("sessionCookie" = []))
)]
pub async fn transfer_ownership(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(org_id): Path<Uuid>,
    Json(req): Json<TransferReq>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    let principal = rbac::load_principal(&state.pool, authed.0.user.id, org_id).await?;
    let Some(principal) = principal else {
        return Err(ApiError::Forbidden);
    };
    if !principal.is_owner {
        return Err(ApiError::Forbidden);
    }
    if req.new_owner_user_id == authed.0.user.id {
        return Err(ApiError::Validation("you already own this organization".into()));
    }

    // The new owner must be an active member.
    if !rbac::is_active_member(&state.pool, req.new_owner_user_id, org_id).await? {
        return Err(ApiError::Validation("the new owner must be an active member".into()));
    }

    let owner_role = rbac::find_org_role(&mut *state.pool.acquire().await.map_internal("acquire conn")?, org_id, rbac::ROLE_OWNER)
        .await?
        .ok_or_else(|| ApiError::internal("missing owner role", "owner role not seeded"))?;
    let admin_role = rbac::find_org_role(&mut *state.pool.acquire().await.map_internal("acquire conn")?, org_id, rbac::ROLE_ADMIN)
        .await?
        .ok_or_else(|| ApiError::internal("missing admin role", "admin role not seeded"))?;

    let mut tx = state.pool.begin().await.map_internal("begin transfer tx")?;
    sqlx::query(
        "UPDATE org_memberships SET role_id = $1 WHERE org_id = $2 AND user_id = $3",
    )
    .bind(admin_role)
    .bind(org_id)
    .bind(authed.0.user.id)
    .execute(&mut *tx)
    .await
    .map_internal("demote old owner")?;
    sqlx::query(
        "UPDATE org_memberships SET role_id = $1 WHERE org_id = $2 AND user_id = $3",
    )
    .bind(owner_role)
    .bind(org_id)
    .bind(req.new_owner_user_id)
    .execute(&mut *tx)
    .await
    .map_internal("promote new owner")?;
    sqlx::query("UPDATE organizations SET owner_id = $1, updated_at = now() WHERE id = $2")
        .bind(req.new_owner_user_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await
        .map_internal("update organization owner")?;
    tx.commit().await.map_internal("commit transfer")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "org.ownership_transferred",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("user"),
            target_id: Some(req.new_owner_user_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

/// List organization members (requires `org.members.read`).
#[utoipa::path(
    get,
    path = "/api/orgs/{org_id}/members",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    responses(
        (status = 200, description = "List of members", body = inline(crate::openapi::MembersResponse)),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn list_members(
    State(state): State<AppState>,
    authed: Authed,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::MEMBERS_READ).await?;
    let members = sqlx::query_as::<_, MemberRow>(
        r#"
        SELECT m.user_id, u.email, u.display_name, m.role_id, r.name AS role_name,
               COALESCE(r.is_owner, false) AS is_owner, m.status, m.joined_at
        FROM org_memberships m
        JOIN users u ON u.id = m.user_id
        LEFT JOIN roles r ON r.id = m.role_id
        WHERE m.org_id = $1
        ORDER BY m.joined_at
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list members")?;

    Ok(Json(serde_json::json!({ "members": members })).into_response())
}

#[derive(sqlx::FromRow, Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberRow {
    user_id: Uuid,
    email: String,
    display_name: String,
    role_id: Option<Uuid>,
    role_name: Option<String>,
    is_owner: bool,
    status: String,
    joined_at: chrono::DateTime<chrono::Utc>,
}

/// A member target that is not the canonical owner and not the caller.
async fn validate_member_target(
    state: &AppState,
    principal: &rbac::OrgPrincipal,
    target_user_id: Uuid,
) -> ApiResult<()> {
    if target_user_id == principal.user_id {
        return Err(ApiError::Validation("cannot modify your own membership this way".into()));
    }
    let is_owner = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1 AND owner_id = $2)",
    )
    .bind(principal.org_id)
    .bind(target_user_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("check target is owner")?;
    if is_owner {
        return Err(ApiError::Validation(
            "the owner can only be changed via ownership transfer".into(),
        ));
    }
    Ok(())
}

/// Change a member's role (requires `org.members.manage`). The Owner role
/// can only be assigned via ownership transfer.
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/members/{user_id}/role",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("user_id" = Uuid, Path, description = "Member user id")
    ),
    request_body = SetRoleReq,
    responses(
        (status = 200, description = "Role changed"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Member not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn set_member_role(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<SetRoleReq>,
) -> ApiResult<Response> {
    let principal = rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::MEMBERS_MANAGE).await?;
    authed.0.require_reauth(&state.config)?;
    validate_member_target(&state, &principal, user_id).await?;

    // Role must belong to this organization.
    let role_org: Option<Uuid> = sqlx::query_scalar("SELECT org_id FROM roles WHERE id = $1")
        .bind(req.role_id)
        .fetch_optional(&state.pool)
        .await
        .map_internal("lookup role")?;
    let Some(role_org) = role_org else {
        return Err(ApiError::Validation("role not found".into()));
    };
    if role_org != org_id {
        return Err(ApiError::Validation("role does not belong to this organization".into()));
    }
    // Owner role can only be assigned via ownership transfer.
    let is_owner_role: bool = sqlx::query_scalar("SELECT is_owner FROM roles WHERE id = $1")
        .bind(req.role_id)
        .fetch_one(&state.pool)
        .await
        .map_internal("check role kind")?;
    if is_owner_role {
        return Err(ApiError::Validation("use ownership transfer to assign the Owner role".into()));
    }

    let res = sqlx::query(
        "UPDATE org_memberships SET role_id = $1 WHERE org_id = $2 AND user_id = $3 AND status = 'active'",
    )
    .bind(req.role_id)
    .bind(org_id)
    .bind(user_id)
    .execute(&state.pool)
    .await
    .map_internal("set member role")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "member.role_changed",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("user"),
            target_id: Some(user_id),
            metadata: serde_json::json!({ "roleId": req.role_id }),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

/// Suspend a member (requires `org.members.suspend`).
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/members/{user_id}/suspend",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("user_id" = Uuid, Path, description = "Member user id")
    ),
    responses(
        (status = 200, description = "Member suspended"),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn suspend_member(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    let principal = rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::MEMBERS_SUSPEND).await?;
    authed.0.require_reauth(&state.config)?;
    validate_member_target(&state, &principal, user_id).await?;
    update_member_status(&state, &meta, authed.0.user.id, org_id, user_id, "suspended").await
}

/// Restore a suspended member (requires `org.members.suspend`).
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/members/{user_id}/unsuspend",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("user_id" = Uuid, Path, description = "Member user id")
    ),
    responses(
        (status = 200, description = "Member restored"),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn unsuspend_member(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    let principal = rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::MEMBERS_SUSPEND).await?;
    authed.0.require_reauth(&state.config)?;
    validate_member_target(&state, &principal, user_id).await?;
    update_member_status(&state, &meta, authed.0.user.id, org_id, user_id, "active").await
}

async fn update_member_status(
    state: &AppState,
    meta: &HttpMeta,
    actor_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
    status: &str,
) -> ApiResult<Response> {
    let res = sqlx::query(
        "UPDATE org_memberships SET status = $1 WHERE org_id = $2 AND user_id = $3 AND status <> $1",
    )
    .bind(status)
    .bind(org_id)
    .bind(user_id)
    .execute(&state.pool)
    .await
    .map_internal("update member status")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    if status == "suspended" {
        crate::oidc::token::revoke_user_tokens(state, user_id, Some(org_id)).await?;
    }

    audit::record(
        &state.pool,
        meta,
        AuditEvent {
            event_type: if status == "suspended" { "member.suspended" } else { "member.unsuspended" },
            actor_type: ActorType::User,
            actor_id: Some(actor_id),
            org_id: Some(org_id),
            target_type: Some("user"),
            target_id: Some(user_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

/// Remove a member (requires `org.members.remove`; users may also leave
/// themselves). The owner can only be removed via ownership transfer.
#[utoipa::path(
    delete,
    path = "/api/orgs/{org_id}/members/{user_id}",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("user_id" = Uuid, Path, description = "Member user id")
    ),
    responses(
        (status = 204, description = "Member removed"),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn remove_member(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    let principal = rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::MEMBERS_REMOVE).await?;

    // Anyone may leave an organization themselves; admins may remove others
    // (never the owner, and only after reauthentication).
    if user_id != principal.user_id {
        authed.0.require_reauth(&state.config)?;
        validate_member_target(&state, &principal, user_id).await?;
    }

    let is_owner = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1 AND owner_id = $2)",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("check target is owner")?;
    if is_owner {
        return Err(ApiError::Validation("the owner cannot be removed; transfer ownership first".into()));
    }

    let res = sqlx::query("DELETE FROM org_memberships WHERE org_id = $1 AND user_id = $2")
        .bind(org_id)
        .bind(user_id)
        .execute(&state.pool)
        .await
        .map_internal("remove member")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    crate::oidc::token::revoke_user_tokens(&state, user_id, Some(org_id)).await?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "member.removed",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("user"),
            target_id: Some(user_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Invite a member by email (requires `org.members.invite`). The invitation
/// email links to the acceptance flow; the invitee's account email must
/// match the invited address.
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/invitations",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    request_body = CreateInvitationReq,
    responses(
        (status = 201, description = "Invitation created"),
        (status = 403, description = "Insufficient permissions"),
        (status = 409, description = "Already a member")
    ),
    security(("sessionCookie" = []))
)]
pub async fn create_invitation(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(org_id): Path<Uuid>,
    Json(req): Json<CreateInvitationReq>,
) -> ApiResult<Response> {
    let ip_key = meta.ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    if let Err(retry) = state.rl.check("invite", &ip_key, RL_INVITE.0, RL_INVITE.1).await {
        return Err(ApiError::RateLimited { retry_after_secs: retry });
    }
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::MEMBERS_INVITE).await?;

    let email = req.email.trim().to_lowercase();
    if !util::is_valid_email(&email) {
        return Err(ApiError::Validation("invalid email address".into()));
    }

    // Role must belong to this organization and must not be the Owner role.
    let role_ok = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1 AND org_id = $2 AND NOT is_owner)",
    )
    .bind(req.role_id)
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("validate invite role")?;
    if !role_ok {
        return Err(ApiError::Validation("role does not belong to this organization".into()));
    }

    // An active membership blocks re-invitation.
    let already_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM org_memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = $1 AND u.email = $2)",
    )
    .bind(org_id)
    .bind(&email)
    .fetch_one(&state.pool)
    .await
    .map_internal("check existing membership")?;
    if already_member {
        return Err(ApiError::Conflict("this user is already a member".into()));
    }

    let token = random_token();
    let invite_id = new_id();
    sqlx::query(
        r#"
        INSERT INTO invitations (id, org_id, email, role_id, token_hash, invited_by, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(invite_id)
    .bind(org_id)
    .bind(&email)
    .bind(req.role_id)
    .bind(hash_token(&token))
    .bind(authed.0.user.id)
    .bind(chrono::Utc::now() + chrono::Duration::from_std(state.config.invite_ttl).unwrap_or_default())
    .execute(&state.pool)
    .await
    .map_internal("create invitation")?;

    let link = format!("{}/invite/{token}", state.config.web_origin);
    let _ = state
        .mailer
        .send(&email, "You're invited to join an ArcticWorks organization", invitation_email_html(&link))
        .await;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "invite.created",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("invitation"),
            target_id: Some(invite_id),
            metadata: serde_json::json!({ "email": email, "roleId": req.role_id }),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "invitationId": invite_id })),
    )
        .into_response())
}

/// List invitations (requires `org.members.read`).
#[utoipa::path(
    get,
    path = "/api/orgs/{org_id}/invitations",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    responses(
        (status = 200, description = "List of invitations", body = inline(crate::openapi::InvitationsResponse)),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn list_invitations(
    State(state): State<AppState>,
    authed: Authed,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::MEMBERS_READ).await?;
    let invitations = sqlx::query_as::<_, InvitationRow>(
        r#"
        SELECT i.id, i.email, i.role_id, r.name AS role_name,
               i.invited_by, i.created_at, i.expires_at,
               i.accepted_at, i.revoked_at
        FROM invitations i
        LEFT JOIN roles r ON r.id = i.role_id
        WHERE i.org_id = $1
        ORDER BY i.created_at DESC
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list invitations")?;

    let now = chrono::Utc::now();
    let items: Vec<InvitationJson> = invitations
        .into_iter()
        .map(|i| {
            let status = if i.accepted_at.is_some() {
                "accepted".to_string()
            } else if i.revoked_at.is_some() {
                "revoked".to_string()
            } else if i.expires_at < now {
                "expired".to_string()
            } else {
                "pending".to_string()
            };
            InvitationJson {
                id: i.id,
                email: i.email,
                role_id: i.role_id,
                role_name: i.role_name.unwrap_or_default(),
                status,
                invited_by: i.invited_by,
                created_at: i.created_at,
                expires_at: i.expires_at,
            }
        })
        .collect();

    Ok(Json(serde_json::json!({ "invitations": items })).into_response())
}

#[derive(sqlx::FromRow)]
struct InvitationRow {
    id: Uuid,
    email: String,
    role_id: Option<Uuid>,
    role_name: Option<String>,
    invited_by: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    accepted_at: Option<chrono::DateTime<chrono::Utc>>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Revoke a pending invitation (requires `org.members.manage`).
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/invitations/{invite_id}/revoke",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("invite_id" = Uuid, Path, description = "Invitation id")
    ),
    responses(
        (status = 204, description = "Invitation revoked"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Invitation not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn revoke_invitation(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, invite_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::MEMBERS_MANAGE).await?;
    let res = sqlx::query(
        "UPDATE invitations SET revoked_at = now() WHERE id = $1 AND org_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL",
    )
    .bind(invite_id)
    .bind(org_id)
    .execute(&state.pool)
    .await
    .map_internal("revoke invitation")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "invite.revoked",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("invitation"),
            target_id: Some(invite_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Accept an invitation (authenticated; the account email must match the
/// invited address). The new organization becomes the active one.
#[utoipa::path(
    post,
    path = "/api/invitations/{token}/accept",
    params(("token" = String, Path, description = "Invitation token from the email link")),
    responses(
        (status = 200, description = "Joined the organization"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Invitation is for a different email"),
        (status = 410, description = "Invitation expired or revoked")
    ),
    security(("sessionCookie" = []))
)]
pub async fn accept_invitation(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(token): Path<String>,
) -> ApiResult<Response> {
    let invite = sqlx::query_as::<_, AcceptInviteRow>(
        r#"
        SELECT i.id, i.org_id, i.email, i.role_id, i.expires_at, i.accepted_at, i.revoked_at,
               o.name AS org_name, o.slug AS org_slug
        FROM invitations i
        JOIN organizations o ON o.id = i.org_id
        WHERE i.token_hash = $1
        "#,
    )
    .bind(hash_token(&token))
    .fetch_optional(&state.pool)
    .await
    .map_internal("lookup invitation")?;

    let Some(invite) = invite else {
        return Err(ApiError::TokenInvalid);
    };
    if invite.accepted_at.is_some() || invite.revoked_at.is_some() {
        return Err(ApiError::Gone("this invitation is no longer valid".into()));
    }
    if invite.expires_at < chrono::Utc::now() {
        return Err(ApiError::Gone("this invitation has expired".into()));
    }
    if invite.email.to_lowercase() != authed.0.user.email.to_lowercase() {
        return Err(ApiError::Forbidden);
    }

    // Role may have been deleted since the invite; fall back to Member.
    let role_ok = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1 AND org_id = $2 AND NOT is_owner)",
    )
    .bind(invite.role_id)
    .bind(invite.org_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("validate invite role")?;

    let role_id = if role_ok && invite.role_id.is_some() {
        invite.role_id
    } else {
        rbac::find_org_role(
            &mut *state.pool.acquire().await.map_internal("acquire conn")?,
            invite.org_id,
            rbac::ROLE_MEMBER,
        )
        .await?
    };

    let mut tx = state.pool.begin().await.map_internal("begin accept tx")?;

    let already = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM org_memberships WHERE org_id = $1 AND user_id = $2)",
    )
    .bind(invite.org_id)
    .bind(authed.0.user.id)
    .fetch_one(&mut *tx)
    .await
    .map_internal("check membership")?;
    if already {
        return Err(ApiError::Conflict("you are already a member of this organization".into()));
    }

    sqlx::query(
        "INSERT INTO org_memberships (id, org_id, user_id, role_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(new_id())
    .bind(invite.org_id)
    .bind(authed.0.user.id)
    .bind(role_id)
    .execute(&mut *tx)
    .await
    .map_internal("insert membership")?;

    sqlx::query(
        "UPDATE invitations SET accepted_at = now() WHERE id = $1",
    )
    .bind(invite.id)
    .execute(&mut *tx)
    .await
    .map_internal("mark invitation accepted")?;

    sqlx::query("UPDATE sessions SET current_org_id = $1 WHERE id = $2")
        .bind(invite.org_id)
        .bind(authed.0.session.id)
        .execute(&mut *tx)
        .await
        .map_internal("set current org")?;

    tx.commit().await.map_internal("commit accept")?;

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "invite.accepted",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(invite.org_id),
            target_type: Some("invitation"),
            target_id: Some(invite.id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "organization": { "id": invite.org_id, "name": invite.org_name, "slug": invite.org_slug } }))
        .into_response())
}

#[derive(sqlx::FromRow)]
struct AcceptInviteRow {
    id: Uuid,
    org_id: Uuid,
    email: String,
    role_id: Option<Uuid>,
    expires_at: chrono::DateTime<chrono::Utc>,
    accepted_at: Option<chrono::DateTime<chrono::Utc>>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    org_name: String,
    org_slug: String,
}

/// List teams (requires `org.teams.read`).
#[utoipa::path(
    get,
    path = "/api/orgs/{org_id}/teams",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    responses(
        (status = 200, description = "List of teams"),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn list_teams(
    State(state): State<AppState>,
    authed: Authed,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::TEAMS_READ).await?;
    let teams = sqlx::query_as::<_, TeamJson>(
        "SELECT id, org_id, name, description, created_at FROM teams WHERE org_id = $1 ORDER BY name",
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list teams")?;
    Ok(Json(serde_json::json!({ "teams": teams })).into_response())
}

/// Create a team or department (requires `org.teams.manage`).
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/teams",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    request_body = CreateTeamReq,
    responses(
        (status = 201, description = "Team created"),
        (status = 403, description = "Insufficient permissions"),
        (status = 409, description = "Team name already exists")
    ),
    security(("sessionCookie" = []))
)]
pub async fn create_team(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(org_id): Path<Uuid>,
    Json(req): Json<CreateTeamReq>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::TEAMS_MANAGE).await?;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::Validation("team name must be between 1 and 100 characters".into()));
    }
    let description = req.description.trim().chars().take(500).collect::<String>();

    let team_id = new_id();
    let res = sqlx::query(
        "INSERT INTO teams (id, org_id, name, description) VALUES ($1, $2, $3, $4)",
    )
    .bind(team_id)
    .bind(org_id)
    .bind(name)
    .bind(&description)
    .execute(&state.pool)
    .await;
    if let Err(e) = res {
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            return Err(ApiError::Conflict("a team with this name already exists".into()));
        }
        return Err(ApiError::internal("create team", e));
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "team.created",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("team"),
            target_id: Some(team_id),
            metadata: serde_json::json!({ "name": name }),
        },
    )
    .await;

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "teamId": team_id }))).into_response())
}

/// Update a team (requires `org.teams.manage`).
#[utoipa::path(
    patch,
    path = "/api/orgs/{org_id}/teams/{team_id}",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("team_id" = Uuid, Path, description = "Team id")
    ),
    request_body = UpdateTeamReq,
    responses(
        (status = 200, description = "Team updated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Team not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn update_team(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, team_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateTeamReq>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::TEAMS_MANAGE).await?;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::Validation("team name must be between 1 and 100 characters".into()));
    }
    let description = req.description.trim().chars().take(500).collect::<String>();

    let res = sqlx::query(
        "UPDATE teams SET name = $1, description = $2 WHERE id = $3 AND org_id = $4",
    )
    .bind(name)
    .bind(&description)
    .bind(team_id)
    .bind(org_id)
    .execute(&state.pool)
    .await
    .map_internal("update team")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "team.updated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("team"),
            target_id: Some(team_id),
            metadata: serde_json::json!({ "name": name }),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

/// Delete a team (requires `org.teams.manage`).
#[utoipa::path(
    delete,
    path = "/api/orgs/{org_id}/teams/{team_id}",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("team_id" = Uuid, Path, description = "Team id")
    ),
    responses(
        (status = 204, description = "Team deleted"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Team not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn delete_team(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, team_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::TEAMS_MANAGE).await?;
    let res = sqlx::query("DELETE FROM teams WHERE id = $1 AND org_id = $2")
        .bind(team_id)
        .bind(org_id)
        .execute(&state.pool)
        .await
        .map_internal("delete team")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "team.deleted",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("team"),
            target_id: Some(team_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn list_team_members(
    State(state): State<AppState>,
    authed: Authed,
    Path((org_id, team_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::TEAMS_READ).await?;
    let members = sqlx::query_as::<_, TeamMemberRow>(
        r#"
        SELECT tm.user_id, u.email, u.display_name, tm.added_at
        FROM team_members tm
        JOIN users u ON u.id = tm.user_id
        WHERE tm.team_id = $1 AND tm.org_id = $2
        ORDER BY tm.added_at
        "#,
    )
    .bind(team_id)
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list team members")?;
    Ok(Json(serde_json::json!({ "members": members })).into_response())
}

#[derive(sqlx::FromRow, Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamMemberRow {
    user_id: Uuid,
    email: String,
    display_name: String,
    added_at: chrono::DateTime<chrono::Utc>,
}

async fn add_team_member(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, team_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<AddTeamMemberReq>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::TEAMS_MANAGE).await?;

    // Target must be an org member, and the team must belong to this org.
    if !rbac::is_active_member(&state.pool, req.user_id, org_id).await? {
        return Err(ApiError::Validation("user is not an active member of this organization".into()));
    }
    let team_ok = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM teams WHERE id = $1 AND org_id = $2)",
    )
    .bind(team_id)
    .bind(org_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("check team")?;
    if !team_ok {
        return Err(ApiError::Validation("team does not belong to this organization".into()));
    }

    let res = sqlx::query(
        "INSERT INTO team_members (id, team_id, org_id, user_id) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(new_id())
    .bind(team_id)
    .bind(org_id)
    .bind(req.user_id)
    .execute(&state.pool)
    .await
    .map_internal("add team member")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::Conflict("user is already in this team".into()));
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "team.member_added",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("team"),
            target_id: Some(team_id),
            metadata: serde_json::json!({ "userId": req.user_id }),
        },
    )
    .await;

    Ok(StatusCode::CREATED.into_response())
}

async fn remove_team_member(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, team_id, user_id)): Path<(Uuid, Uuid, Uuid)>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::TEAMS_MANAGE).await?;
    let res = sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND org_id = $2 AND user_id = $3")
        .bind(team_id)
        .bind(org_id)
        .bind(user_id)
        .execute(&state.pool)
        .await
        .map_internal("remove team member")?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &state.pool,
        &meta,
        AuditEvent {
            event_type: "team.member_removed",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("team"),
            target_id: Some(team_id),
            metadata: serde_json::json!({ "userId": user_id }),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Organization audit log (requires `org.audit.read`). Append-only records
/// of security-relevant events.
#[utoipa::path(
    get,
    path = "/api/orgs/{org_id}/audit-log",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("limit" = Option<i64>, Query, description = "Page size (max 500)"),
        ("offset" = Option<i64>, Query, description = "Page offset")
    ),
    responses(
        (status = 200, description = "Audit events, newest first"),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn audit_log(
    State(state): State<AppState>,
    authed: Authed,
    Path(org_id): Path<Uuid>,
    Query(query): Query<AuditLogQuery>,
) -> ApiResult<Response> {
    rbac::authorize(&state.pool, authed.0.user.id, org_id, rbac::perms::AUDIT_READ).await?;

    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0).max(0);

    let events = sqlx::query_as::<_, AuditEventRow>(
        r#"
        SELECT id, event_type, actor_type, actor_id, org_id, target_type, target_id,
               ip::text AS ip, user_agent, metadata, occurred_at, correlation_id
        FROM audit_events
        WHERE org_id = $1
        ORDER BY occurred_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(org_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await
    .map_internal("load audit events")?;

    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&state.pool)
        .await
        .map_internal("count audit events")?;

    Ok(Json(serde_json::json!({ "events": events, "total": total, "limit": limit, "offset": offset }))
        .into_response())
}

#[derive(sqlx::FromRow, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEventRow {
    id: Uuid,
    event_type: String,
    actor_type: String,
    actor_id: Option<Uuid>,
    org_id: Option<Uuid>,
    target_type: Option<String>,
    target_id: Option<Uuid>,
    ip: Option<String>,
    user_agent: Option<String>,
    metadata: serde_json::Value,
    occurred_at: chrono::DateTime<chrono::Utc>,
    correlation_id: Uuid,
}

fn invitation_email_html(link: &str) -> String {
    format!(
        "<p>You have been invited to join an organization on ArcticWorks.</p>\
         <p><a href=\"{link}\">Accept invitation</a></p>\
         <p>If the link does not work, copy this URL into your browser:</p>\
         <p>{link}</p>\
         <p>This invitation expires in 7 days.</p>"
    )
}
