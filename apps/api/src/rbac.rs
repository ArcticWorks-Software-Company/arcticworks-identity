//! Roles and permissions.
//!
//! Permission identifiers use `product.resource.action` (e.g.
//! `continuity.document.read`, `org.members.manage`). Built-in roles are
//! seeded per organization: Owner (implicit allow-all), Administrator,
//! Member and Viewer. Custom roles are org-scoped collections of
//! permissions. Every authorization decision is scoped to an organization
//! and denies by default.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use utoipa::ToSchema;

use crate::audit::{self, ActorType, AuditEvent};
use crate::authn::Authed;
use crate::correlation::HttpMeta;
use crate::error::{ApiError, ApiResult, MapInternal};
use crate::ids::new_id;
use crate::oidc::token;
use crate::state::AppState;
use crate::util;

pub mod perms {
    pub const OVERVIEW_READ: &str = "org.overview.read";
    pub const MEMBERS_READ: &str = "org.members.read";
    pub const MEMBERS_MANAGE: &str = "org.members.manage";
    pub const MEMBERS_INVITE: &str = "org.members.invite";
    pub const MEMBERS_SUSPEND: &str = "org.members.suspend";
    pub const MEMBERS_REMOVE: &str = "org.members.remove";
    pub const TEAMS_READ: &str = "org.teams.read";
    pub const TEAMS_MANAGE: &str = "org.teams.manage";
    pub const ROLES_READ: &str = "org.roles.read";
    pub const ROLES_MANAGE: &str = "org.roles.manage";
    pub const APPS_READ: &str = "org.apps.read";
    pub const APPS_MANAGE: &str = "org.apps.manage";
    pub const SERVICE_ACCOUNTS_READ: &str = "org.service-accounts.read";
    pub const SERVICE_ACCOUNTS_MANAGE: &str = "org.service-accounts.manage";
    pub const DEVICES_READ: &str = "org.devices.read";
    pub const DEVICES_MANAGE: &str = "org.devices.manage";
    pub const AUDIT_READ: &str = "org.audit.read";
    pub const SETTINGS_READ: &str = "org.settings.read";
    pub const SETTINGS_MANAGE: &str = "org.settings.manage";
    pub const WEBHOOKS_MANAGE: &str = "org.webhooks.manage";
}

/// Default permission set for the built-in Administrator role.
pub const ADMIN_PERMS: &[&str] = &[
    perms::OVERVIEW_READ,
    perms::MEMBERS_READ,
    perms::MEMBERS_MANAGE,
    perms::MEMBERS_INVITE,
    perms::MEMBERS_SUSPEND,
    perms::MEMBERS_REMOVE,
    perms::TEAMS_READ,
    perms::TEAMS_MANAGE,
    perms::ROLES_READ,
    perms::ROLES_MANAGE,
    perms::APPS_READ,
    perms::APPS_MANAGE,
    perms::SERVICE_ACCOUNTS_READ,
    perms::SERVICE_ACCOUNTS_MANAGE,
    perms::DEVICES_READ,
    perms::DEVICES_MANAGE,
    perms::AUDIT_READ,
    perms::SETTINGS_READ,
    perms::SETTINGS_MANAGE,
    perms::WEBHOOKS_MANAGE,
];

/// Default permission set for the built-in Member role.
pub const MEMBER_PERMS: &[&str] = &[
    perms::OVERVIEW_READ,
    perms::MEMBERS_READ,
    perms::TEAMS_READ,
    perms::ROLES_READ,
    perms::APPS_READ,
    perms::SETTINGS_READ,
];

/// Default permission set for the built-in Viewer role (read-only).
pub const VIEWER_PERMS: &[&str] = &[
    perms::OVERVIEW_READ,
    perms::MEMBERS_READ,
    perms::TEAMS_READ,
    perms::ROLES_READ,
    perms::APPS_READ,
    perms::SERVICE_ACCOUNTS_READ,
    perms::DEVICES_READ,
    perms::AUDIT_READ,
    perms::SETTINGS_READ,
];

pub const ROLE_OWNER: &str = "Owner";
pub const ROLE_ADMIN: &str = "Administrator";
pub const ROLE_MEMBER: &str = "Member";
pub const ROLE_VIEWER: &str = "Viewer";

/// An authenticated principal within an organization.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgPrincipal {
    pub org_id: Uuid,
    pub org_name: String,
    pub org_slug: String,
    pub user_id: Uuid,
    pub role_id: Option<Uuid>,
    pub role_name: String,
    pub is_owner: bool,
    pub status: String,
}

impl OrgPrincipal {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

#[derive(sqlx::FromRow)]
struct PrincipalRow {
    org_id: Uuid,
    org_name: String,
    org_slug: String,
    user_id: Uuid,
    role_id: Option<Uuid>,
    role_name: Option<String>,
    is_owner: bool,
    status: String,
}

/// Load the caller's organization context. Returns None when the user has no
/// membership in the organization (or it was deleted).
pub async fn load_principal(pool: &PgPool, user_id: Uuid, org_id: Uuid) -> ApiResult<Option<OrgPrincipal>> {
    let row = sqlx::query_as::<_, PrincipalRow>(
        r#"
        SELECT
            o.id AS org_id, o.name AS org_name, o.slug AS org_slug,
            m.user_id, m.role_id, r.name AS role_name,
            COALESCE(r.is_owner, false) AS is_owner, m.status
        FROM org_memberships m
        JOIN organizations o ON o.id = m.org_id
        LEFT JOIN roles r ON r.id = m.role_id
        WHERE m.user_id = $1 AND m.org_id = $2
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .map_internal("load principal")?;

    Ok(row.map(|r| OrgPrincipal {
        org_id: r.org_id,
        org_name: r.org_name,
        org_slug: r.org_slug,
        user_id: r.user_id,
        role_id: r.role_id,
        role_name: r.role_name.unwrap_or_default(),
        is_owner: r.is_owner,
        status: r.status,
    }))
}

/// Authorize an organization-scoped permission. Denies by default.
pub async fn authorize(
    pool: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
    permission: &str,
) -> ApiResult<OrgPrincipal> {
    let Some(principal) = load_principal(pool, user_id, org_id).await? else {
        return Err(ApiError::Forbidden);
    };
    if !principal.is_active() {
        return Err(ApiError::Forbidden);
    }
    if principal.is_owner || has_permission(pool, user_id, org_id, permission).await? {
        Ok(principal)
    } else {
        Err(ApiError::Forbidden)
    }
}

/// True when the user holds the permission (or is owner). Never errors on
/// "no membership" — returns false.
pub async fn has_permission(
    pool: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
    permission: &str,
) -> ApiResult<bool> {
    let res = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM org_memberships m
            LEFT JOIN roles r ON r.id = m.role_id
            WHERE m.user_id = $1 AND m.org_id = $2 AND m.status = 'active'
              AND (r.is_owner OR EXISTS(
                    SELECT 1 FROM role_permissions rp
                    WHERE rp.role_id = r.id AND rp.permission = $3
                  ))
        )
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .bind(permission)
    .fetch_one(pool)
    .await
    .map_internal("check permission")?;
    Ok(res)
}

/// True when the user is an active member (regardless of role).
pub async fn is_active_member(pool: &PgPool, user_id: Uuid, org_id: Uuid) -> ApiResult<bool> {
    let res = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM org_memberships WHERE user_id = $1 AND org_id = $2 AND status = 'active')",
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_one(pool)
    .await
    .map_internal("check membership")?;
    Ok(res)
}

/// Seed the four built-in roles for a new organization. Idempotent.
/// Runs on a connection so callers can wrap it in a transaction.
pub async fn seed_org_roles(conn: &mut sqlx::PgConnection, org_id: Uuid) -> ApiResult<()> {
    if sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM roles WHERE org_id = $1)")
        .bind(org_id)
        .fetch_one(&mut *conn)
        .await
        .map_internal("check existing roles")?
    {
        return Ok(());
    }

    let roles: [(&str, bool, &[&str]); 4] = [
        (ROLE_OWNER, true, &[]),
        (ROLE_ADMIN, false, ADMIN_PERMS),
        (ROLE_MEMBER, false, MEMBER_PERMS),
        (ROLE_VIEWER, false, VIEWER_PERMS),
    ];

    for (name, is_owner, perms) in roles {
        let role_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO roles (id, org_id, name, is_system, is_owner, description) VALUES ($1, $2, $3, true, $4, '')",
        )
        .bind(role_id)
        .bind(org_id)
        .bind(name)
        .bind(is_owner)
        .execute(&mut *conn)
        .await
        .map_internal("insert built-in role")?;

        for p in perms {
            sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ($1, $2)")
                .bind(role_id)
                .bind(p)
                .execute(&mut *conn)
                .await
                .map_internal("insert role permission")?;
        }
    }
    Ok(())
}

/// Find the org-scoped built-in role id by name (e.g. "Member").
pub async fn find_org_role(
    conn: &mut sqlx::PgConnection,
    org_id: Uuid,
    name: &str,
) -> ApiResult<Option<Uuid>> {
    let res = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM roles WHERE org_id = $1 AND name = $2",
    )
    .bind(org_id)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await
    .map_internal("find org role")?;
    Ok(res)
}

/// RBAC administrative endpoints and the authorization check API.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/orgs/{org_id}/roles", get(list_roles).post(create_role))
        .route(
            "/api/orgs/{org_id}/roles/{role_id}",
            patch(update_role).delete(delete_role),
        )
        .route("/api/v1/authorize/check", post(permission_check))
}

// ------------------------------------------------------------------- models

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleJson {
    pub id: Uuid,
    pub name: String,
    pub is_system: bool,
    pub is_owner: bool,
    pub description: String,
    pub permissions: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateRoleReq {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub permissions: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRoleReq {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Option<Vec<String>>,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PermissionCheckReq {
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub permission: String,
}

// ---------------------------------------------------------------- handlers

/// List the roles of an organization (requires `org.roles.read`).
#[utoipa::path(
    get,
    path = "/api/orgs/{org_id}/roles",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    responses(
        (status = 200, description = "Roles of the organization"),
        (status = 403, description = "Insufficient permissions")
    ),
    security(("sessionCookie" = []))
)]
pub async fn list_roles(
    State(state): State<AppState>,
    authed: Authed,
    Path(org_id): Path<Uuid>,
) -> ApiResult<Response> {
    rbac_authorize(&state, authed.0.user.id, org_id, perms::ROLES_READ).await?;

    let roles = sqlx::query_as::<_, RoleRow>(
        r#"
        SELECT id, name, is_system, is_owner, description FROM roles
        WHERE org_id = $1 ORDER BY is_system DESC, name
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_internal("list roles")?;

    let mut result: Vec<RoleJson> = Vec::with_capacity(roles.len());
    for role in roles {
        let permissions: Vec<String> =
            sqlx::query_scalar("SELECT permission FROM role_permissions WHERE role_id = $1 ORDER BY permission")
                .bind(role.id)
                .fetch_all(&state.pool)
                .await
                .map_internal("list role permissions")?;
        result.push(RoleJson {
            id: role.id,
            name: role.name,
            is_system: role.is_system,
            is_owner: role.is_owner,
            description: role.description,
            permissions,
        });
    }

    Ok(Json(serde_json::json!({ "roles": result })).into_response())
}

#[derive(sqlx::FromRow)]
struct RoleRow {
    id: Uuid,
    name: String,
    is_system: bool,
    is_owner: bool,
    description: String,
}

/// Create a custom organization role (requires `org.roles.manage`).
#[utoipa::path(
    post,
    path = "/api/orgs/{org_id}/roles",
    params(("org_id" = Uuid, Path, description = "Organization id")),
    request_body = CreateRoleReq,
    responses(
        (status = 201, description = "Role created"),
        (status = 403, description = "Insufficient permissions"),
        (status = 409, description = "Role name already exists")
    ),
    security(("sessionCookie" = []))
)]
pub async fn create_role(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path(org_id): Path<Uuid>,
    Json(req): Json<CreateRoleReq>,
) -> ApiResult<Response> {
    rbac_authorize(&state, authed.0.user.id, org_id, perms::ROLES_MANAGE).await?;

    let name = validate_role_name(&req.name)?;
    validate_permissions(&req.permissions)?;
    let description = req.description.trim().chars().take(200).collect::<String>();

    let role_id = new_id();
    let mut tx = state.pool.begin().await.map_internal("begin role tx")?;
    let inserted = sqlx::query(
        "INSERT INTO roles (id, org_id, name, is_system, is_owner, description) VALUES ($1, $2, $3, false, false, $4)",
    )
    .bind(role_id)
    .bind(org_id)
    .bind(&name)
    .bind(&description)
    .execute(&mut *tx)
    .await;
    if let Err(e) = inserted {
        if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
            return Err(ApiError::Conflict("a role with this name already exists".into()));
        }
        return Err(ApiError::internal("create role", e));
    }
    for p in &req.permissions {
        sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ($1, $2)")
            .bind(role_id)
            .bind(p)
            .execute(&mut *tx)
            .await
            .map_internal("insert role permission")?;
    }
    tx.commit().await.map_internal("commit role tx")?;

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: "role.created",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("role"),
            target_id: Some(role_id),
            metadata: serde_json::json!({ "name": name }),
        },
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "role": { "id": role_id, "name": name } })),
    )
        .into_response())
}

/// Update a custom role (requires `org.roles.manage`). Built-in roles are
/// immutable.
#[utoipa::path(
    patch,
    path = "/api/orgs/{org_id}/roles/{role_id}",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("role_id" = Uuid, Path, description = "Role id")
    ),
    request_body = UpdateRoleReq,
    responses(
        (status = 200, description = "Role updated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Role not found")
    ),
    security(("sessionCookie" = []))
)]
pub async fn update_role(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateRoleReq>,
) -> ApiResult<Response> {
    rbac_authorize(&state, authed.0.user.id, org_id, perms::ROLES_MANAGE).await?;
    authed.0.require_reauth(&state.config)?;

    let role = sqlx::query_as::<_, RoleRow>(
        "SELECT id, name, is_system, is_owner, description FROM roles WHERE id = $1 AND org_id = $2",
    )
    .bind(role_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load role")?
    .ok_or(ApiError::NotFound)?;

    if role.is_system || role.is_owner {
        return Err(ApiError::Validation("built-in roles are immutable".into()));
    }

    let mut tx = state.pool.begin().await.map_internal("begin role update")?;
    if let Some(name) = &req.name {
        let name = validate_role_name(name)?;
        let res = sqlx::query("UPDATE roles SET name = $1 WHERE id = $2 AND org_id = $3")
            .bind(&name)
            .bind(role_id)
            .bind(org_id)
            .execute(&mut *tx)
            .await;
        if let Err(e) = res {
            if e.as_database_error().is_some_and(|d| d.is_unique_violation()) {
                return Err(ApiError::Conflict("a role with this name already exists".into()));
            }
            return Err(ApiError::internal("rename role", e));
        }
    }
    if let Some(description) = &req.description {
        let description = description.trim().chars().take(200).collect::<String>();
        sqlx::query("UPDATE roles SET description = $1 WHERE id = $2")
            .bind(&description)
            .bind(role_id)
            .execute(&mut *tx)
            .await
            .map_internal("update role description")?;
    }
    if let Some(permissions) = &req.permissions {
        validate_permissions(permissions)?;
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
            .bind(role_id)
            .execute(&mut *tx)
            .await
            .map_internal("clear role permissions")?;
        for p in permissions {
            sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ($1, $2)")
                .bind(role_id)
                .bind(p)
                .execute(&mut *tx)
                .await
                .map_internal("insert role permission")?;
        }
    }
    tx.commit().await.map_internal("commit role update")?;

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: "role.updated",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("role"),
            target_id: Some(role_id),
            metadata: serde_json::json!({}),
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

/// Delete a custom role (requires `org.roles.manage` + reauthentication).
/// Roles assigned to members or service accounts cannot be deleted.
#[utoipa::path(
    delete,
    path = "/api/orgs/{org_id}/roles/{role_id}",
    params(
        ("org_id" = Uuid, Path, description = "Organization id"),
        ("role_id" = Uuid, Path, description = "Role id")
    ),
    responses(
        (status = 204, description = "Role deleted"),
        (status = 403, description = "Insufficient permissions or reauthentication required"),
        (status = 404, description = "Role not found"),
        (status = 409, description = "Role is in use")
    ),
    security(("sessionCookie" = []))
)]
pub async fn delete_role(
    State(state): State<AppState>,
    meta: HttpMeta,
    authed: Authed,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    authed.0.require_reauth(&state.config)?;
    rbac_authorize(&state, authed.0.user.id, org_id, perms::ROLES_MANAGE).await?;

    let role = sqlx::query_as::<_, RoleRow>(
        "SELECT id, name, is_system, is_owner, description FROM roles WHERE id = $1 AND org_id = $2",
    )
    .bind(role_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .map_internal("load role")?
    .ok_or(ApiError::NotFound)?;

    if role.is_system || role.is_owner {
        return Err(ApiError::Validation("built-in roles cannot be deleted".into()));
    }

    let in_use = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM org_memberships WHERE role_id = $1
            UNION ALL
            SELECT 1 FROM service_accounts WHERE role_id = $1
        )
        "#,
    )
    .bind(role_id)
    .fetch_one(&state.pool)
    .await
    .map_internal("check role usage")?;
    if in_use {
        return Err(ApiError::Conflict(
            "this role is assigned to members or service accounts; reassign them first".into(),
        ));
    }

    sqlx::query("DELETE FROM roles WHERE id = $1 AND org_id = $2")
        .bind(role_id)
        .bind(org_id)
        .execute(&state.pool)
        .await
        .map_internal("delete role")?;

    audit::record(
        &state,
        &meta,
        AuditEvent {
            event_type: "role.deleted",
            actor_type: ActorType::User,
            actor_id: Some(authed.0.user.id),
            org_id: Some(org_id),
            target_type: Some("role"),
            target_id: Some(role_id),
            metadata: serde_json::json!({ "name": role.name }),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The documented permission-check endpoint for product APIs.
///
/// Authentication: bearer access token issued via `client_credentials`
/// (service account or device). The caller may only ask about users within
/// its own organization; the `organization_id` in the body must match the
/// token's organization. Deny by default.
#[utoipa::path(
    post,
    path = "/api/v1/authorize/check",
    request_body = PermissionCheckReq,
    responses(
        (status = 200, description = "Authorization decision", body = inline(crate::openapi::PermissionCheckResponse)),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller may not check this organization")
    ),
    security(("bearerAuth" = []))
)]
pub async fn permission_check(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PermissionCheckReq>,
) -> ApiResult<Response> {
    let token_str = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    let tok = token::validate_access_token(&state, token_str, None).await?;
    if !matches!(tok.actor_type.as_str(), "service_account" | "device") {
        return Err(ApiError::Forbidden);
    }
    let Some(actor_org) = tok.org_id else {
        return Err(ApiError::Forbidden);
    };

    // Tenant isolation: the caller can only check within its own organization.
    if req.organization_id != actor_org {
        return Err(ApiError::Forbidden);
    }
    if !util::is_valid_permission(&req.permission) {
        return Err(ApiError::Validation("malformed permission identifier".into()));
    }

    // Deny by default: no membership, suspended member, missing permission.
    let allowed = is_active_member(&state.pool, req.user_id, req.organization_id).await?
        && has_permission(&state.pool, req.user_id, req.organization_id, &req.permission).await?;

    Ok(Json(serde_json::json!({
        "allowed": allowed,
        "organizationId": req.organization_id,
        "userId": req.user_id,
        "permission": req.permission,
    }))
    .into_response())
}

// ------------------------------------------------------------------ helpers

fn validate_role_name(name: &str) -> ApiResult<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiError::Validation("role name must be between 1 and 64 characters".into()));
    }
    let reserved = [ROLE_OWNER, ROLE_ADMIN, ROLE_MEMBER, ROLE_VIEWER];
    if reserved.contains(&name) {
        return Err(ApiError::Validation(format!("{name} is a reserved role name")));
    }
    Ok(name.to_string())
}

fn validate_permissions(permissions: &[String]) -> ApiResult<()> {
    if permissions.is_empty() {
        return Err(ApiError::Validation("a role needs at least one permission".into()));
    }
    if permissions.len() > 200 {
        return Err(ApiError::Validation("too many permissions".into()));
    }
    for p in permissions {
        if !util::is_valid_permission(p) {
            return Err(ApiError::Validation(format!("invalid permission identifier: {p}")));
        }
    }
    Ok(())
}

async fn rbac_authorize(state: &AppState, user_id: Uuid, org_id: Uuid, permission: &str) -> ApiResult<()> {
    authorize(&state.pool, user_id, org_id, permission).await.map(|_| ())
}
