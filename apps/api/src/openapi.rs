//! OpenAPI documentation for the administrative API.
//!
//! Served at `GET /api/openapi.json`; interactive UI at `GET /api/docs`.
//! OIDC endpoints are standards-defined and documented in `docs/architecture.md`.

use axum::Router;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use uuid::Uuid;

use crate::state::AppState;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "ArcticWorks Identity — Administrative API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Administrative API for ArcticWorks Identity: organizations, members, teams, roles and permissions, applications (OIDC clients), service accounts, device enrollment and the audit log.\n\nAuthentication: browser session cookie for human administration endpoints; bearer access token (service account / device client credentials) for POST /api/v1/authorize/check.",
    ),
    paths(
        crate::accounts::register,
        crate::accounts::login,
        crate::accounts::me,
        crate::orgs::create_org,
        crate::orgs::get_org,
        crate::orgs::update_org,
        crate::orgs::transfer_ownership,
        crate::orgs::list_members,
        crate::orgs::set_member_role,
        crate::orgs::suspend_member,
        crate::orgs::unsuspend_member,
        crate::orgs::remove_member,
        crate::orgs::create_invitation,
        crate::orgs::list_invitations,
        crate::orgs::revoke_invitation,
        crate::orgs::accept_invitation,
        crate::orgs::create_team,
        crate::orgs::list_teams,
        crate::orgs::update_team,
        crate::orgs::delete_team,
        crate::orgs::audit_log,
        crate::rbac::list_roles,
        crate::rbac::create_role,
        crate::rbac::update_role,
        crate::rbac::delete_role,
        crate::rbac::permission_check,
        crate::oidc::list_applications,
        crate::oidc::create_application,
        crate::oidc::update_application,
        crate::oidc::rotate_client_secret,
        crate::oidc::delete_application,
        crate::machine::create_service_account,
        crate::machine::list_service_accounts,
        crate::machine::rotate_service_account_credential,
        crate::machine::suspend_service_account,
        crate::machine::unsuspend_service_account,
        crate::machine::delete_service_account,
        crate::machine::create_enrollment_token,
        crate::machine::enroll_device,
        crate::machine::list_devices,
        crate::machine::update_device,
        crate::machine::rotate_device_credential,
        crate::machine::revoke_device,
    ),
    components(schemas(
        crate::accounts::RegisterReq,
        crate::accounts::LoginReq,
        crate::accounts::UserJson,
        crate::orgs::CreateOrgReq,
        crate::orgs::UpdateOrgReq,
        crate::orgs::TransferReq,
        crate::orgs::SetRoleReq,
        crate::orgs::CreateInvitationReq,
        crate::orgs::CreateTeamReq,
        crate::orgs::UpdateTeamReq,
        crate::orgs::AddTeamMemberReq,
        crate::orgs::MemberJson,
        crate::orgs::InvitationJson,
        crate::orgs::TeamJson,
        crate::rbac::CreateRoleReq,
        crate::rbac::UpdateRoleReq,
        crate::rbac::PermissionCheckReq,
        crate::rbac::RoleJson,
        crate::oidc::CreateApplicationReq,
        crate::oidc::UpdateApplicationReq,
        crate::oidc::ApplicationJson,
        crate::machine::CreateServiceAccountReq,
        crate::machine::UpdateServiceAccountReq,
        crate::machine::CreateEnrollmentTokenReq,
        crate::machine::EnrollReq,
        crate::machine::UpdateDeviceReq,
        crate::machine::ServiceAccountJson,
        crate::machine::DeviceJson,
        crate::openapi::MembersResponse,
        crate::openapi::InvitationsResponse,
        crate::openapi::RolesResponse,
        crate::openapi::ApplicationsResponse,
        crate::openapi::ServiceAccountsResponse,
        crate::openapi::DevicesResponse,
        crate::openapi::PermissionCheckResponse,
    )),
    modifiers(&SecurityAddon),
)]
pub struct AdminApi;

#[derive(utoipa::ToSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MembersResponse {
    pub members: Vec<crate::orgs::MemberJson>,
}

#[derive(utoipa::ToSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationsResponse {
    pub invitations: Vec<crate::orgs::InvitationJson>,
}

#[derive(utoipa::ToSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RolesResponse {
    pub roles: Vec<crate::rbac::RoleJson>,
}

#[derive(utoipa::ToSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationsResponse {
    pub applications: Vec<crate::oidc::ApplicationJson>,
}

#[derive(utoipa::ToSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountsResponse {
    pub service_accounts: Vec<crate::machine::ServiceAccountJson>,
}

#[derive(utoipa::ToSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicesResponse {
    pub devices: Vec<crate::machine::DeviceJson>,
}

#[derive(utoipa::ToSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionCheckResponse {
    pub allowed: bool,
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub permission: String,
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearerAuth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            components.add_security_scheme(
                "sessionCookie",
                SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("aw_session"))),
            );
        }
    }
}

pub fn routes() -> Router<AppState> {
    // SwaggerUi serves both the interactive UI (/api/docs) and the raw
    // OpenAPI document (/api/openapi.json).
    utoipa_swagger_ui::SwaggerUi::new("/api/docs")
        .url("/api/openapi.json", AdminApi::openapi())
        .into()
}
