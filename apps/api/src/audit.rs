//! Append-only audit log. Every security-relevant action is recorded here.
//! Rows are never updated or deleted; event types are stable strings.

use serde_json::Value;
use uuid::Uuid;

use crate::correlation::HttpMeta;
use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorType {
    User,
    ServiceAccount,
    Device,
    System,
}

impl ActorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActorType::User => "user",
            ActorType::ServiceAccount => "service_account",
            ActorType::Device => "device",
            ActorType::System => "system",
        }
    }
}

pub struct AuditEvent<'a> {
    pub event_type: &'a str,
    pub actor_type: ActorType,
    pub actor_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
    pub target_type: Option<&'a str>,
    pub target_id: Option<Uuid>,
    pub metadata: Value,
}

/// Record an audit event. Failures are logged loudly but never fail the
/// caller's operation (audit must not break the primary flow); security
/// events that accompany a successful operation are recorded in the same
/// transaction by callers where durability matters. Org-scoped events are
/// scheduled for asynchronous webhook delivery.
pub async fn record(state: &AppState, meta: &HttpMeta, event: AuditEvent<'_>) {
    let id = Uuid::now_v7();
    let res = sqlx::query(
        r#"
        INSERT INTO audit_events
            (id, correlation_id, event_type, actor_type, actor_id, org_id,
             target_type, target_id, ip, user_agent, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::inet, $10, $11)
        "#,
    )
    .bind(id)
    .bind(meta.correlation_id)
    .bind(event.event_type)
    .bind(event.actor_type.as_str())
    .bind(event.actor_id)
    .bind(event.org_id)
    .bind(event.target_type)
    .bind(event.target_id)
    .bind(meta.ip.map(|ip| ip.to_string()))
    .bind(&meta.user_agent)
    .bind(&event.metadata)
    .execute(&state.pool)
    .await;

    if let Err(e) = res {
        tracing::error!(
            event_type = event.event_type,
            error = %e,
            "failed to record audit event"
        );
    } else if let Some(org_id) = event.org_id {
        crate::webhooks::schedule(state, id, org_id);
    }
}
