//! Identifier generation. All public identifiers are UUIDv7 — sortable,
//! globally unique, and never sequential.

use uuid::Uuid;

pub fn new_id() -> Uuid {
    Uuid::now_v7()
}

/// New correlation identifier.
pub fn new_correlation_id() -> Uuid {
    Uuid::now_v7()
}
