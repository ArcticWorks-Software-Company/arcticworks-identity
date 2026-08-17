//! Central error type. Renders as JSON with a stable machine-readable code
//! and a human-readable message. Internal details are never leaked to clients.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Validation(String),

    #[error("not found")]
    NotFound,

    #[error("{0}")]
    Conflict(String),

    #[error("authentication required")]
    Unauthorized,

    #[error("insufficient permissions")]
    Forbidden,

    #[error("reauthentication required")]
    ReauthRequired,

    #[error("invalid or expired token")]
    TokenInvalid,

    #[error("email address is not verified")]
    EmailNotVerified,

    #[error("rate limit exceeded")]
    RateLimited { retry_after_secs: u64 },

    #[error("{0}")]
    Gone(String),

    #[error("internal server error")]
    Internal(#[source] anyhow::Error),
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    fn code(&self) -> &'static str {
        match self {
            ApiError::Validation(_) => "validation_failed",
            ApiError::NotFound => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::Unauthorized => "unauthorized",
            ApiError::Forbidden => "forbidden",
            ApiError::ReauthRequired => "reauth_required",
            ApiError::TokenInvalid => "token_invalid",
            ApiError::EmailNotVerified => "email_not_verified",
            ApiError::RateLimited { .. } => "rate_limited",
            ApiError::Gone(_) => "gone",
            ApiError::Internal(_) => "internal",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            ApiError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::ReauthRequired => StatusCode::FORBIDDEN,
            ApiError::TokenInvalid => StatusCode::UNAUTHORIZED,
            ApiError::EmailNotVerified => StatusCode::FORBIDDEN,
            ApiError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Gone(_) => StatusCode::GONE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Log a server-side error with full context before turning it into a
    /// response. Use at service boundaries.
    pub fn internal(context: &str, err: impl std::fmt::Display) -> Self {
        tracing::error!(context, error = %err);
        ApiError::Internal(anyhow::anyhow!("{context}: {err}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = json!({
            "error": {
                "code": self.code(),
                "message": self.to_string(),
            }
        });
        let mut resp = (status, Json(body)).into_response();
        if let ApiError::RateLimited { retry_after_secs } = self {
            if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                resp.headers_mut().insert("retry-after", value);
            }
        }
        resp
    }
}

pub trait MapInternal<T> {
    fn map_internal(self, context: &str) -> ApiResult<T>;
}

impl<T, E: std::fmt::Display> MapInternal<T> for Result<T, E> {
    fn map_internal(self, context: &str) -> ApiResult<T> {
        self.map_err(|e| ApiError::internal(context, e))
    }
}
