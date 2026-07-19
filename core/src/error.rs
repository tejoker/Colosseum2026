//! Minimal error type for HTTP boundary handlers.
//!
//! Replaces `.unwrap()` / `.expect()` / `panic!` inside axum handlers so that
//! a malicious or malformed request can no longer DoS the server. Every
//! variant maps to a non-5xx-leaking HTTP response that does not expose
//! internal panic strings to the caller.
//!
//! Use `AppError::from(rusqlite::Error)` or `.map_err(AppError::internal)?` at
//! call sites that previously `.unwrap()`'d a fallible value.
//!
//! Responses are a JSON envelope that teaches the caller how to recover:
//! `{"error":{"code":"<stable_snake_case>","message":"...","fix":"..."}}`.
//! `code` is stable machine-matchable; `message` keeps the exact legacy text
//! (existing substring assertions in redteam/e2e suites still pass); `fix` is
//! a one-line remediation hint.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    NotFound(String),
    Conflict(String),
    ServiceUnavailable(String),
    Internal(String),
    /// Fully specified error with explicit status, stable code, and a
    /// remediation hint. Used where a generic per-variant hint is not enough
    /// (e.g. each distinct call-signature middleware rejection).
    Detailed {
        status: StatusCode,
        code: &'static str,
        message: String,
        fix: &'static str,
    },
}

impl AppError {
    pub fn internal<E: fmt::Display>(e: E) -> Self {
        AppError::Internal(e.to_string())
    }
    pub fn bad_request<S: Into<String>>(s: S) -> Self {
        AppError::BadRequest(s.into())
    }
    /// Error with an explicit stable code and one-line fix hint.
    pub fn with_hint<S: Into<String>>(
        status: StatusCode,
        code: &'static str,
        message: S,
        fix: &'static str,
    ) -> Self {
        AppError::Detailed {
            status,
            code,
            message: message.into(),
            fix,
        }
    }
    /// HTTP status this error maps to (without consuming it).
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Detailed { status, .. } => *status,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::BadRequest(s) => write!(f, "bad request: {s}"),
            AppError::Unauthorized(s) => write!(f, "unauthorized: {s}"),
            AppError::NotFound(s) => write!(f, "not found: {s}"),
            AppError::Conflict(s) => write!(f, "conflict: {s}"),
            AppError::ServiceUnavailable(s) => write!(f, "service unavailable: {s}"),
            AppError::Internal(s) => write!(f, "internal: {s}"),
            AppError::Detailed { code, message, .. } => write!(f, "{code}: {message}"),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message, fix) = match self {
            AppError::BadRequest(m) => (
                StatusCode::BAD_REQUEST,
                "bad_request",
                m,
                "check the request body and parameters against the API schema; see docs/sdk-integration.md",
            ),
            AppError::Unauthorized(m) => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                m,
                "check credentials and required x-sauron-* headers; see docs/sdk-integration.md",
            ),
            AppError::NotFound(m) => (
                StatusCode::NOT_FOUND,
                "not_found",
                m,
                "check the resource id and that it belongs to your tenant",
            ),
            AppError::Conflict(m) => (
                StatusCode::CONFLICT,
                "conflict",
                m,
                "the resource already exists or was modified concurrently; re-fetch current state and retry",
            ),
            AppError::ServiceUnavailable(m) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                m,
                "a dependency is temporarily unavailable; retry with backoff",
            ),
            // Internal errors: log full detail, return generic message to caller
            // to avoid leaking implementation details to pentesters.
            AppError::Internal(m) => {
                tracing::error!(target: "sauron::error", detail = %m, "internal handler error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal server error".to_string(),
                    "retry; contact the operator with the request timestamp if the error persists",
                )
            }
            AppError::Detailed {
                status,
                code,
                message,
                fix,
            } => (status, code, message, fix),
        };
        (
            status,
            Json(serde_json::json!({
                "error": { "code": code, "message": message, "fix": fix }
            })),
        )
            .into_response()
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Internal(format!("sqlite: {e}"))
    }
}
