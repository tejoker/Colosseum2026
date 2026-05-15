//! Minimal error type for HTTP boundary handlers.
//!
//! Replaces `.unwrap()` / `.expect()` / `panic!` inside axum handlers so that
//! a malicious or malformed request can no longer DoS the server. Every
//! variant maps to a non-5xx-leaking HTTP response that does not expose
//! internal panic strings to the caller.
//!
//! Use `AppError::from(rusqlite::Error)` or `.map_err(AppError::internal)?` at
//! call sites that previously `.unwrap()`'d a fallible value.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    NotFound(String),
    Conflict(String),
    Internal(String),
}

impl AppError {
    pub fn internal<E: fmt::Display>(e: E) -> Self {
        AppError::Internal(e.to_string())
    }
    pub fn bad_request<S: Into<String>>(s: S) -> Self {
        AppError::BadRequest(s.into())
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::BadRequest(s) => write!(f, "bad request: {s}"),
            AppError::Unauthorized(s) => write!(f, "unauthorized: {s}"),
            AppError::NotFound(s) => write!(f, "not found: {s}"),
            AppError::Conflict(s) => write!(f, "conflict: {s}"),
            AppError::Internal(s) => write!(f, "internal: {s}"),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m),
            // Internal errors: log full detail, return generic message to caller
            // to avoid leaking implementation details to pentesters.
            AppError::Internal(m) => {
                tracing::error!(target: "sauron::error", detail = %m, "internal handler error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".to_string())
            }
        };
        (code, msg).into_response()
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Internal(format!("sqlite: {e}"))
    }
}
