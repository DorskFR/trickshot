use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Errors surfaced to HTTP clients.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("render timed out")]
    Timeout,

    #[error("render failed: {0}")]
    Render(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Render(_) => StatusCode::BAD_GATEWAY,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}
