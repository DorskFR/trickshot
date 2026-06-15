use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::AppState;
use crate::engine::ShotRequest;
use crate::error::ApiError;

pub async fn health() -> &'static str {
    "ok"
}

/// Query parameters for `GET /shot`. Short aliases (`w`, `h`) are accepted.
#[derive(Debug, Deserialize)]
pub struct ShotParams {
    pub url: String,
    #[serde(alias = "w")]
    pub width: Option<u32>,
    #[serde(alias = "h")]
    pub height: Option<u32>,
    pub timeout: Option<u64>,
}

/// `GET /shot?url=…&w=…&h=…&timeout=…` → `image/png`.
pub async fn shot(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ShotParams>,
) -> Result<impl IntoResponse, ApiError> {
    let cfg = &state.config;
    let req = ShotRequest {
        url: params.url,
        width: params.width.unwrap_or(cfg.default_width),
        height: params.height.unwrap_or(cfg.default_height),
        timeout: Duration::from_secs(params.timeout.unwrap_or(cfg.render_timeout_secs)),
    };

    let started = Instant::now();
    let png = state.pool.render(&req).await?;
    tracing::info!(
        url = %req.url,
        bytes = png.len(),
        ms = started.elapsed().as_millis(),
        "rendered"
    );

    Ok(([(header::CONTENT_TYPE, "image/png")], png))
}
