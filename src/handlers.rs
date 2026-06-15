use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::AppState;
use crate::error::ApiError;
use crate::renderer::ShotRequest;

pub async fn health() -> &'static str {
    "ok"
}

/// Query parameters for `GET /shot`. Short aliases (`w`, `h`, `dpr`) are accepted.
#[derive(Debug, Deserialize)]
pub struct ShotParams {
    pub url: String,
    #[serde(alias = "w")]
    pub width: Option<u32>,
    #[serde(alias = "h")]
    pub height: Option<u32>,
    #[serde(alias = "dpr")]
    pub device_pixel_ratio: Option<f32>,
    pub timeout: Option<u64>,
}

/// `GET /shot?url=…&w=…&h=…&dpr=…&timeout=…` → `image/png`.
pub async fn shot(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ShotParams>,
) -> Result<impl IntoResponse, ApiError> {
    let cfg = &state.config;
    let req = ShotRequest {
        url: params.url,
        width: params.width.unwrap_or(cfg.default_width),
        height: params.height.unwrap_or(cfg.default_height),
        device_pixel_ratio: params.device_pixel_ratio,
        timeout: Duration::from_secs(params.timeout.unwrap_or(cfg.render_timeout_secs)),
    };

    // Cap concurrent Servo processes to bound memory use.
    let _permit = state
        .render_slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let started = Instant::now();
    let png = state.renderer.render(&req).await?;
    tracing::info!(
        url = %req.url,
        bytes = png.len(),
        ms = started.elapsed().as_millis(),
        "rendered"
    );

    Ok(([(header::CONTENT_TYPE, "image/png")], png))
}
