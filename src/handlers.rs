use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use url::Url;

use crate::AppState;
use crate::chrome::ShotRequest;
use crate::error::ApiError;
use crate::ssrf;

pub async fn health() -> &'static str {
    "ok"
}

/// Extract the presented API key from (in order) `X-API-Key`,
/// `Authorization: Bearer <key>`, or the `api_key` query param.
fn extract_key(headers: &HeaderMap, query: Option<&str>) -> Option<String> {
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(v.to_string());
    }
    if let Some(v) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok())
        && let Some(token) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer "))
    {
        return Some(token.trim().to_string());
    }
    query.and_then(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == "api_key")
            .map(|(_, v)| v.into_owned())
    })
}

/// Axum middleware guarding `/shot`: rejects requests without a valid,
/// enabled key and logs the matched key id/label (never the secret).
pub async fn require_api_key(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let presented = extract_key(request.headers(), request.uri().query())
        .ok_or_else(|| ApiError::Unauthorized("missing api key".into()))?;

    match state.keys.verify(&presented) {
        Some((id, label)) => {
            tracing::info!(key_id = %id, key_label = %label, "authenticated request");
            Ok(next.run(request).await)
        }
        None => Err(ApiError::Unauthorized("invalid api key".into())),
    }
}

/// Query parameters for `GET /shot`. Short aliases (`w`, `h`) are accepted.
#[derive(Debug, Deserialize)]
pub struct ShotParams {
    pub url: String,
    #[serde(alias = "w")]
    pub width: Option<u32>,
    #[serde(alias = "h")]
    pub height: Option<u32>,
    /// Device pixel ratio (DPR). `scale=2` (alias `dpr`) yields a crisp 2x render.
    #[serde(alias = "dpr")]
    pub scale: Option<f64>,
    pub timeout: Option<u64>,
}

/// `GET /shot?url=…&w=…&h=…&timeout=…` → `image/png`.
pub async fn shot(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ShotParams>,
) -> Result<impl IntoResponse, ApiError> {
    let cfg = &state.config;

    // SSRF defense-in-depth: reject targets resolving to private/reserved IPs
    // (cloud metadata, loopback, RFC1918) unless explicitly allowed. The
    // scheme + deeper checks still run inside chrome.render.
    let parsed =
        Url::parse(&params.url).map_err(|e| ApiError::BadRequest(format!("invalid url: {e}")))?;
    ssrf::check(&parsed, cfg.allow_private_targets)?;

    let req = ShotRequest {
        url: params.url,
        width: params.width.unwrap_or(cfg.default_width),
        height: params.height.unwrap_or(cfg.default_height),
        scale: params.scale.unwrap_or(1.0),
        timeout: Duration::from_secs(params.timeout.unwrap_or(cfg.render_timeout_secs)),
    };

    let started = Instant::now();
    let png = state.chrome.render(&req).await?;
    tracing::info!(
        url = %req.url,
        bytes = png.len(),
        ms = started.elapsed().as_millis(),
        "rendered"
    );

    Ok(([(header::CONTENT_TYPE, "image/png")], png))
}
