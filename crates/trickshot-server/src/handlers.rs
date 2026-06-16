use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use url::Url;

use crate::chrome::ShotRequest;
use crate::error::ApiError;
use crate::{AppState, ssrf, tunnel};

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
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let presented = extract_key(request.headers(), request.uri().query())
        .ok_or_else(|| ApiError::Unauthorized("missing api key".into()))?;

    match state.keys.verify(&presented) {
        Some((id, label)) => {
            tracing::info!(key_id = %id, key_label = %label, "authenticated request");
            // Stash the matched key id so downstream handlers (e.g. /tunnel)
            // can attribute the tunnel to the caller.
            request.extensions_mut().insert(AuthedKey(id));
            Ok(next.run(request).await)
        }
        None => Err(ApiError::Unauthorized("invalid api key".into())),
    }
}

/// The authenticated key id, injected into request extensions by
/// [`require_api_key`] so downstream handlers can read it.
#[derive(Clone)]
pub struct AuthedKey(pub String);

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
    /// Route this shot through an open reverse tunnel (TRI-5). When set, the
    /// shot uses the tunnel's loopback SOCKS5 proxy and the direct-path SSRF
    /// private-IP block is skipped (reachability is the requester's network's).
    pub tunnel: Option<String>,
}

/// `GET /shot?url=…&w=…&h=…&timeout=…` → `image/png`.
pub async fn shot(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ShotParams>,
) -> Result<impl IntoResponse, ApiError> {
    let cfg = &state.config;

    let parsed =
        Url::parse(&params.url).map_err(|e| ApiError::BadRequest(format!("invalid url: {e}")))?;

    // Resolve an optional reverse tunnel. When present, traffic is delegated to
    // the requester's network: we use its loopback SOCKS5 proxy and skip the
    // direct-path SSRF private-IP block (intentional, per TRI-5). Without a
    // tunnel, behaviour is unchanged — direct egress + the SSRF block.
    let proxy_server = if let Some(id) = &params.tunnel {
        let t = state
            .tunnels
            .get(id)
            .await
            .ok_or_else(|| ApiError::BadRequest("unknown or closed tunnel".into()))?;
        Some(t.proxy_server())
    } else {
        ssrf::check(&parsed, cfg.allow_private_targets)?;
        None
    };

    let req = ShotRequest {
        url: params.url,
        width: params.width.unwrap_or(cfg.default_width),
        height: params.height.unwrap_or(cfg.default_height),
        scale: params.scale.unwrap_or(1.0),
        timeout: Duration::from_secs(params.timeout.unwrap_or(cfg.render_timeout_secs)),
        proxy_server,
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

/// `GET /tunnel` (WebSocket upgrade). The requester's agent dials this; on
/// upgrade the server binds a per-tunnel loopback SOCKS5 proxy and registers it
/// under a fresh `tunnel_id`, which the agent then passes to `/shot?...&tunnel=`.
/// Requires the same API key as `/shot` (the route is behind the same guard).
pub async fn tunnel(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
    request: Request,
) -> Response {
    // `require_api_key` ran first and stashed the caller's key id.
    let key_id = request
        .extensions()
        .get::<AuthedKey>()
        .map_or_else(|| "unknown".to_string(), |k| k.0.clone());
    let tunnels = state.tunnels.clone();
    let cfg = state.config.tunnel_config();
    ws.on_upgrade(move |socket| tunnel::run(socket, tunnels, cfg, key_id))
}
