use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Extension, Json, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::chrome::ShotRequest;
use crate::error::ApiError;
use crate::keys::{KeyInfo, Role};
use crate::{AppState, ssrf, tunnel};

/// Liveness: fails once the CDP connection to Chrome is gone, so the pod is
/// restarted instead of serving errors forever.
pub async fn health(State(state): State<Arc<AppState>>) -> (StatusCode, &'static str) {
    health_status(state.chrome.is_alive().await)
}

const fn health_status(chrome_alive: bool) -> (StatusCode, &'static str) {
    if chrome_alive {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "chrome connection lost")
    }
}

/// Extract the presented API key from (in order) `X-API-Key`,
/// `Authorization: Bearer <key>`, or the `api_key`/`apiKey` query param.
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
        // Accept both the snake_case `api_key` and the camelCase `apiKey`
        // spelling so a screenshot URL can be pasted straight into a browser.
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == "api_key" || k == "apiKey")
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
        Some((id, label, role)) => {
            tracing::info!(key_id = %id, key_label = %label, %role, "authenticated request");
            // Stash the matched key id/role so downstream handlers (e.g.
            // /tunnel, the admin guard) can read them.
            request.extensions_mut().insert(AuthedKey { id, role });
            Ok(next.run(request).await)
        }
        None => Err(ApiError::Unauthorized("invalid api key".into())),
    }
}

/// Axum middleware guarding `/admin/*`: runs *after* [`require_api_key`] and
/// rejects any key whose role is not `admin` with 403. The distinction from
/// 401 is intentional: a valid render key is authenticated but unauthorized.
pub async fn require_admin(request: Request, next: Next) -> Result<Response, ApiError> {
    let role = request.extensions().get::<AuthedKey>().map(|k| k.role);
    match role {
        Some(Role::Admin) => Ok(next.run(request).await),
        _ => Err(ApiError::Forbidden("insufficient permission: needs an admin key".into())),
    }
}

/// The authenticated key id + role, injected into request extensions by
/// [`require_api_key`] so downstream handlers can read them.
#[derive(Clone)]
pub struct AuthedKey {
    pub id: String,
    pub role: Role,
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
    /// Route this shot through an open reverse tunnel. The private-IP block is
    /// skipped: reachability is the requester's network's.
    pub tunnel: Option<String>,
}

/// `GET /shot?url=…&w=…&h=…&timeout=…` → `image/png`.
pub async fn shot(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthedKey>,
    Query(params): Query<ShotParams>,
) -> Result<impl IntoResponse, ApiError> {
    let cfg = &state.config;

    let width = dimension("width", params.width, cfg.default_width)?;
    let height = dimension("height", params.height, cfg.default_height)?;
    let scale = scale(params.scale)?;
    let timeout = timeout(params.timeout, cfg.render_timeout_secs)?;

    let parsed =
        Url::parse(&params.url).map_err(|e| ApiError::BadRequest(format!("invalid url: {e}")))?;

    let proxy_server = if let Some(id) = &params.tunnel {
        let t = state.tunnels.get(id).await.filter(|t| t.key_id == caller.id);
        let t = t.ok_or_else(|| ApiError::NotFound("unknown or closed tunnel".into()))?;
        Some(t.proxy_server())
    } else {
        ssrf::check(&parsed, cfg.allow_private_targets).await?;
        None
    };

    let req = ShotRequest { url: params.url, width, height, scale, timeout, proxy_server };

    let started = Instant::now();
    let png = state.chrome.render(req.clone()).await?;
    tracing::info!(
        url = %req.url,
        bytes = png.len(),
        ms = started.elapsed().as_millis(),
        "rendered"
    );

    Ok(([(header::CONTENT_TYPE, "image/png")], png))
}

const MAX_DIMENSION: u32 = 4096;
const SCALE_RANGE: RangeInclusive<f64> = 0.5..=3.0;

fn dimension(name: &str, value: Option<u32>, default: u32) -> Result<u32, ApiError> {
    match value {
        None => Ok(default),
        Some(v) if (1..=MAX_DIMENSION).contains(&v) => Ok(v),
        Some(v) => {
            Err(ApiError::BadRequest(format!("{name}={v} out of range 1..={MAX_DIMENSION}")))
        }
    }
}

fn scale(value: Option<f64>) -> Result<f64, ApiError> {
    match value {
        None => Ok(1.0),
        Some(v) if SCALE_RANGE.contains(&v) => Ok(v),
        Some(v) => Err(ApiError::BadRequest(format!(
            "scale={v} out of range {}..={}",
            SCALE_RANGE.start(),
            SCALE_RANGE.end()
        ))),
    }
}

/// Callers may shorten the render timeout, never extend it past the server's.
fn timeout(value: Option<u64>, max_secs: u64) -> Result<Duration, ApiError> {
    match value {
        None => Ok(Duration::from_secs(max_secs)),
        Some(v) if (1..=max_secs).contains(&v) => Ok(Duration::from_secs(v)),
        Some(v) => Err(ApiError::BadRequest(format!("timeout={v} out of range 1..={max_secs}"))),
    }
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
        .map_or_else(|| "unknown".to_string(), |k| k.id.clone());
    let tunnels = state.tunnels.clone();
    let cfg = state.config.tunnel_config();
    ws.on_upgrade(move |socket| tunnel::run(socket, tunnels, cfg, key_id))
}

// --- Admin: remote key management (admin-scoped) -----------------------------

#[derive(Debug, Deserialize)]
pub struct CreateKeyBody {
    pub label: String,
    #[serde(default)]
    pub role: Role,
}

/// Response to `POST /admin/keys`: the public info plus the one-time secret.
#[derive(Debug, Serialize)]
pub struct CreatedKey {
    #[serde(flatten)]
    pub info: KeyInfo,
    /// The plaintext key, returned exactly once — never retrievable again.
    pub secret: String,
}

#[derive(Debug, Deserialize)]
pub struct RoleBody {
    pub role: Role,
}

/// `POST /admin/keys {label, role}` → create a key, returning the secret once.
pub async fn admin_create_key(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateKeyBody>,
) -> Result<impl IntoResponse, ApiError> {
    let (info, secret) = state.keys.create(&body.label, body.role)?;
    tracing::info!(key_id = %info.id, role = %info.role, "admin created key");
    Ok(Json(CreatedKey { info, secret }))
}

/// `GET /admin/keys` → list keys (no secrets).
pub async fn admin_list_keys(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.keys.list()))
}

/// `POST /admin/keys/{id}/disable`. Also closes the key's open tunnels.
pub async fn admin_disable_key(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let info = state.keys.set_disabled(&id, true)?;
    close_revoked_tunnels(&state).await;
    Ok(Json(info))
}

pub async fn close_revoked_tunnels(state: &AppState) {
    state.tunnels.retain_owners(|key_id| state.keys.is_enabled(key_id)).await;
}

/// `POST /admin/keys/{id}/enable`.
pub async fn admin_enable_key(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.keys.set_disabled(&id, false)?))
}

/// `DELETE /admin/keys/{id}`.
pub async fn admin_delete_key(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state.keys.delete(&id)?;
    close_revoked_tunnels(&state).await;
    Ok(Json(serde_json::json!({"deleted": id})))
}

/// `POST /admin/keys/{id}/role {role}` → promote/demote (render⇄admin).
pub async fn admin_set_role(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<RoleBody>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(state.keys.set_role(&id, body.role)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_api_key_query_param() {
        let h = HeaderMap::new();
        assert_eq!(extract_key(&h, Some("url=x&api_key=secret")).as_deref(), Some("secret"));
    }

    #[test]
    fn extracts_camelcase_apikey_query_param() {
        let h = HeaderMap::new();
        assert_eq!(extract_key(&h, Some("url=x&apiKey=secret")).as_deref(), Some("secret"));
    }

    #[test]
    fn dimension_bounds() {
        assert_eq!(dimension("width", None, 1024).unwrap(), 1024);
        assert_eq!(dimension("width", Some(1), 1024).unwrap(), 1);
        assert_eq!(dimension("width", Some(4096), 1024).unwrap(), 4096);
        assert!(dimension("width", Some(0), 1024).is_err());
        assert!(dimension("width", Some(4097), 1024).is_err());
        assert!(dimension("height", Some(100_000), 768).is_err());
    }

    #[test]
    fn scale_bounds() {
        assert!((scale(None).unwrap() - 1.0).abs() < f64::EPSILON);
        assert!(scale(Some(0.5)).is_ok());
        assert!(scale(Some(3.0)).is_ok());
        for bad in [0.49, 3.01, 0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(scale(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn timeout_bounds() {
        assert_eq!(timeout(None, 60).unwrap(), Duration::from_secs(60));
        assert_eq!(timeout(Some(5), 60).unwrap(), Duration::from_secs(5));
        assert_eq!(timeout(Some(60), 60).unwrap(), Duration::from_secs(60));
        assert!(timeout(Some(0), 60).is_err());
        assert!(timeout(Some(61), 60).is_err());
        assert!(timeout(Some(86_400), 60).is_err());
    }

    #[test]
    fn out_of_range_is_400() {
        let err = dimension("width", Some(100_000), 1024).unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn health_fails_when_chrome_is_gone() {
        assert_eq!(health_status(true).0, StatusCode::OK);
        assert_eq!(health_status(false).0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn header_takes_precedence_over_query() {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", "fromheader".parse().unwrap());
        assert_eq!(extract_key(&h, Some("apiKey=fromquery")).as_deref(), Some("fromheader"));
    }
}
