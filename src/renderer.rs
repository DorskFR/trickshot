use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;

use crate::error::ApiError;

/// A single render request, already resolved against config defaults.
#[derive(Debug, Clone)]
pub struct ShotRequest {
    pub url: String,
    pub width: u32,
    pub height: u32,
    pub device_pixel_ratio: Option<f32>,
    pub timeout: Duration,
}

/// Renders pages to PNG bytes by driving the `servoshell` headless binary as a
/// subprocess (one cold process per shot).
///
/// This is the phase-1 engine: simple and correct, but pays Servo's process
/// startup on every request. The intended phase-2 swap is an embedded, warm
/// renderer built on the `servo` crate — keep that seam in mind: the HTTP layer
/// only depends on `render() -> Result<Vec<u8>, ApiError>`, so a warmer engine
/// can drop in behind the same shape.
pub struct ServoRenderer {
    bin: String,
}

impl ServoRenderer {
    pub const fn new(bin: String) -> Self {
        Self { bin }
    }

    /// Render `req` to PNG bytes. Validates the URL scheme, runs `servoshell`
    /// headless with a hard timeout, and returns the produced image.
    pub async fn render(&self, req: &ShotRequest) -> Result<Vec<u8>, ApiError> {
        let parsed =
            Url::parse(&req.url).map_err(|e| ApiError::BadRequest(format!("invalid url: {e}")))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(ApiError::BadRequest("only http(s) urls are allowed".to_owned()));
        }

        let out = std::env::temp_dir().join(format!("trickshot-{}.png", Uuid::new_v4()));

        let mut cmd = Command::new(&self.bin);
        cmd.arg("-z") // headless
            .arg("-x") // exit once rendered
            .arg(format!("--window-size={}x{}", req.width, req.height));
        if let Some(dpr) = req.device_pixel_ratio {
            cmd.arg(format!("--device-pixel-ratio={dpr}"));
        }
        cmd.arg("-o")
            .arg(&out)
            .arg(parsed.as_str())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let child =
            cmd.spawn().map_err(|e| ApiError::Internal(format!("spawn {}: {e}", self.bin)))?;

        let Ok(waited) = timeout(req.timeout, child.wait_with_output()).await else {
            let _ = tokio::fs::remove_file(&out).await;
            return Err(ApiError::Timeout);
        };
        let output = waited.map_err(|e| ApiError::Internal(e.to_string()))?;

        if !output.status.success() {
            let _ = tokio::fs::remove_file(&out).await;
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail = stderr.lines().last().unwrap_or("").trim();
            return Err(ApiError::Render(format!("servoshell exited {}: {tail}", output.status)));
        }

        let bytes = tokio::fs::read(&out)
            .await
            .map_err(|e| ApiError::Render(format!("read output image: {e}")))?;
        let _ = tokio::fs::remove_file(&out).await;

        if bytes.is_empty() {
            return Err(ApiError::Render("servoshell produced an empty image".to_owned()));
        }
        Ok(bytes)
    }
}
