//! Chrome/CDP screenshot engine — a single always-warm headless Chrome driven
//! over the DevTools Protocol. One Chrome process multiplexes many requests via
//! cheap, isolated pages (tabs); concurrency is bounded by a semaphore.

use std::sync::Arc;
use std::time::Duration;

use chromiumoxide::cdp::browser_protocol::emulation::SetDeviceMetricsOverrideParams;
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use chromiumoxide::page::ScreenshotParams;
use chromiumoxide::{Browser, BrowserConfig};
use futures::StreamExt;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use url::Url;

use crate::error::ApiError;

/// A single render request, already resolved against config defaults.
#[derive(Debug, Clone)]
pub struct ShotRequest {
    pub url: String,
    pub width: u32,
    pub height: u32,
    /// Device pixel ratio (DPR). 1.0 = standard, 2.0 = crisp "retina" 2x render.
    pub scale: f64,
    pub timeout: Duration,
}

/// Startup configuration for the Chrome engine.
#[derive(Debug, Clone)]
pub struct ChromeConfig {
    /// Path to (or name of) the Chrome/Chromium binary. `None` lets
    /// chromiumoxide auto-detect a system install.
    pub bin: Option<String>,
    /// Initial window size; per-request viewport overrides this.
    pub width: u32,
    pub height: u32,
    /// Max number of pages rendering concurrently in the one browser.
    pub max_concurrency: usize,
}

/// A long-lived headless Chrome instance plus the background task that drives
/// its CDP connection.
pub struct Chrome {
    browser: Browser,
    /// Drives the CDP websocket; kept alive for the process lifetime.
    #[allow(dead_code)]
    handler: JoinHandle<()>,
    /// Bounds how many pages render at once.
    permits: Arc<Semaphore>,
}

impl Chrome {
    /// Launch the browser and start its event-handler loop. Returns once Chrome
    /// is up and the DevTools connection is live.
    pub async fn start(cfg: &ChromeConfig) -> Result<Arc<Self>, ApiError> {
        let mut builder = BrowserConfig::builder()
            .window_size(cfg.width, cfg.height)
            // Run unsandboxed so Chromium starts as root in the container; this
            // emits `--no-sandbox --disable-setuid-sandbox` for us.
            .no_sandbox()
            // Container-friendly flags; headless is chromiumoxide's default.
            // NOTE: chromiumoxide takes bare arg keys (no leading `--`); it
            // stores the string verbatim and later prepends `--`, so passing
            // `--foo` here would emit the bogus flag `----foo` and be ignored.
            .arg("disable-dev-shm-usage")
            .arg("disable-gpu")
            .arg("hide-scrollbars")
            .arg("force-color-profile=srgb");
        if let Some(bin) = &cfg.bin {
            builder = builder.chrome_executable(bin);
        }
        let config =
            builder.build().map_err(|e| ApiError::Internal(format!("chrome config: {e}")))?;

        let (browser, mut handler) = Browser::launch(config)
            .await
            .map_err(|e| ApiError::Internal(format!("chrome launch: {e}")))?;

        // The handler stream must be polled continuously or CDP calls hang.
        let handler = tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if let Err(err) = event {
                    tracing::warn!(error = %err, "chrome handler event error");
                }
            }
            tracing::error!("chrome handler stream ended; browser connection lost");
        });

        tracing::info!(max_concurrency = cfg.max_concurrency, "chrome warm");
        Ok(Arc::new(Self {
            browser,
            handler,
            permits: Arc::new(Semaphore::new(cfg.max_concurrency)),
        }))
    }

    /// Render `req.url` to a PNG. Each call gets a fresh, isolated page that is
    /// always closed before returning.
    pub async fn render(&self, req: &ShotRequest) -> Result<Vec<u8>, ApiError> {
        let url =
            Url::parse(&req.url).map_err(|e| ApiError::BadRequest(format!("invalid url: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ApiError::BadRequest("only http(s) urls allowed".into()));
        }

        // Bound concurrency; a closed semaphore means we are shutting down.
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| ApiError::Internal("chrome engine closed".into()))?;

        (timeout(req.timeout, self.render_inner(&url, req)).await)
            .map_or(Err(ApiError::Timeout), |result| result)
    }

    async fn render_inner(&self, url: &Url, req: &ShotRequest) -> Result<Vec<u8>, ApiError> {
        let page = self
            .browser
            .new_page("about:blank")
            .await
            .map_err(|e| ApiError::Render(format!("new page: {e}")))?;

        // Render the page, capturing the result so we can always close the tab.
        let result = Self::shoot(&page, url, req).await;

        if let Err(err) = page.close().await {
            tracing::warn!(error = %err, "failed to close chrome page");
        }
        result
    }

    async fn shoot(
        page: &chromiumoxide::Page,
        url: &Url,
        req: &ShotRequest,
    ) -> Result<Vec<u8>, ApiError> {
        // Exact viewport via CDP device-metrics override (logical pixels).
        let metrics = SetDeviceMetricsOverrideParams::builder()
            .width(i64::from(req.width))
            .height(i64::from(req.height))
            .device_scale_factor(req.scale)
            .mobile(false)
            .build()
            .map_err(|e| ApiError::Internal(format!("device metrics: {e}")))?;
        page.execute(metrics).await.map_err(|e| ApiError::Render(format!("set viewport: {e}")))?;

        page.goto(url.as_str()).await.map_err(|e| ApiError::Render(format!("navigate: {e}")))?;
        page.wait_for_navigation().await.map_err(|e| ApiError::Render(format!("load: {e}")))?;

        let params = ScreenshotParams::builder().format(CaptureScreenshotFormat::Png).build();
        let png = page
            .screenshot(params)
            .await
            .map_err(|e| ApiError::Render(format!("screenshot: {e}")))?;
        if png.is_empty() {
            return Err(ApiError::Render("empty screenshot".into()));
        }
        Ok(png)
    }
}
