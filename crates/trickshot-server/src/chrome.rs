//! Chrome/CDP screenshot engine — a single always-warm headless Chrome driven
//! over the DevTools Protocol. One Chrome process multiplexes many requests via
//! cheap, isolated pages (tabs); concurrency is bounded by a semaphore.

use std::sync::Arc;
use std::time::Duration;

use chromiumoxide::cdp::browser_protocol::emulation::SetDeviceMetricsOverrideParams;
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use chromiumoxide::cdp::browser_protocol::target::{
    CreateBrowserContextParams, CreateTargetParams,
};
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
    /// Reverse-tunnel proxy (e.g. `socks5://127.0.0.1:NNNN`) for this shot.
    /// `None` routes through the egress guard.
    pub proxy_server: Option<String>,
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
    /// Keep Chromium's sandbox on. Off only where user namespaces are
    /// unavailable (e.g. a host with AppArmor userns restrictions).
    pub sandbox: bool,
    /// Egress guard proxy every non-tunnel connection goes through.
    pub egress_proxy: String,
}

/// Chrome skips the proxy for loopback and link-local targets unless told
/// otherwise; this removes that implicit bypass.
const PROXY_BYPASS: &str = "<-loopback>";

/// A long-lived headless Chrome instance plus the background task that drives
/// its CDP connection.
pub struct Chrome {
    browser: Browser,
    /// Drives the CDP websocket; kept alive for the process lifetime.
    #[allow(dead_code)]
    handler: JoinHandle<()>,
    /// Bounds how many pages render at once.
    permits: Arc<Semaphore>,
    egress_proxy: String,
}

impl Chrome {
    /// Launch the browser and start its event-handler loop. Returns once Chrome
    /// is up and the DevTools connection is live.
    pub async fn start(cfg: &ChromeConfig) -> Result<Arc<Self>, ApiError> {
        // chromiumoxide prepends `--` to each arg itself.
        let mut builder = BrowserConfig::builder()
            .window_size(cfg.width, cfg.height)
            .arg("disable-dev-shm-usage")
            .arg("disable-gpu")
            .arg("hide-scrollbars")
            .arg("force-color-profile=srgb")
            .arg(("proxy-server", cfg.egress_proxy.as_str()))
            .arg(("proxy-bypass-list", PROXY_BYPASS))
            .arg(("force-webrtc-ip-handling-policy", "disable_non_proxied_udp"));
        if !cfg.sandbox {
            builder = builder.no_sandbox();
        }
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

        tracing::info!(max_concurrency = cfg.max_concurrency, sandbox = cfg.sandbox, "chrome warm");
        Ok(Arc::new(Self {
            browser,
            handler,
            permits: Arc::new(Semaphore::new(cfg.max_concurrency)),
            egress_proxy: cfg.egress_proxy.clone(),
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

        (timeout(req.timeout, self.render_inner(&url, req)).await).unwrap_or(Err(ApiError::Timeout))
    }

    async fn render_inner(&self, url: &Url, req: &ShotRequest) -> Result<Vec<u8>, ApiError> {
        // One isolated context per shot, always disposed before returning. All
        // of its traffic, DNS included (SOCKS5 resolves at the proxy), goes
        // through the tunnel or the egress guard.
        let proxy = req.proxy_server.as_deref().unwrap_or(&self.egress_proxy);
        let ctx_params = CreateBrowserContextParams::builder()
            .proxy_server(proxy)
            .proxy_bypass_list(PROXY_BYPASS)
            .build();
        let ctx_id = self
            .browser
            .create_browser_context(ctx_params)
            .await
            .map_err(|e| ApiError::Render(format!("create browser context: {e}")))?;

        let target = CreateTargetParams::builder()
            .url("about:blank")
            .browser_context_id(ctx_id.clone())
            .build()
            .map_err(|e| ApiError::Internal(format!("create target params: {e}")))?;
        let page = match self.browser.new_page(target).await {
            Ok(page) => page,
            Err(e) => {
                let _ = self.browser.dispose_browser_context(ctx_id).await;
                return Err(ApiError::Render(format!("new page: {e}")));
            }
        };

        // Render the page, capturing the result so we can always tear down.
        let result = Self::shoot(&page, url, req).await;

        if let Err(err) = page.close().await {
            tracing::warn!(error = %err, "failed to close chrome page");
        }
        if let Err(err) = self.browser.dispose_browser_context(ctx_id).await {
            tracing::warn!(error = %err, "failed to dispose browser context");
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

#[cfg(test)]
mod e2e {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::egress::{EgressGuard, Policy};

    const INTERNAL: [u8; 4] = [127, 0, 0, 2];

    async fn http_server(
        ip: [u8; 4],
        respond: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> SocketAddr {
        let l = TcpListener::bind((IpAddr::from(ip), 0)).await.unwrap();
        let addr = l.local_addr().unwrap();
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let respond = respond.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let _ = s.write_all(respond(&path).as_bytes()).await;
                });
            }
        });
        addr
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    #[ignore = "needs a Chromium binary in TRICKSHOT_TEST_CHROME"]
    async fn guard_blocks_redirects_subresources_and_workers() {
        let bin = std::env::var("TRICKSHOT_TEST_CHROME").expect("TRICKSHOT_TEST_CHROME");
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let internal = http_server(INTERNAL, move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            ok("internal-secret")
        })
        .await;
        let target = format!("http://{internal}/");
        let public = http_server([127, 0, 0, 1], move |path| match path {
            "/redirect" => format!(
                "HTTP/1.1 302 Found\r\nlocation: {target}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            ),
            "/worker.js" => format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/javascript\r\nconnection: close\r\n\r\nfetch('{target}w').catch(()=>{{}});"
            ),
            _ => ok(&format!(
                "<iframe src='{target}f'></iframe><img src='{target}i'>\
                 <script>fetch('{target}x').catch(()=>{{}});new Worker('/worker.js');</script>"
            )),
        })
        .await;

        let block = Arc::new(AtomicBool::new(false));
        let flag = block.clone();
        let policy: Policy =
            Arc::new(move |ip| flag.load(Ordering::SeqCst) && ip == IpAddr::from(INTERNAL));
        let guard = EgressGuard::start(policy).await.unwrap();
        let chrome = Chrome::start(&ChromeConfig {
            bin: Some(bin),
            width: 800,
            height: 600,
            max_concurrency: 1,
            sandbox: std::env::var("TRICKSHOT_TEST_CHROME_SANDBOX").is_ok(),
            egress_proxy: guard.proxy_server(),
        })
        .await
        .unwrap();

        let render_all = || async {
            hits.store(0, Ordering::SeqCst);
            for path in ["/redirect", "/page"] {
                let req = ShotRequest {
                    url: format!("http://{public}{path}"),
                    width: 800,
                    height: 600,
                    scale: 1.0,
                    timeout: Duration::from_secs(20),
                    proxy_server: None,
                };
                let res = chrome.render(&req).await;
                eprintln!("{path}: {:?}", res.map(|png| png.len()));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            hits.load(Ordering::SeqCst)
        };

        let control = render_all().await;
        eprintln!("internal hits without block: {control}");
        assert!(control >= 4, "control run should reach the internal host, got {control}");

        block.store(true, Ordering::SeqCst);
        let blocked = render_all().await;
        eprintln!("internal hits with block: {blocked}");
        assert_eq!(blocked, 0);
    }
}
