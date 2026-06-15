use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep, timeout};
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

/// Parameters shared by every worker in the pool.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub bin: String,
    pub width: u32,
    pub height: u32,
    pub ready_timeout: Duration,
}

#[derive(Deserialize)]
struct StatusResp {
    value: StatusVal,
}
#[derive(Deserialize)]
struct StatusVal {
    ready: bool,
}
#[derive(Deserialize)]
struct SessionResp {
    value: SessionVal,
}
#[derive(Deserialize)]
struct SessionVal {
    #[serde(rename = "sessionId")]
    session_id: String,
}
#[derive(Deserialize)]
struct ScreenshotResp {
    value: String,
}

/// A long-lived headless `servoshell` process with its WebDriver session.
/// The engine stays warm between requests; a shot is just navigate + screenshot.
pub struct Worker {
    // `kill_on_drop` is the backstop; `shutdown` kills + reaps explicitly so the
    // WebDriver port is freed before we respawn on it.
    child: Child,
    base: String,
    session: String,
    http: reqwest::Client,
    pub port: u16,
    cur_w: u32,
    cur_h: u32,
}

impl Worker {
    /// Launch a headless `servoshell` with a WebDriver server on `port`, wait for
    /// it to report ready, and open a session.
    pub async fn spawn(cfg: &WorkerConfig, port: u16) -> Result<Self, ApiError> {
        let child = Command::new(&cfg.bin)
            .arg("-z") // headless
            .arg(format!("--webdriver={port}"))
            .arg(format!("--window-size={}x{}", cfg.width, cfg.height))
            .arg("about:blank")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| ApiError::Internal(format!("spawn {}: {e}", cfg.bin)))?;

        let base = format!("http://127.0.0.1:{port}");
        let http =
            reqwest::Client::builder().build().map_err(|e| ApiError::Internal(e.to_string()))?;

        let mut worker = Self {
            child,
            base,
            session: String::new(),
            http,
            port,
            cur_w: cfg.width,
            cur_h: cfg.height,
        };
        worker.wait_ready(cfg.ready_timeout).await?;
        worker.session = worker.create_session().await?;
        tracing::info!(port, "servo worker ready");
        Ok(worker)
    }

    /// Kill the process and reap it, releasing the WebDriver port.
    async fn shutdown(mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }

    async fn wait_ready(&self, ready_timeout: Duration) -> Result<(), ApiError> {
        let deadline = Instant::now() + ready_timeout;
        loop {
            if let Ok(resp) = self.http.get(format!("{}/status", self.base)).send().await
                && let Ok(s) = resp.json::<StatusResp>().await
                && s.value.ready
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ApiError::Internal(format!(
                    "webdriver on :{} not ready in time",
                    self.port
                )));
            }
            sleep(Duration::from_millis(200)).await;
        }
    }

    async fn create_session(&self) -> Result<String, ApiError> {
        let resp = self
            .http
            .post(format!("{}/session", self.base))
            .json(&serde_json::json!({ "capabilities": { "alwaysMatch": {} } }))
            .send()
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let body: SessionResp = resp.json().await.map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(body.value.session_id)
    }

    /// Navigate to `url` and capture a screenshot as PNG bytes.
    async fn shot(&mut self, url: &Url, req: &ShotRequest) -> Result<Vec<u8>, ApiError> {
        // Servo's headless screenshot 500s when hit mid-paint; retry this many
        // times with growing backoff to let heavy pages settle.
        const SCREENSHOT_ATTEMPTS: u32 = 6;

        // Resize only when the viewport actually changed — a redundant Set Window
        // Rect on a heavy page forces an expensive reflow.
        if req.width != self.cur_w || req.height != self.cur_h {
            let resized = self
                .http
                .post(format!("{}/session/{}/window/rect", self.base, self.session))
                .json(
                    &serde_json::json!({ "x": 0, "y": 0, "width": req.width, "height": req.height }),
                )
                .timeout(Duration::from_secs(5))
                .send()
                .await;
            if matches!(&resized, Ok(r) if r.status().is_success()) {
                self.cur_w = req.width;
                self.cur_h = req.height;
            }
        }

        let nav = self
            .http
            .post(format!("{}/session/{}/url", self.base, self.session))
            .json(&serde_json::json!({ "url": url.as_str() }))
            .timeout(req.timeout)
            .send()
            .await
            .map_err(|e| map_reqwest_err(&e))?;
        if !nav.status().is_success() {
            return Err(ApiError::Render(format!("navigate failed: HTTP {}", nav.status())));
        }

        let mut last = ApiError::Render("screenshot not attempted".to_owned());
        for attempt in 0..SCREENSHOT_ATTEMPTS {
            if attempt > 0 {
                sleep(Duration::from_millis(500 * u64::from(attempt))).await;
            }
            let shot = match self
                .http
                .get(format!("{}/session/{}/screenshot", self.base, self.session))
                .timeout(req.timeout)
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    last = map_reqwest_err(&e);
                    continue;
                }
            };
            if !shot.status().is_success() {
                last = ApiError::Render(format!("screenshot failed: HTTP {}", shot.status()));
                continue;
            }
            let body: ScreenshotResp =
                shot.json().await.map_err(|e| ApiError::Render(e.to_string()))?;
            let bytes = B64
                .decode(body.value.as_bytes())
                .map_err(|e| ApiError::Render(format!("decode screenshot: {e}")))?;
            if bytes.is_empty() {
                last = ApiError::Render("empty screenshot".to_owned());
                continue;
            }
            return Ok(bytes);
        }
        Err(last)
    }
}

fn map_reqwest_err(e: &reqwest::Error) -> ApiError {
    if e.is_timeout() { ApiError::Timeout } else { ApiError::Render(e.to_string()) }
}

/// A pool of always-warm Servo workers. Requests check a worker out, render, and
/// return it; a worker that errors is torn down and respawned on its port so the
/// pool self-heals without leaking the slot.
pub struct Pool {
    tx: async_channel::Sender<Worker>,
    rx: async_channel::Receiver<Worker>,
    cfg: WorkerConfig,
    checkout_timeout: Duration,
}

impl Pool {
    /// Spawn `size` warm workers (concurrently) on `base_port..base_port+size`.
    pub async fn start(
        cfg: WorkerConfig,
        size: usize,
        base_port: u16,
        checkout_timeout: Duration,
    ) -> Result<Arc<Self>, ApiError> {
        let (tx, rx) = async_channel::bounded(size);

        let mut handles = Vec::with_capacity(size);
        for i in 0..size {
            let cfg = cfg.clone();
            let port = base_port + i as u16;
            handles.push(tokio::spawn(async move { Worker::spawn(&cfg, port).await }));
        }
        for handle in handles {
            let worker = handle.await.map_err(|e| ApiError::Internal(e.to_string()))??;
            tx.send(worker).await.map_err(|e| ApiError::Internal(e.to_string()))?;
        }

        tracing::info!(size, base_port, "servo pool warm");
        Ok(Arc::new(Self { tx, rx, cfg, checkout_timeout }))
    }

    /// Render `req` on a warm worker. Validates the URL before taking a worker so
    /// client errors never recycle a healthy engine.
    pub async fn render(&self, req: &ShotRequest) -> Result<Vec<u8>, ApiError> {
        let url =
            Url::parse(&req.url).map_err(|e| ApiError::BadRequest(format!("invalid url: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ApiError::BadRequest("only http(s) urls are allowed".to_owned()));
        }

        let worker = match timeout(self.checkout_timeout, self.rx.recv()).await {
            Ok(Ok(worker)) => worker,
            Ok(Err(_)) => return Err(ApiError::Internal("worker pool closed".to_owned())),
            Err(_) => {
                return Err(ApiError::Internal("no warm worker available (pool busy)".to_owned()));
            }
        };

        // Hold the checked-out worker in a guard so that *any* early exit from
        // here on — an error, or the request future being dropped when the
        // client disconnects mid-render — recycles the slot instead of leaking
        // it. Without this, a cancelled slow render permanently drains the pool.
        let mut guard =
            WorkerGuard { worker: Some(worker), tx: self.tx.clone(), cfg: self.cfg.clone() };
        let worker = guard.worker.as_mut().expect("worker present");
        let port = worker.port;

        match worker.shot(&url, req).await {
            Ok(bytes) => {
                // Healthy engine: defuse the guard and return it to the pool as-is.
                let worker = guard.worker.take().expect("worker present");
                let _ = self.tx.send(worker).await;
                Ok(bytes)
            }
            Err(err) => {
                // The session may be in an unknown state; let the guard recycle it.
                tracing::warn!(port, error = %err, "worker shot failed; recycling");
                Err(err)
            }
        }
    }
}

/// RAII handle for a checked-out worker. If still holding the worker when
/// dropped (error or cancellation), it recycles the slot on a detached task:
/// the possibly-wedged engine is killed and a fresh one respawned on its port,
/// so the pool self-heals and never leaks a slot.
struct WorkerGuard {
    worker: Option<Worker>,
    tx: async_channel::Sender<Worker>,
    cfg: WorkerConfig,
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        let Some(worker) = self.worker.take() else { return };
        let tx = self.tx.clone();
        let cfg = self.cfg.clone();
        let port = worker.port;
        tokio::spawn(async move {
            worker.shutdown().await;
            // Give the OS a moment to release the WebDriver port.
            sleep(Duration::from_millis(300)).await;
            match Worker::spawn(&cfg, port).await {
                Ok(fresh) => {
                    let _ = tx.send(fresh).await;
                }
                Err(err) => {
                    tracing::error!(port, error = %err, "respawn after recycle failed; pool reduced");
                }
            }
        });
    }
}
