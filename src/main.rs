//! trickshot — fast screenshot-as-API backed by a pool of always-warm Servo
//! engines driven over WebDriver.

mod chrome;
mod config;
mod engine;
mod error;
mod handlers;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use clap::Parser;
use tower_http::trace::TraceLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use crate::chrome::{Chrome, ChromeConfig};
use crate::config::Config;
use crate::engine::{Pool, WorkerConfig};

/// Shared application state handed to every handler.
pub struct AppState {
    pub config: Config,
    pub pool: Arc<Pool>,
    pub chrome: Arc<Chrome>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer())
        .init();

    let config = Config::parse();
    tracing::info!(bind = %config.bind, servo = %config.servo_bin, pool = config.pool_size, "starting trickshot");

    let worker_cfg = WorkerConfig {
        bin: config.servo_bin.clone(),
        width: config.default_width,
        height: config.default_height,
        ready_timeout: Duration::from_secs(config.worker_ready_timeout_secs),
    };
    let pool = Pool::start(
        worker_cfg,
        config.pool_size,
        config.webdriver_base_port,
        Duration::from_secs(config.checkout_timeout_secs),
    )
    .await?;

    let chrome_cfg = ChromeConfig {
        bin: config.chrome_bin.clone(),
        width: config.default_width,
        height: config.default_height,
        max_concurrency: config.chrome_max_concurrency,
    };
    let chrome = Chrome::start(&chrome_cfg).await?;

    let bind = config.bind.clone();
    let state = Arc::new(AppState { config, pool, chrome });

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(addr = %bind, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/shot", get(handlers::shot))
        .route("/shot2", get(handlers::shot2))
        // Per-request access log; enable with `tower_http=debug` in RUST_LOG.
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
