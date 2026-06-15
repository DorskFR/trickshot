//! trickshot — fast screenshot-as-API: render a URL to an image and return it.

mod config;
mod error;
mod handlers;
mod renderer;

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use clap::Parser;
use tokio::sync::Semaphore;
use tower_http::trace::TraceLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use crate::config::Config;
use crate::renderer::ServoRenderer;

/// Shared application state handed to every handler.
pub struct AppState {
    pub config: Config,
    pub renderer: ServoRenderer,
    pub render_slots: Arc<Semaphore>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer())
        .init();

    let config = Config::parse();
    tracing::info!(bind = %config.bind, servo = %config.servo_bin, "starting trickshot");

    let render_slots = Arc::new(Semaphore::new(config.max_concurrency));
    let renderer = ServoRenderer::new(config.servo_bin.clone());
    let bind = config.bind.clone();
    let state = Arc::new(AppState { config, renderer, render_slots });

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
        // Per-request access log; enable with `tower_http=debug` in RUST_LOG.
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
