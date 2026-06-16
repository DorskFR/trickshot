//! trickshot — fast screenshot-as-API backed by an always-warm headless Chrome
//! driven over the DevTools Protocol (CDP).

mod chrome;
mod config;
mod error;
mod handlers;
mod keys;
mod ssrf;
mod tunnel;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use clap::Parser;
use notify::event::EventKind;
use notify::{RecursiveMode, Watcher};
use tower_http::trace::TraceLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use crate::chrome::{Chrome, ChromeConfig};
use crate::config::{Cli, Cmd, Config};
use crate::keys::{KeyStore, Role};
use crate::tunnel::TunnelRegistry;

/// Shared application state handed to every handler.
pub struct AppState {
    pub config: Config,
    pub chrome: Arc<Chrome>,
    pub keys: Arc<KeyStore>,
    pub tunnels: Arc<TunnelRegistry>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer())
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Keys { cmd }) => {
            // Key management runs without booting Chrome. Resolve the file from
            // the same flag/env the server uses.
            keys::run(&cmd, &cli.serve.keys_file)?;
            Ok(())
        }
        Some(Cmd::Serve(config)) => serve(config).await,
        None => serve(cli.serve).await,
    }
}

async fn serve(config: Config) -> anyhow::Result<()> {
    tracing::info!(bind = %config.bind, "starting trickshot");

    let keys = setup_keys(&config)?;

    let chrome_cfg = ChromeConfig {
        bin: config.chrome_bin.clone(),
        width: config.default_width,
        height: config.default_height,
        max_concurrency: config.chrome_max_concurrency,
    };
    let chrome = Chrome::start(&chrome_cfg).await?;

    let bind = config.bind.clone();
    let tunnels = TunnelRegistry::new();
    let state = Arc::new(AppState { config, chrome, keys, tunnels });

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(addr = %bind, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Load the key store, bootstrap the first admin key if needed, and start its
/// hot-reload tasks.
fn setup_keys(config: &Config) -> anyhow::Result<Arc<KeyStore>> {
    let keys = KeyStore::load(config.keys_file.clone())?;
    bootstrap_admin(&keys, config)?;
    if !keys.has_enabled_keys() {
        tracing::warn!(
            path = %config.keys_file.display(),
            "no enabled api keys — /shot will reject every request"
        );
    }
    spawn_key_reloaders(keys.clone());
    Ok(keys)
}

/// Ensure at least one enabled `admin` key exists so remote `ts` management
/// works with no `kubectl exec`. If `TRICKSHOT_BOOTSTRAP_ADMIN_KEY` is set, seed
/// it; otherwise mint one and log a one-time secret. No-op once an admin key
/// already exists.
fn bootstrap_admin(keys: &Arc<KeyStore>, config: &Config) -> anyhow::Result<()> {
    if keys.has_admin_key() {
        return Ok(());
    }
    if let Some(secret) = &config.bootstrap_admin_key {
        let info = keys.create_with_secret("bootstrap", Role::Admin, secret)?;
        tracing::info!(key_id = %info.id, "seeded bootstrap admin key from TRICKSHOT_BOOTSTRAP_ADMIN_KEY");
    } else {
        let (info, secret) = keys.create("bootstrap", Role::Admin)?;
        tracing::warn!(
            key_id = %info.id,
            "no admin key found and TRICKSHOT_BOOTSTRAP_ADMIN_KEY unset — minted a one-time \
             bootstrap admin key. Save this secret now (shown once): {secret}"
        );
    }
    Ok(())
}

/// Whether a notify event should trigger a key-store reload: it must touch the
/// keys file itself (we watch the parent dir, so unrelated siblings churn too)
/// and be a create/modify/remove — access/metadata-only noise is ignored.
fn is_relevant_key_event(event: &notify::Event, keys_path: &std::path::Path) -> bool {
    let touches_keys_file = event.paths.iter().any(|p| p == keys_path);
    let meaningful =
        matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_));
    touches_keys_file && meaningful
}

/// Hot-reload the key store on SIGHUP and on file modification, so the CLI can
/// add/revoke keys without restarting the server.
fn spawn_key_reloaders(keys: Arc<KeyStore>) {
    // SIGHUP → reload.
    let sighup_keys = keys.clone();
    tokio::spawn(async move {
        let mut sig = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "cannot install SIGHUP handler; reload via signal disabled");
                return;
            }
        };
        while sig.recv().await.is_some() {
            if let Err(e) = sighup_keys.reload() {
                tracing::warn!(error = %e, "key reload (SIGHUP) failed");
            }
        }
    });

    // File-modification watch (best-effort) → reload via a debounced channel.
    // We watch the parent directory (so rename-into-place / atomic saves are
    // seen) but only forward events that touch the keys file itself with a
    // meaningful kind — k8s-mounted dirs emit a steady stream of unrelated fs
    // events that would otherwise drive a reload every ~200ms.
    let keys_path = keys.path().to_path_buf();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res
            && is_relevant_key_event(&event, &keys_path)
        {
            let _ = tx.send(());
        }
    });
    match watcher {
        Ok(mut watcher) => {
            // Watch the parent dir so rename-into-place (atomic save) is seen.
            let target = keys
                .path()
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map_or_else(|| keys.path().to_path_buf(), std::path::Path::to_path_buf);
            if let Err(e) = watcher.watch(&target, RecursiveMode::NonRecursive) {
                tracing::warn!(error = %e, "cannot watch keys file; file-change reload disabled");
                return;
            }
            tokio::spawn(async move {
                // Keep the watcher alive for the task's lifetime.
                let _watcher = watcher;
                while rx.recv().await.is_some() {
                    // Debounce a burst of fs events.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    while rx.try_recv().is_ok() {}
                    if let Err(e) = keys.reload() {
                        tracing::warn!(error = %e, "key reload (watch) failed");
                    }
                }
            });
        }
        Err(e) => {
            tracing::warn!(error = %e, "cannot create file watcher; file-change reload disabled");
        }
    }
}

fn build_router(state: Arc<AppState>) -> Router {
    use axum::routing::{delete, post};

    let authed = Router::new()
        .route("/shot", get(handlers::shot))
        .route("/tunnel", get(handlers::tunnel))
        // Auth guard on /shot and /tunnel; /health stays open.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            handlers::require_api_key,
        ));

    // Admin key-management API: require_api_key (401) then require_admin (403).
    let admin = Router::new()
        .route("/admin/keys", post(handlers::admin_create_key).get(handlers::admin_list_keys))
        .route("/admin/keys/{id}", delete(handlers::admin_delete_key))
        .route("/admin/keys/{id}/disable", post(handlers::admin_disable_key))
        .route("/admin/keys/{id}/enable", post(handlers::admin_enable_key))
        .route("/admin/keys/{id}/role", post(handlers::admin_set_role))
        .route_layer(axum::middleware::from_fn(handlers::require_admin))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            handlers::require_api_key,
        ));

    Router::new()
        .route("/health", get(handlers::health))
        .merge(authed)
        .merge(admin)
        // Per-request access log; enable with `tower_http=debug` in RUST_LOG.
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
