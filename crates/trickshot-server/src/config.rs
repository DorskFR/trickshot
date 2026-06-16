use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::keys::KeysCmd;

/// Top-level CLI: run the server (default) or manage API keys.
#[derive(Debug, Parser)]
#[command(name = "trickshot", about = "Fast screenshot-as-API backed by headless Chrome (CDP)")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,

    /// Server flags, used when no subcommand is given (the default `serve`).
    #[command(flatten)]
    pub serve: Config,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Run the HTTP server (default).
    Serve(Config),
    /// Manage API keys against `TRICKSHOT_KEYS_FILE`.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
}

/// Runtime configuration, sourced from CLI flags or environment variables.
#[derive(Debug, Clone, Parser)]
#[command(name = "trickshot", about = "Fast screenshot-as-API backed by headless Chrome (CDP)")]
pub struct Config {
    /// Address:port to bind the HTTP server.
    #[arg(long, env = "TRICKSHOT_BIND", default_value = "0.0.0.0:8900")]
    pub bind: String,

    /// Default viewport width in logical pixels; override per-request with `w`.
    #[arg(long, env = "TRICKSHOT_DEFAULT_WIDTH", default_value_t = 1024)]
    pub default_width: u32,

    /// Default viewport height in logical pixels.
    #[arg(long, env = "TRICKSHOT_DEFAULT_HEIGHT", default_value_t = 768)]
    pub default_height: u32,

    /// Per-shot timeout (navigate + screenshot), in seconds.
    #[arg(long, env = "TRICKSHOT_RENDER_TIMEOUT_SECS", default_value_t = 60)]
    pub render_timeout_secs: u64,

    /// Path to (or name of) the Chrome/Chromium binary backing `/shot`.
    /// Unset lets chromiumoxide auto-detect a system install.
    #[arg(long, env = "TRICKSHOT_CHROME_BIN")]
    pub chrome_bin: Option<String>,

    /// Max pages rendering concurrently in the one warm Chrome. One process,
    /// many cheap tabs.
    #[arg(long, env = "TRICKSHOT_CHROME_MAX_CONCURRENCY", default_value_t = 4)]
    pub chrome_max_concurrency: usize,

    /// File-backed API-key store (JSON). `/shot` requires a valid key; the
    /// `trickshot keys …` CLI manages this same file.
    #[arg(long, env = "TRICKSHOT_KEYS_FILE", default_value = "/data/keys.json")]
    pub keys_file: PathBuf,

    /// Allow rendering targets that resolve to private/reserved IP ranges
    /// (RFC1918, loopback, link-local incl. cloud metadata). Default deny.
    #[arg(long, env = "TRICKSHOT_ALLOW_PRIVATE_TARGETS", default_value_t = false)]
    pub allow_private_targets: bool,

    /// Max concurrent reverse tunnels (`/tunnel`); further upgrades are
    /// rejected. Each tunnel binds one loopback SOCKS5 listener.
    #[arg(long, env = "TRICKSHOT_MAX_TUNNELS", default_value_t = 16)]
    pub max_tunnels: usize,

    /// Drop a reverse tunnel after this many seconds with no WebSocket traffic.
    #[arg(long, env = "TRICKSHOT_TUNNEL_IDLE_SECS", default_value_t = 300)]
    pub tunnel_idle_secs: u64,
}

impl Config {
    /// Lifecycle limits for the reverse-tunnel subsystem.
    pub const fn tunnel_config(&self) -> crate::tunnel::TunnelConfig {
        crate::tunnel::TunnelConfig {
            max_tunnels: self.max_tunnels,
            idle_timeout: std::time::Duration::from_secs(self.tunnel_idle_secs),
        }
    }
}
