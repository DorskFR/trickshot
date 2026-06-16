use clap::Parser;

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
}
