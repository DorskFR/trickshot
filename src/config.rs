use clap::Parser;

/// Runtime configuration, sourced from CLI flags or environment variables.
#[derive(Debug, Clone, Parser)]
#[command(name = "trickshot", about = "Fast screenshot-as-API backed by Servo")]
pub struct Config {
    /// Address:port to bind the HTTP server.
    #[arg(long, env = "TRICKSHOT_BIND", default_value = "0.0.0.0:8900")]
    pub bind: String,

    /// Path to (or name of) the `servoshell` binary the workers run.
    #[arg(long, env = "TRICKSHOT_SERVO_BIN", default_value = "servoshell")]
    pub servo_bin: String,

    /// Number of always-warm Servo workers. Each holds a live engine
    /// (~300-800MB), so this bounds both concurrency and memory.
    #[arg(long, env = "TRICKSHOT_POOL_SIZE", default_value_t = 2)]
    pub pool_size: usize,

    /// First WebDriver port; workers use base_port..base_port+pool_size.
    #[arg(long, env = "TRICKSHOT_WEBDRIVER_BASE_PORT", default_value_t = 7010)]
    pub webdriver_base_port: u16,

    /// Default viewport width in logical pixels. Servo's headless screenshot
    /// degrades sharply above ~1024px wide (slow + flaky), so the default stays
    /// conservative; override per-request with `w` if you accept the trade-off.
    #[arg(long, env = "TRICKSHOT_DEFAULT_WIDTH", default_value_t = 1024)]
    pub default_width: u32,

    /// Default viewport height in logical pixels.
    #[arg(long, env = "TRICKSHOT_DEFAULT_HEIGHT", default_value_t = 768)]
    pub default_height: u32,

    /// Per-shot timeout (navigate + screenshot), in seconds.
    #[arg(long, env = "TRICKSHOT_RENDER_TIMEOUT_SECS", default_value_t = 60)]
    pub render_timeout_secs: u64,

    /// How long a worker has to come up at startup, in seconds.
    #[arg(long, env = "TRICKSHOT_WORKER_READY_TIMEOUT_SECS", default_value_t = 30)]
    pub worker_ready_timeout_secs: u64,

    /// How long a request waits for a free warm worker, in seconds.
    #[arg(long, env = "TRICKSHOT_CHECKOUT_TIMEOUT_SECS", default_value_t = 30)]
    pub checkout_timeout_secs: u64,

    /// Path to (or name of) the Chrome/Chromium binary backing `/shot2`.
    /// Unset lets chromiumoxide auto-detect a system install.
    #[arg(long, env = "TRICKSHOT_CHROME_BIN")]
    pub chrome_bin: Option<String>,

    /// Max pages rendering concurrently in the one warm Chrome (`/shot2`).
    /// One process, many cheap tabs, so this can exceed `pool_size`.
    #[arg(long, env = "TRICKSHOT_CHROME_MAX_CONCURRENCY", default_value_t = 4)]
    pub chrome_max_concurrency: usize,
}
