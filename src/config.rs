use clap::Parser;

/// Runtime configuration, sourced from CLI flags or environment variables.
#[derive(Debug, Clone, Parser)]
#[command(name = "trickshot", about = "Fast screenshot-as-API backed by Servo")]
pub struct Config {
    /// Address:port to bind the HTTP server.
    #[arg(long, env = "TRICKSHOT_BIND", default_value = "0.0.0.0:8900")]
    pub bind: String,

    /// Path to (or name of) the `servoshell` binary used to render pages.
    #[arg(long, env = "TRICKSHOT_SERVO_BIN", default_value = "servoshell")]
    pub servo_bin: String,

    /// Default viewport width in logical pixels.
    #[arg(long, env = "TRICKSHOT_DEFAULT_WIDTH", default_value_t = 1280)]
    pub default_width: u32,

    /// Default viewport height in logical pixels.
    #[arg(long, env = "TRICKSHOT_DEFAULT_HEIGHT", default_value_t = 900)]
    pub default_height: u32,

    /// Hard timeout for a single render, in seconds.
    #[arg(long, env = "TRICKSHOT_RENDER_TIMEOUT_SECS", default_value_t = 60)]
    pub render_timeout_secs: u64,

    /// Maximum number of concurrent renders. Each Servo process is memory-hungry
    /// (~300-800MB), so this caps memory pressure rather than CPU.
    #[arg(long, env = "TRICKSHOT_MAX_CONCURRENCY", default_value_t = 2)]
    pub max_concurrency: usize,
}
