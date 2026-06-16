//! `ts` — the trickshot CLI client.
//!
//! Three modes in one binary:
//!
//! * **plain shot** — `ts <url>`: `GET ${server}/shot?url=…` with the API key,
//!   streaming the `image/png` body to a file (or stdout);
//! * **`--tunnel`** — open `wss://${server}/tunnel`, act as the reverse-tunnel
//!   agent (TRI-5): dial each `connect host:port` the server frames over the WS
//!   on the *caller's* network and pipe bytes both ways, then take the shot with
//!   `&tunnel=<id>` so private/VPN hostnames resolve locally;
//! * **admin** — `ts auth/servers/default` manage a local config at
//!   `~/.config/trickshot/config.json` (mirroring the `yt` CLI), and `ts keys …`
//!   drive the server's `/admin/keys…` endpoints with an admin-scoped key.
//!
//! Credentials resolve from env (`TRICKSHOT_URL`/`TRICKSHOT_API_KEY`, which take
//! precedence) else the config's selected/`--server` entry.
//!
//! Lean by design: reqwest+rustls + tokio-tungstenite + clap, no chromiumoxide.

mod admin;
mod config;
mod tunnel;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::config::resolve;

/// trickshot client: take a screenshot, tunnel, or manage keys remotely.
#[derive(Debug, Parser)]
#[command(name = "ts", version, about, long_about = None)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    /// Use a named server from the config (env vars still take precedence).
    #[arg(long, global = true)]
    pub server: Option<String>,

    #[command(subcommand)]
    pub cmd: Option<Cmd>,

    /// Plain-shot args, used when no subcommand is given (`ts <url> …`).
    #[command(flatten)]
    pub shot: ShotArgs,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Save credentials to ~/.config/trickshot/config.json.
    Auth {
        /// trickshot server base URL, e.g. https://shot.example.com.
        url: String,
        /// API key (admin key for `ts keys …`); "-" reads stdin.
        key: String,
        /// Server name; defaults to "default".
        name: Option<String>,
    },
    /// List configured servers (* marks the default).
    Servers,
    /// Set the default server.
    Default {
        /// Server name.
        name: String,
    },
    /// Manage API keys remotely via the admin endpoints (needs an admin key).
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
}

#[derive(Debug, Subcommand)]
pub enum KeysCmd {
    /// Create a key; prints the plaintext secret once.
    Create {
        #[arg(long)]
        label: String,
        /// Permission scope.
        #[arg(long, default_value = "render")]
        role: String,
    },
    /// List keys (id, label, role, created, status) — never the secret.
    List,
    /// Disable a key by id.
    Disable { id: String },
    /// Enable a previously disabled key by id.
    Enable { id: String },
    /// Delete a key by id.
    Delete { id: String },
    /// Promote a key to the admin role.
    Promote { id: String },
    /// Demote a key to the render role.
    Demote { id: String },
}

/// Plain-shot arguments. Server/key are optional here because they may come
/// from env or the config file (resolved in [`run_shot`]).
#[derive(Debug, clap::Args)]
pub struct ShotArgs {
    /// Page to screenshot.
    pub url: Option<String>,

    /// trickshot server base URL (overrides config/env precedence is in env).
    #[arg(long, env = "TRICKSHOT_URL")]
    pub server_url: Option<String>,

    /// API key (sent as `X-API-Key`).
    #[arg(long = "api-key", env = "TRICKSHOT_API_KEY")]
    pub api_key: Option<String>,

    /// Viewport width in logical pixels.
    #[arg(short = 'w', long)]
    pub width: Option<u32>,

    /// Viewport height in logical pixels. (No `-h` short: that is clap's --help.)
    #[arg(long)]
    pub height: Option<u32>,

    /// Device pixel ratio; `2` renders a crisp 2x retina shot.
    #[arg(long, alias = "scale")]
    pub dpr: Option<f64>,

    /// Per-shot render timeout in seconds.
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Output file, or `-` for stdout. Default: derived from the URL host.
    #[arg(short = 'o', long)]
    pub output: Option<String>,

    /// Open a reverse tunnel for this shot so private/VPN URLs resolve on the
    /// caller's network.
    #[arg(long)]
    pub tunnel: bool,
}

/// Resolved shot request: a target URL plus credentials and render options.
pub struct Shot {
    pub url: String,
    pub server: String,
    pub api_key: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub dpr: Option<f64>,
    pub timeout: Option<u64>,
    pub output: Option<String>,
    pub tunnel: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("ts: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Some(Cmd::Auth { url, key, name }) => config::auth(&url, &key, name.as_deref()),
        Some(Cmd::Servers) => config::servers(),
        Some(Cmd::Default { name }) => config::set_default(&name),
        Some(Cmd::Keys { cmd }) => admin::run(cli.server.as_deref(), &cmd).await,
        None => run_shot(cli.server.as_deref(), cli.shot).await,
    }
}

async fn run_shot(server: Option<&str>, args: ShotArgs) -> Result<()> {
    let url = args.url.context("missing <url>: `ts <url>` or a subcommand (see `ts --help`)")?;
    let parsed = Url::parse(&url).with_context(|| format!("invalid url: {url}"))?;
    let (server_url, api_key) = resolve(server, args.server_url, args.api_key)?;

    let shot = Shot {
        url,
        server: server_url,
        api_key,
        width: args.width,
        height: args.height,
        dpr: args.dpr,
        timeout: args.timeout,
        output: args.output,
        tunnel: args.tunnel,
    };

    if shot.tunnel {
        tunnel::run(&shot, &parsed).await
    } else {
        let png = fetch_shot(&shot, None).await?;
        write_output(&shot, &parsed, &png).await
    }
}

/// Build `${server}/shot?…` for the given (optional) tunnel id.
pub fn shot_url(shot: &Shot, tunnel_id: Option<&str>) -> Result<Url> {
    let base = shot.server.trim_end_matches('/');
    let mut u = Url::parse(&format!("{base}/shot")).context("invalid server url")?;
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("url", &shot.url);
        if let Some(w) = shot.width {
            q.append_pair("w", &w.to_string());
        }
        if let Some(h) = shot.height {
            q.append_pair("height", &h.to_string());
        }
        if let Some(d) = shot.dpr {
            q.append_pair("dpr", &d.to_string());
        }
        if let Some(t) = shot.timeout {
            q.append_pair("timeout", &t.to_string());
        }
        if let Some(id) = tunnel_id {
            q.append_pair("tunnel", id);
        }
    }
    Ok(u)
}

/// Issue `GET /shot` (optionally `&tunnel=<id>`), returning the PNG bytes.
/// A non-2xx response surfaces the server's JSON `error` and fails.
pub async fn fetch_shot(shot: &Shot, tunnel_id: Option<&str>) -> Result<Vec<u8>> {
    let url = shot_url(shot, tunnel_id)?;
    let client = reqwest::Client::builder().build().context("building http client")?;
    let resp = client
        .get(url)
        .header("X-API-Key", &shot.api_key)
        .send()
        .await
        .context("requesting /shot")?;

    let status = resp.status();
    let body = resp.bytes().await.context("reading response body")?;
    if !status.is_success() {
        let msg = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
            .unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
        bail!("server returned {status}: {msg}");
    }
    Ok(body.to_vec())
}

/// Write the PNG to the chosen destination: `-` → stdout, explicit path, or a
/// name derived from the URL host (`<host>.png`).
async fn write_output(shot: &Shot, parsed: &Url, png: &[u8]) -> Result<()> {
    match shot.output.as_deref() {
        Some("-") => {
            let mut out = tokio::io::stdout();
            out.write_all(png).await.context("writing to stdout")?;
            out.flush().await.ok();
        }
        Some(path) => write_file(PathBuf::from(path), png).await?,
        None => {
            let host = parsed.host_str().unwrap_or("shot");
            write_file(PathBuf::from(format!("{host}.png")), png).await?;
        }
    }
    Ok(())
}

async fn write_file(path: PathBuf, png: &[u8]) -> Result<()> {
    tokio::fs::write(&path, png).await.with_context(|| format!("writing {}", path.display()))?;
    eprintln!("ts: wrote {} ({} bytes)", path.display(), png.len());
    Ok(())
}
