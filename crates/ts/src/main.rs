//! `ts` — the trickshot CLI client.
//!
//! Two modes in one foreground command:
//!
//! * **plain shot** — `GET ${server}/shot?url=…` with the API key, streaming the
//!   `image/png` body to a file (or stdout);
//! * **`--tunnel`** — open `wss://${server}/tunnel`, act as the reverse-tunnel
//!   agent (TRI-5): dial each `connect host:port` the server frames over the WS
//!   on the *caller's* network and pipe bytes both ways, then take the shot with
//!   `&tunnel=<id>` so private/VPN hostnames resolve locally.
//!
//! Lean by design: reqwest+rustls + tokio-tungstenite + clap, no chromiumoxide.

mod tunnel;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::io::AsyncWriteExt;
use url::Url;

/// trickshot client: take a screenshot, optionally through a reverse tunnel.
#[derive(Debug, Parser)]
#[command(name = "ts", version, about, long_about = None)]
pub struct Args {
    /// Page to screenshot.
    pub url: String,

    /// trickshot server base URL (e.g. https://shot.example.com).
    #[arg(long, env = "TRICKSHOT_URL")]
    pub server: String,

    /// API key (sent as `X-API-Key`). Required by the server (TRI-4).
    #[arg(long, env = "TRICKSHOT_API_KEY")]
    pub api_key: String,

    /// Viewport width in logical pixels.
    #[arg(short = 'w', long)]
    pub width: Option<u32>,

    /// Viewport height in logical pixels. (No `-h` short: that is clap's --help.)
    #[arg(long)]
    pub height: Option<u32>,

    /// Device pixel ratio; `2` renders a crisp 2x retina shot. (Long-only:
    /// a clap short is single-char, so `-dpr` would parse as `-d -p -r`.)
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if let Err(e) = run(args).await {
        eprintln!("ts: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

async fn run(args: Args) -> Result<()> {
    // Validate the target URL early and use it to derive a default output name.
    let parsed = Url::parse(&args.url).with_context(|| format!("invalid url: {}", args.url))?;

    if args.tunnel {
        tunnel::run(&args, &parsed).await
    } else {
        let png = fetch_shot(&args, None).await?;
        write_output(&args, &parsed, &png).await
    }
}

/// Build `${server}/shot?…` for the given (optional) tunnel id.
pub fn shot_url(args: &Args, tunnel_id: Option<&str>) -> Result<Url> {
    let base = args.server.trim_end_matches('/');
    let mut u = Url::parse(&format!("{base}/shot")).context("invalid --server url")?;
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("url", &args.url);
        if let Some(w) = args.width {
            q.append_pair("w", &w.to_string());
        }
        if let Some(h) = args.height {
            q.append_pair("height", &h.to_string());
        }
        if let Some(d) = args.dpr {
            q.append_pair("dpr", &d.to_string());
        }
        if let Some(t) = args.timeout {
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
pub async fn fetch_shot(args: &Args, tunnel_id: Option<&str>) -> Result<Vec<u8>> {
    let url = shot_url(args, tunnel_id)?;
    let client = reqwest::Client::builder().build().context("building http client")?;
    let resp = client
        .get(url)
        .header("X-API-Key", &args.api_key)
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
async fn write_output(args: &Args, parsed: &Url, png: &[u8]) -> Result<()> {
    match args.output.as_deref() {
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
