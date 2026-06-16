//! Local credential config at `~/.config/trickshot/config.json`, mirroring the
//! `yt` CLI shape:
//!
//! ```json
//! {"default":"prod","servers":{"prod":{"url":"https://…","key":"<admin-key>"}}}
//! ```
//!
//! `TRICKSHOT_URL`/`TRICKSHOT_API_KEY` take precedence over the file (as in `yt`).

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde_json::{Value, json};

fn config_path() -> std::path::PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))
        .unwrap_or_default()
        .join("trickshot/config.json")
}

/// On-disk config: `{"default": "<name>", "servers": {"<name>": {url, key}}}`.
#[derive(Default)]
pub struct Config {
    pub default: Option<String>,
    /// name → (url, key)
    pub servers: BTreeMap<String, (String, String)>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = config_path();
        let Ok(s) = std::fs::read_to_string(&path) else { return Ok(Self::default()) };
        let cfg: Value = serde_json::from_str(&s)
            .with_context(|| format!("invalid JSON in {}", path.display()))?;
        let mut servers = BTreeMap::new();
        if let Some(obj) = cfg["servers"].as_object() {
            for (name, v) in obj {
                if let (Some(u), Some(k)) = (v["url"].as_str(), v["key"].as_str()) {
                    servers.insert(name.clone(), (u.to_string(), k.to_string()));
                }
            }
        }
        let default = cfg["default"].as_str().map(String::from);
        Ok(Self { default, servers })
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path();
        std::fs::create_dir_all(path.parent().context("no config dir")?)?;
        let servers: serde_json::Map<String, Value> = self
            .servers
            .iter()
            .map(|(name, (u, k))| (name.clone(), json!({"url": u, "key": k})))
            .collect();
        let cfg = json!({"default": self.default, "servers": servers});
        std::fs::write(&path, serde_json::to_string_pretty(&cfg)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Pick a server's `(url, key)` by name, default, or sole entry.
    pub fn select(&self, server: Option<&str>) -> Result<(String, String)> {
        let name = match server {
            Some(s) => s.to_string(),
            None => self
                .default
                .clone()
                .or_else(|| {
                    (self.servers.len() == 1).then(|| self.servers.keys().next().unwrap().clone())
                })
                .context(
                    "no server selected: set a default with `ts default NAME`, pass --server, \
                     or set TRICKSHOT_URL/TRICKSHOT_API_KEY",
                )?,
        };
        self.servers
            .get(&name)
            .cloned()
            .with_context(|| format!("no server named '{name}': run `ts auth URL KEY {name}`"))
    }
}

/// Resolve `(url, key)`: env vars win (when both present and no explicit
/// `--server`), else the config's selected entry. `--server-url`/`--api-key`
/// flags (which also read the env vars) override last.
pub fn resolve(
    server: Option<&str>,
    flag_url: Option<String>,
    flag_key: Option<String>,
) -> Result<(String, String)> {
    // The shot flags already fold in TRICKSHOT_URL/TRICKSHOT_API_KEY via clap
    // `env`; when both are present (and no explicit --server) use them directly.
    if server.is_none()
        && let (Some(u), Some(k)) = (&flag_url, &flag_key)
    {
        return Ok((u.clone(), k.clone()));
    }
    let (mut url, mut key) = Config::load()?.select(server)?;
    if let Some(u) = flag_url {
        url = u;
    }
    if let Some(k) = flag_key {
        key = k;
    }
    Ok((url, key))
}

fn read_arg(value: &str) -> Result<String> {
    if value == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).context("reading stdin")?;
        Ok(s.trim().to_string())
    } else {
        Ok(value.to_string())
    }
}

pub fn auth(url: &str, key: &str, name: Option<&str>) -> Result<()> {
    let name = name.unwrap_or("default").to_string();
    let key = read_arg(key)?;
    let mut cfg = Config::load()?;
    cfg.servers.insert(name.clone(), (url.trim_end_matches('/').to_string(), key));
    if cfg.default.is_none() {
        cfg.default = Some(name.clone());
    }
    cfg.save()?;
    eprintln!("ts: saved server '{name}'");
    Ok(())
}

pub fn servers() -> Result<()> {
    let cfg = Config::load()?;
    if cfg.servers.is_empty() {
        eprintln!("(no servers configured — run `ts auth URL KEY`)");
        return Ok(());
    }
    for (name, (url, _)) in &cfg.servers {
        let mark = if cfg.default.as_deref() == Some(name) { "*" } else { " " };
        println!("{mark} {name:<12} {url}");
    }
    Ok(())
}

pub fn set_default(name: &str) -> Result<()> {
    let mut cfg = Config::load()?;
    if !cfg.servers.contains_key(name) {
        anyhow::bail!("no server named '{name}': run `ts auth URL KEY {name}`");
    }
    cfg.default = Some(name.to_string());
    cfg.save()?;
    eprintln!("ts: default server is now '{name}'");
    Ok(())
}
