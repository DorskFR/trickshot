//! Remote admin client: drives the server's `/admin/keys…` endpoints with an
//! admin-scoped key resolved from env or `~/.config/trickshot/config.json`.
//! A 403 from the server is reported as needing an admin key.

use anyhow::{Context, Result, bail};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use crate::KeysCmd;
use crate::config::Config;

/// Resolve admin credentials: `TRICKSHOT_URL`/`TRICKSHOT_API_KEY` win (when both
/// set and no explicit `--server`), else the config's selected server.
fn resolve_admin(server: Option<&str>) -> Result<(String, String)> {
    let env_url = std::env::var("TRICKSHOT_URL").ok();
    let env_key = std::env::var("TRICKSHOT_API_KEY").ok();
    if server.is_none()
        && let (Some(u), Some(k)) = (env_url, env_key)
    {
        return Ok((u, k));
    }
    Config::load()?.select(server)
}

pub async fn run(server: Option<&str>, cmd: &KeysCmd) -> Result<()> {
    let (base, key) = resolve_admin(server)?;
    let base = base.trim_end_matches('/');
    let client = reqwest::Client::builder().build().context("building http client")?;

    match cmd {
        KeysCmd::Create { label, role } => {
            let v = request(
                &client,
                &key,
                Method::POST,
                &format!("{base}/admin/keys"),
                Some(json!({"label": label, "role": role})),
            )
            .await?;
            println!(
                "Created key id={} label={} role={}",
                v["id"].as_str().unwrap_or("?"),
                v["label"].as_str().unwrap_or("?"),
                v["role"].as_str().unwrap_or("?"),
            );
            println!("Secret (shown once, store it now):\n{}", v["secret"].as_str().unwrap_or("?"));
        }
        KeysCmd::List => {
            let v =
                request(&client, &key, Method::GET, &format!("{base}/admin/keys"), None).await?;
            let empty = vec![];
            let keys = v.as_array().unwrap_or(&empty);
            if keys.is_empty() {
                println!("(no keys)");
            }
            for k in keys {
                println!(
                    "{:<12} {:<24} {:<8} created={:<12} {}",
                    k["id"].as_str().unwrap_or("?"),
                    k["label"].as_str().unwrap_or("?"),
                    k["role"].as_str().unwrap_or("?"),
                    k["created_at"].as_u64().unwrap_or(0),
                    if k["disabled"].as_bool().unwrap_or(false) { "disabled" } else { "active" },
                );
            }
        }
        KeysCmd::Disable { id } => {
            simple(&client, &key, &format!("{base}/admin/keys/{id}/disable"), None).await?;
            println!("Disabled key id={id}");
        }
        KeysCmd::Enable { id } => {
            simple(&client, &key, &format!("{base}/admin/keys/{id}/enable"), None).await?;
            println!("Enabled key id={id}");
        }
        KeysCmd::Delete { id } => {
            request(&client, &key, Method::DELETE, &format!("{base}/admin/keys/{id}"), None)
                .await?;
            println!("Deleted key id={id}");
        }
        KeysCmd::Promote { id } => {
            simple(&client, &key, &format!("{base}/admin/keys/{id}/role"), Some("admin")).await?;
            println!("Promoted key id={id} to admin");
        }
        KeysCmd::Demote { id } => {
            simple(&client, &key, &format!("{base}/admin/keys/{id}/role"), Some("render")).await?;
            println!("Demoted key id={id} to render");
        }
    }
    Ok(())
}

/// POST helper for endpoints that take an optional `{role}` body.
async fn simple(
    client: &reqwest::Client,
    key: &str,
    url: &str,
    role: Option<&str>,
) -> Result<Value> {
    let body = role.map(|r| json!({"role": r}));
    request(client, key, Method::POST, url, body).await
}

async fn request(
    client: &reqwest::Client,
    key: &str,
    method: Method,
    url: &str,
    body: Option<Value>,
) -> Result<Value> {
    let mut req = client.request(method, url).header("X-API-Key", key);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.context("requesting admin endpoint")?;
    let status = resp.status();
    let bytes = resp.bytes().await.context("reading response body")?;

    if status == StatusCode::FORBIDDEN {
        bail!("insufficient permission: needs an admin key");
    }
    if !status.is_success() {
        let msg = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
            .unwrap_or_else(|| String::from_utf8_lossy(&bytes).into_owned());
        bail!("server returned {status}: {msg}");
    }
    Ok(serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}
