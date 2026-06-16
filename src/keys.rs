//! File-backed API-key store with SHA-256 hashing at rest, plus the
//! `trickshot keys …` management CLI. Keys are stored as hashes only; the
//! plaintext secret is shown exactly once, at creation.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;

/// One stored key. The secret is never persisted — only its SHA-256 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub id: String,
    pub label: String,
    /// Hex-encoded SHA-256 of the plaintext key.
    pub hash: String,
    /// Unix seconds.
    pub created_at: u64,
    #[serde(default)]
    pub disabled: bool,
}

/// The on-disk document: a flat list of entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyFile {
    #[serde(default)]
    pub keys: Vec<KeyEntry>,
}

/// Hex-encode the SHA-256 of `plaintext`.
pub fn hash_key(plaintext: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(plaintext.as_bytes());
    digest.iter().fold(String::with_capacity(digest.len() * 2), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Constant-time comparison of two equal-length byte slices. Returns false for
/// length mismatches (length is not secret here — the hash width is fixed).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Generate a fresh 32-byte base64url secret and a short random id.
fn gen_key() -> (String, String) {
    let mut rng = rand::rng();
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    let secret = URL_SAFE_NO_PAD.encode(buf);
    let mut id_buf = [0u8; 6];
    rng.fill_bytes(&mut id_buf);
    let id = URL_SAFE_NO_PAD.encode(id_buf);
    (id, secret)
}

/// Read the key file from disk, returning an empty document if it does not
/// exist yet.
pub fn load_file(path: &Path) -> Result<KeyFile, ApiError> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| ApiError::Internal(format!("parse keys file: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(KeyFile::default()),
        Err(e) => Err(ApiError::Internal(format!("read keys file: {e}"))),
    }
}

/// Atomically write the key file (write-temp-then-rename).
pub fn save_file(path: &Path, file: &KeyFile) -> Result<(), ApiError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| ApiError::Internal(format!("create keys dir: {e}")))?;
    }
    let json = serde_json::to_vec_pretty(file)
        .map_err(|e| ApiError::Internal(format!("serialize keys: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json).map_err(|e| ApiError::Internal(format!("write keys tmp: {e}")))?;
    std::fs::rename(&tmp, path).map_err(|e| ApiError::Internal(format!("rename keys: {e}")))?;
    Ok(())
}

/// In-memory, hot-reloadable view of the key store used by the request path.
pub struct KeyStore {
    path: PathBuf,
    inner: RwLock<KeyFile>,
}

impl KeyStore {
    /// Load the store from `path`. A missing file is treated as empty.
    pub fn load(path: PathBuf) -> Result<Arc<Self>, ApiError> {
        let file = load_file(&path)?;
        Ok(Arc::new(Self { path, inner: RwLock::new(file) }))
    }

    /// Re-read the file from disk, replacing the in-memory view. Used on file
    /// change / SIGHUP for revocation without a restart.
    pub fn reload(&self) -> Result<(), ApiError> {
        let file = load_file(&self.path)?;
        let count = file.keys.len();
        *self.inner.write().expect("keystore poisoned") = file;
        tracing::info!(keys = count, "reloaded api keys");
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Look up a presented plaintext key. Returns the matching, enabled entry's
    /// `(id, label)` or `None`. Comparison against each stored hash is
    /// constant-time.
    pub fn verify(&self, presented: &str) -> Option<(String, String)> {
        let presented_hash = hash_key(presented);
        let guard = self.inner.read().expect("keystore poisoned");
        let matched = guard
            .keys
            .iter()
            .filter(|e| !e.disabled)
            .find(|e| constant_time_eq(presented_hash.as_bytes(), e.hash.as_bytes()))
            .map(|e| (e.id.clone(), e.label.clone()));
        drop(guard);
        matched
    }

    /// Whether the store holds at least one enabled key. An empty store means
    /// auth would reject everything; callers warn on this at startup.
    pub fn has_enabled_keys(&self) -> bool {
        self.inner.read().expect("keystore poisoned").keys.iter().any(|k| !k.disabled)
    }
}

// --- CLI ---------------------------------------------------------------------

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum KeysCmd {
    /// Generate a new key, print the plaintext once, store only its hash.
    Create {
        #[arg(long)]
        label: String,
    },
    /// List keys (id, label, created, disabled) — never the secret.
    List,
    /// Disable a key by id.
    Disable { id: String },
    /// Enable a previously disabled key by id.
    Enable { id: String },
    /// Delete a key by id.
    Delete { id: String },
}

/// Execute a `trickshot keys …` subcommand against `keys_file`.
pub fn run(cmd: &KeysCmd, keys_file: &Path) -> Result<(), ApiError> {
    let mut file = load_file(keys_file)?;
    match cmd {
        KeysCmd::Create { label } => {
            let (id, secret) = gen_key();
            file.keys.push(KeyEntry {
                id: id.clone(),
                label: label.clone(),
                hash: hash_key(&secret),
                created_at: now_secs(),
                disabled: false,
            });
            save_file(keys_file, &file)?;
            println!("Created key id={id} label={label}");
            println!("Secret (shown once, store it now):\n{secret}");
        }
        KeysCmd::List => {
            if file.keys.is_empty() {
                println!("(no keys)");
            }
            for k in &file.keys {
                println!(
                    "{:<12} {:<24} created={:<12} {}",
                    k.id,
                    k.label,
                    k.created_at,
                    if k.disabled { "disabled" } else { "active" }
                );
            }
        }
        KeysCmd::Disable { id } => set_disabled(&mut file, keys_file, id, true)?,
        KeysCmd::Enable { id } => set_disabled(&mut file, keys_file, id, false)?,
        KeysCmd::Delete { id } => {
            let before = file.keys.len();
            file.keys.retain(|k| &k.id != id);
            if file.keys.len() == before {
                return Err(ApiError::BadRequest(format!("no key with id {id}")));
            }
            save_file(keys_file, &file)?;
            println!("Deleted key id={id}");
        }
    }
    Ok(())
}

fn set_disabled(file: &mut KeyFile, path: &Path, id: &str, disabled: bool) -> Result<(), ApiError> {
    let entry = file
        .keys
        .iter_mut()
        .find(|k| k.id == id)
        .ok_or_else(|| ApiError::BadRequest(format!("no key with id {id}")))?;
    entry.disabled = disabled;
    save_file(path, file)?;
    println!("{} key id={id}", if disabled { "Disabled" } else { "Enabled" });
    Ok(())
}
