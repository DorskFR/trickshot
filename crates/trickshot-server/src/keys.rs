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

/// A key's permission scope. `render` keys may call `/shot` (+ `/tunnel`);
/// `admin` keys may *also* call the `/admin/keys…` endpoints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum Role {
    #[default]
    Render,
    Admin,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Render => "render",
            Self::Admin => "admin",
        })
    }
}

/// One stored key. The secret is never persisted — only its SHA-256 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub id: String,
    pub label: String,
    /// Hex-encoded SHA-256 of the plaintext key.
    pub hash: String,
    /// Permission scope; legacy entries without this field default to `render`.
    #[serde(default)]
    pub role: Role,
    /// Unix seconds.
    pub created_at: u64,
    #[serde(default)]
    pub disabled: bool,
}

/// Public view of a key for admin listing — never includes the hash/secret.
#[derive(Debug, Clone, Serialize)]
pub struct KeyInfo {
    pub id: String,
    pub label: String,
    pub role: Role,
    pub created_at: u64,
    pub disabled: bool,
}

impl From<&KeyEntry> for KeyInfo {
    fn from(e: &KeyEntry) -> Self {
        Self {
            id: e.id.clone(),
            label: e.label.clone(),
            role: e.role,
            created_at: e.created_at,
            disabled: e.disabled,
        }
    }
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
    /// `(id, label, role)` or `None`. Comparison against each stored hash is
    /// constant-time.
    pub fn verify(&self, presented: &str) -> Option<(String, String, Role)> {
        let presented_hash = hash_key(presented);
        let guard = self.inner.read().expect("keystore poisoned");
        let matched = guard
            .keys
            .iter()
            .filter(|e| !e.disabled)
            .find(|e| constant_time_eq(presented_hash.as_bytes(), e.hash.as_bytes()))
            .map(|e| (e.id.clone(), e.label.clone(), e.role));
        drop(guard);
        matched
    }

    /// Whether the store holds at least one enabled key. An empty store means
    /// auth would reject everything; callers warn on this at startup.
    pub fn has_enabled_keys(&self) -> bool {
        self.inner.read().expect("keystore poisoned").keys.iter().any(|k| !k.disabled)
    }

    /// Whether the store holds at least one enabled `admin` key.
    pub fn has_admin_key(&self) -> bool {
        self.inner
            .read()
            .expect("keystore poisoned")
            .keys
            .iter()
            .any(|k| !k.disabled && k.role == Role::Admin)
    }

    /// Persist the current in-memory view back to disk, then reload it (the
    /// file watcher also catches the write, but reloading inline keeps the
    /// in-memory view authoritative for the just-applied mutation).
    fn persist(&self, file: &KeyFile) -> Result<(), ApiError> {
        save_file(&self.path, file)?;
        *self.inner.write().expect("keystore poisoned") = file.clone();
        Ok(())
    }

    /// Create a new key with `label`/`role`, persist its hash, return the
    /// entry's public info plus the one-time plaintext secret.
    pub fn create(&self, label: &str, role: Role) -> Result<(KeyInfo, String), ApiError> {
        let (id, secret) = gen_key();
        let mut file = self.inner.read().expect("keystore poisoned").clone();
        let entry = KeyEntry {
            id,
            label: label.to_string(),
            hash: hash_key(&secret),
            role,
            created_at: now_secs(),
            disabled: false,
        };
        file.keys.push(entry.clone());
        self.persist(&file)?;
        Ok(((&entry).into(), secret))
    }

    /// Seed a bootstrap admin key from a known plaintext secret. Used at
    /// startup so the operator can inject `TRICKSHOT_BOOTSTRAP_ADMIN_KEY` once.
    pub fn create_with_secret(
        &self,
        label: &str,
        role: Role,
        secret: &str,
    ) -> Result<KeyInfo, ApiError> {
        let mut rng = rand::rng();
        let mut id_buf = [0u8; 6];
        rng.fill_bytes(&mut id_buf);
        let id = URL_SAFE_NO_PAD.encode(id_buf);
        let mut file = self.inner.read().expect("keystore poisoned").clone();
        let entry = KeyEntry {
            id,
            label: label.to_string(),
            hash: hash_key(secret),
            role,
            created_at: now_secs(),
            disabled: false,
        };
        file.keys.push(entry.clone());
        self.persist(&file)?;
        Ok((&entry).into())
    }

    /// List all keys' public info (never secrets/hashes).
    pub fn list(&self) -> Vec<KeyInfo> {
        self.inner.read().expect("keystore poisoned").keys.iter().map(KeyInfo::from).collect()
    }

    fn mutate<F>(&self, id: &str, f: F) -> Result<KeyInfo, ApiError>
    where
        F: FnOnce(&mut KeyEntry),
    {
        let mut file = self.inner.read().expect("keystore poisoned").clone();
        let entry = file
            .keys
            .iter_mut()
            .find(|k| k.id == id)
            .ok_or_else(|| ApiError::BadRequest(format!("no key with id {id}")))?;
        f(entry);
        let info = KeyInfo::from(&*entry);
        self.persist(&file)?;
        Ok(info)
    }

    pub fn set_disabled(&self, id: &str, disabled: bool) -> Result<KeyInfo, ApiError> {
        self.mutate(id, |e| e.disabled = disabled)
    }

    pub fn set_role(&self, id: &str, role: Role) -> Result<KeyInfo, ApiError> {
        self.mutate(id, |e| e.role = role)
    }

    pub fn delete(&self, id: &str) -> Result<(), ApiError> {
        let mut file = self.inner.read().expect("keystore poisoned").clone();
        let before = file.keys.len();
        file.keys.retain(|k| k.id != id);
        if file.keys.len() == before {
            return Err(ApiError::BadRequest(format!("no key with id {id}")));
        }
        self.persist(&file)
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
        /// Permission scope for the key.
        #[arg(long, value_enum, default_value_t = Role::Render)]
        role: Role,
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
        KeysCmd::Create { label, role } => {
            let (id, secret) = gen_key();
            file.keys.push(KeyEntry {
                id: id.clone(),
                label: label.clone(),
                hash: hash_key(&secret),
                role: *role,
                created_at: now_secs(),
                disabled: false,
            });
            save_file(keys_file, &file)?;
            println!("Created key id={id} label={label} role={role}");
            println!("Secret (shown once, store it now):\n{secret}");
        }
        KeysCmd::List => {
            if file.keys.is_empty() {
                println!("(no keys)");
            }
            for k in &file.keys {
                println!(
                    "{:<12} {:<24} {:<8} created={:<12} {}",
                    k.id,
                    k.label,
                    k.role.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Arc<KeyStore> {
        let dir = std::env::temp_dir().join(format!("trickshot-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join(format!("keys-{:?}.json", std::time::Instant::now()));
        KeyStore::load(path).unwrap()
    }

    #[test]
    fn create_verify_role_roundtrip() {
        let s = store();
        let (info, secret) = s.create("admin-key", Role::Admin).unwrap();
        assert_eq!(info.role, Role::Admin);
        let (id, _label, role) = s.verify(&secret).expect("verifies");
        assert_eq!(id, info.id);
        assert_eq!(role, Role::Admin);
        assert!(s.has_admin_key());
        assert!(s.verify("not-a-key").is_none());
    }

    #[test]
    fn default_role_is_render() {
        let s = store();
        let (_info, secret) = s.create("r", Role::Render).unwrap();
        assert_eq!(s.verify(&secret).unwrap().2, Role::Render);
        // a fresh render-only store has no admin key
        assert!(!s.has_admin_key());
    }

    #[test]
    fn promote_disable_delete() {
        let s = store();
        let (info, secret) = s.create("k", Role::Render).unwrap();
        s.set_role(&info.id, Role::Admin).unwrap();
        assert_eq!(s.verify(&secret).unwrap().2, Role::Admin);
        s.set_disabled(&info.id, true).unwrap();
        assert!(s.verify(&secret).is_none(), "disabled keys do not verify");
        s.set_disabled(&info.id, false).unwrap();
        assert!(s.verify(&secret).is_some());
        s.delete(&info.id).unwrap();
        assert!(s.verify(&secret).is_none());
        assert!(s.delete(&info.id).is_err(), "deleting a missing id errors");
    }

    #[test]
    fn create_with_secret_bootstrap() {
        let s = store();
        let info = s.create_with_secret("bootstrap", Role::Admin, "fixed-secret").unwrap();
        assert_eq!(info.role, Role::Admin);
        assert_eq!(s.verify("fixed-secret").unwrap().2, Role::Admin);
    }

    #[test]
    fn legacy_entry_defaults_to_render() {
        // An on-disk entry without a `role` field deserializes as render.
        let json = r#"{"keys":[{"id":"x","label":"old","hash":"deadbeef","created_at":1}]}"#;
        let file: KeyFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.keys[0].role, Role::Render);
        assert!(!file.keys[0].disabled);
    }

    #[test]
    fn list_omits_secret_fields() {
        let s = store();
        s.create("a", Role::Render).unwrap();
        let infos = s.list();
        assert_eq!(infos.len(), 1);
        // KeyInfo has no hash/secret field — serialize and confirm.
        let v = serde_json::to_value(&infos[0]).unwrap();
        assert!(v.get("hash").is_none());
        assert!(v.get("secret").is_none());
        assert_eq!(v["role"], "render");
    }
}
