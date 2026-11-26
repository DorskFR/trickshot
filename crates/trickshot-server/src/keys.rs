//! File-backed API-key store with SHA-256 hashing at rest, plus the
//! `trickshot keys …` management CLI. Keys are stored as hashes only; the
//! plaintext secret is shown exactly once, at creation.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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

/// A content fingerprint of the key set used to detect whether a reload
/// actually changed anything. Covers every persisted field so a no-op reload
/// (identical on disk) is recognized and not logged.
fn fingerprint(file: &KeyFile) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((file.keys.len() as u64).to_le_bytes());
    for k in &file.keys {
        hasher.update(k.id.as_bytes());
        hasher.update(b"\0");
        hasher.update(k.label.as_bytes());
        hasher.update(b"\0");
        hasher.update(k.hash.as_bytes());
        hasher.update(b"\0");
        hasher.update(k.role.to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(k.created_at.to_le_bytes());
        hasher.update([u8::from(k.disabled)]);
    }
    hasher.finalize().into()
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

/// Atomically replace the key file: unique temp file in the same directory,
/// fsync, rename, fsync the directory.
pub fn save_file(path: &Path, file: &KeyFile) -> Result<(), ApiError> {
    use std::io::Write;
    static NEXT: AtomicU64 = AtomicU64::new(0);

    let dir = parent_dir(path);
    std::fs::create_dir_all(dir)
        .map_err(|e| ApiError::Internal(format!("create keys dir: {e}")))?;
    let json = serde_json::to_vec_pretty(file)
        .map_err(|e| ApiError::Internal(format!("serialize keys: {e}")))?;
    let name = path.file_name().map_or_else(|| "keys".into(), |n| n.to_string_lossy());
    let tmp = dir.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create_new(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        ApiError::Internal(format!("write keys file: {e}"))
    })
}

fn parent_dir(path: &Path) -> &Path {
    path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."))
}

/// Read-modify-write the key file under an exclusive advisory lock on a
/// sidecar `.lock` file, so concurrent writers (server handlers and the CLI)
/// never lose each other's updates.
pub fn update_file<R>(
    path: &Path,
    f: impl FnOnce(&mut KeyFile) -> Result<R, ApiError>,
) -> Result<(KeyFile, R), ApiError> {
    let dir = parent_dir(path);
    std::fs::create_dir_all(dir)
        .map_err(|e| ApiError::Internal(format!("create keys dir: {e}")))?;
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| ApiError::Internal(format!("open keys lock: {e}")))?;
    lock.lock().map_err(|e| ApiError::Internal(format!("lock keys file: {e}")))?;
    let mut file = load_file(path)?;
    let out = f(&mut file)?;
    save_file(path, &file)?;
    Ok((file, out))
}

/// In-memory, hot-reloadable view of the key store used by the request path.
pub struct KeyStore {
    path: PathBuf,
    inner: RwLock<KeyFile>,
    writer: Mutex<()>,
}

impl KeyStore {
    /// Load the store from `path`. A missing file is treated as empty.
    pub fn load(path: PathBuf) -> Result<Arc<Self>, ApiError> {
        let file = load_file(&path)?;
        Ok(Arc::new(Self { path, inner: RwLock::new(file), writer: Mutex::new(()) }))
    }

    /// Re-read the file from disk, replacing the in-memory view. Used on file
    /// change / SIGHUP for revocation without a restart. Emits the INFO line
    /// only when the key set actually changed; an unchanged reload (e.g. from a
    /// spurious fs event) returns quietly so the log is not spammed.
    pub fn reload(&self) -> Result<(), ApiError> {
        let file = load_file(&self.path)?;
        let count = file.keys.len();
        let new_fp = fingerprint(&file);
        let mut guard = self.inner.write().expect("keystore poisoned");
        let changed = fingerprint(&guard) != new_fp;
        *guard = file;
        drop(guard);
        if changed {
            tracing::info!(keys = count, "reloaded api keys");
        } else {
            tracing::debug!(keys = count, "key file reload: no change");
        }
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

    /// Whether `id` names an enabled key.
    pub fn is_enabled(&self, id: &str) -> bool {
        self.inner.read().expect("keystore poisoned").keys.iter().any(|k| k.id == id && !k.disabled)
    }

    /// Apply `f` to the on-disk file under the store's write lock, then make
    /// the result the in-memory view.
    fn update<R>(
        &self,
        f: impl FnOnce(&mut KeyFile) -> Result<R, ApiError>,
    ) -> Result<R, ApiError> {
        let _writer = self.writer.lock().expect("keystore writer poisoned");
        let (file, out) = update_file(&self.path, f)?;
        *self.inner.write().expect("keystore poisoned") = file;
        Ok(out)
    }

    /// Create a new key with `label`/`role`, persist its hash, return the
    /// entry's public info plus the one-time plaintext secret.
    pub fn create(&self, label: &str, role: Role) -> Result<(KeyInfo, String), ApiError> {
        let (id, secret) = gen_key();
        let info = self.insert(id, label, role, &secret)?;
        Ok((info, secret))
    }

    /// Seed a bootstrap admin key from a known plaintext secret.
    pub fn create_with_secret(
        &self,
        label: &str,
        role: Role,
        secret: &str,
    ) -> Result<KeyInfo, ApiError> {
        let mut id_buf = [0u8; 6];
        rand::rng().fill_bytes(&mut id_buf);
        self.insert(URL_SAFE_NO_PAD.encode(id_buf), label, role, secret)
    }

    fn insert(
        &self,
        id: String,
        label: &str,
        role: Role,
        secret: &str,
    ) -> Result<KeyInfo, ApiError> {
        let entry = KeyEntry {
            id,
            label: label.to_string(),
            hash: hash_key(secret),
            role,
            created_at: now_secs(),
            disabled: false,
        };
        let info = KeyInfo::from(&entry);
        self.update(|file| {
            file.keys.push(entry);
            Ok(())
        })?;
        Ok(info)
    }

    /// List all keys' public info (never secrets/hashes).
    pub fn list(&self) -> Vec<KeyInfo> {
        self.inner.read().expect("keystore poisoned").keys.iter().map(KeyInfo::from).collect()
    }

    fn mutate<F>(&self, id: &str, f: F) -> Result<KeyInfo, ApiError>
    where
        F: FnOnce(&mut KeyEntry),
    {
        self.update(|file| {
            let entry = file
                .keys
                .iter_mut()
                .find(|k| k.id == id)
                .ok_or_else(|| ApiError::BadRequest(format!("no key with id {id}")))?;
            f(entry);
            Ok(KeyInfo::from(&*entry))
        })
    }

    pub fn set_disabled(&self, id: &str, disabled: bool) -> Result<KeyInfo, ApiError> {
        self.mutate(id, |e| e.disabled = disabled)
    }

    pub fn set_role(&self, id: &str, role: Role) -> Result<KeyInfo, ApiError> {
        self.mutate(id, |e| e.role = role)
    }

    pub fn delete(&self, id: &str) -> Result<(), ApiError> {
        self.update(|file| remove_entry(file, id))
    }
}

fn remove_entry(file: &mut KeyFile, id: &str) -> Result<(), ApiError> {
    let before = file.keys.len();
    file.keys.retain(|k| k.id != id);
    if file.keys.len() == before {
        return Err(ApiError::BadRequest(format!("no key with id {id}")));
    }
    Ok(())
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
    match cmd {
        KeysCmd::Create { label, role } => {
            let (id, secret) = gen_key();
            update_file(keys_file, |file| {
                file.keys.push(KeyEntry {
                    id: id.clone(),
                    label: label.clone(),
                    hash: hash_key(&secret),
                    role: *role,
                    created_at: now_secs(),
                    disabled: false,
                });
                Ok(())
            })?;
            println!("Created key id={id} label={label} role={role}");
            println!("Secret (shown once, store it now):\n{secret}");
        }
        KeysCmd::List => {
            let file = load_file(keys_file)?;
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
        KeysCmd::Disable { id } => set_disabled(keys_file, id, true)?,
        KeysCmd::Enable { id } => set_disabled(keys_file, id, false)?,
        KeysCmd::Delete { id } => {
            update_file(keys_file, |file| remove_entry(file, id))?;
            println!("Deleted key id={id}");
        }
    }
    Ok(())
}

fn set_disabled(path: &Path, id: &str, disabled: bool) -> Result<(), ApiError> {
    update_file(path, |file| {
        let entry = file
            .keys
            .iter_mut()
            .find(|k| k.id == id)
            .ok_or_else(|| ApiError::BadRequest(format!("no key with id {id}")))?;
        entry.disabled = disabled;
        Ok(())
    })?;
    println!("{} key id={id}", if disabled { "Disabled" } else { "Enabled" });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Arc<KeyStore> {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("trickshot-keys-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        KeyStore::load(dir.join("keys.json")).unwrap()
    }

    #[test]
    fn concurrent_mutations_lose_nothing() {
        let s = store();
        let (victim, _) = s.create("leaked", Role::Render).unwrap();
        let other = KeyStore::load(s.path().to_path_buf()).unwrap();
        std::thread::scope(|scope| {
            for i in 0..16 {
                let s = if i % 2 == 0 { &s } else { &other };
                scope.spawn(move || s.create(&format!("k{i}"), Role::Render).unwrap());
            }
            scope.spawn(|| s.set_disabled(&victim.id, true).unwrap());
        });
        let on_disk = load_file(s.path()).unwrap();
        assert_eq!(on_disk.keys.len(), 17);
        assert!(on_disk.keys.iter().find(|k| k.id == victim.id).unwrap().disabled);
        let dir = s.path().parent().unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn mutation_rereads_file_changed_by_another_writer() {
        let s = store();
        let (a, _) = s.create("a", Role::Render).unwrap();
        run(&KeysCmd::Disable { id: a.id.clone() }, s.path()).unwrap();
        s.create("b", Role::Render).unwrap();
        assert!(!s.is_enabled(&a.id));
        assert!(load_file(s.path()).unwrap().keys.iter().find(|k| k.id == a.id).unwrap().disabled);
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
    fn fingerprint_detects_changes_only() {
        let mut file = KeyFile::default();
        let fp_empty = fingerprint(&file);
        assert_eq!(fp_empty, fingerprint(&file), "identical content → identical fingerprint");
        file.keys.push(KeyEntry {
            id: "a".into(),
            label: "l".into(),
            hash: "deadbeef".into(),
            role: Role::Render,
            created_at: 1,
            disabled: false,
        });
        let fp_one = fingerprint(&file);
        assert_ne!(fp_empty, fp_one, "adding a key changes the fingerprint");
        // Toggling a persisted field (disabled) changes the fingerprint.
        file.keys[0].disabled = true;
        assert_ne!(fp_one, fingerprint(&file), "disabling a key changes the fingerprint");
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
