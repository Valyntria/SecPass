// vault.rs — Vault data model, serialization, and file I/O

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{decrypt, encrypt, CryptoError, EncryptedBlob};

pub const MIN_MASTER_PASSWORD_CHARS: usize = 14;
const VAULT_DATA_VERSION: u32 = 2;
const FILE_MAGIC_V2: &str = "SECPASS2";
const FILE_MAGIC_V1: &str = "SECPASS1";
const MAX_VAULT_FILE_BYTES: u64 = 96 * 1024 * 1024;

/// A single vault entry.
///
/// Do not derive Debug here. The custom implementation below redacts secrets.
#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp_secret: Option<String>, // Base32 TOTP secret, if set
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Entry {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            title: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            totp_secret: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Returns true if the entry matches a search query (case-insensitive).
    pub fn matches(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_lowercase();
        self.title.to_lowercase().contains(&q)
            || self.username.to_lowercase().contains(&q)
            || self.url.to_lowercase().contains(&q)
            || self.notes.to_lowercase().contains(&q)
    }
}

impl Default for Entry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("url", &self.url)
            .field("notes", &"<redacted>")
            .field(
                "totp_secret",
                &self.totp_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.password.zeroize();
        self.notes.zeroize();
        if let Some(ref mut s) = self.totp_secret {
            s.zeroize();
        }
    }
}

/// The full vault — this is what gets serialized and encrypted.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub version: u32,
    pub entries: Vec<Entry>,
}

impl VaultData {
    pub fn new() -> Self {
        Self {
            version: VAULT_DATA_VERSION,
            entries: Vec::new(),
        }
    }
}

impl std::fmt::Debug for VaultData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultData")
            .field("version", &self.version)
            .field("entries_len", &self.entries.len())
            .finish()
    }
}

/// The in-memory vault state.
pub struct Vault {
    pub data: VaultData,
    pub path: PathBuf,
    password: SecretString, // kept for re-encryption on save; zeroized on drop
    pub is_modified: bool,
}

impl Vault {
    /// Create a new empty vault at the given path with the given master password.
    pub fn create(path: PathBuf, password: String) -> Result<Self, VaultError> {
        validate_master_password(&password)?;

        let mut vault = Self {
            data: VaultData::new(),
            path,
            password: SecretString::new(password),
            is_modified: false,
        };
        vault.save()?;
        Ok(vault)
    }

    /// Open an existing vault file with the given password.
    pub fn open(path: PathBuf, password: String) -> Result<Self, VaultError> {
        validate_file_size(&path)?;

        let raw = fs::read_to_string(&path).map_err(|e| VaultError::Io(e.to_string()))?;

        let (magic, blob_b64) = raw.split_once('\n').ok_or(VaultError::InvalidFormat)?;
        let magic = magic.trim();
        if magic != FILE_MAGIC_V2 && magic != FILE_MAGIC_V1 {
            return Err(VaultError::InvalidFormat);
        }

        let blob = EncryptedBlob::from_base64(blob_b64.trim())
            .map_err(|_| VaultError::InvalidFormat)?;

        let plaintext = Zeroizing::new(decrypt(&blob, &password).map_err(|e| match e {
            CryptoError::DecryptionFailed => VaultError::WrongPassword,
            CryptoError::InvalidFormat => VaultError::InvalidFormat,
            _ => VaultError::Crypto(e.to_string()),
        })?);

        let mut data: VaultData = serde_json::from_slice(plaintext.as_slice())
            .map_err(|e| VaultError::Corrupt(e.to_string()))?;

        // Upgrade older vault data in memory; it will be persisted as v2 on next save.
        if data.version == 0 {
            data.version = 1;
        }
        if data.version < VAULT_DATA_VERSION {
            data.version = VAULT_DATA_VERSION;
        }

        Ok(Self {
            data,
            path,
            password: SecretString::new(password),
            is_modified: false,
        })
    }

    /// Encrypt and write the vault to disk.
    pub fn save(&mut self) -> Result<(), VaultError> {
        self.data.version = VAULT_DATA_VERSION;

        let plaintext = Zeroizing::new(
            serde_json::to_vec(&self.data).map_err(|e| VaultError::Corrupt(e.to_string()))?,
        );

        let blob = encrypt(plaintext.as_slice(), self.password.expose_secret())
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        let content = format!("{}\n{}\n", FILE_MAGIC_V2, blob.to_base64());
        atomic_write_private(&self.path, content.as_bytes())?;

        self.is_modified = false;
        Ok(())
    }

    /// Change the master password and re-save.
    pub fn change_password(&mut self, new_password: String) -> Result<(), VaultError> {
        validate_master_password(&new_password)?;
        self.password = SecretString::new(new_password);
        self.save()
    }

    // --- Entry operations ---

    pub fn add_entry(&mut self, entry: Entry) {
        self.data.entries.push(entry);
        self.is_modified = true;
    }

    pub fn update_entry(&mut self, entry: Entry) {
        if let Some(e) = self.data.entries.iter_mut().find(|e| e.id == entry.id) {
            *e = entry;
            self.is_modified = true;
        }
    }

    pub fn delete_entry(&mut self, id: &str) {
        self.data.entries.retain(|e| e.id != id);
        self.is_modified = true;
    }

    pub fn search(&self, query: &str) -> Vec<&Entry> {
        self.data.entries.iter().filter(|e| e.matches(query)).collect()
    }

    pub fn vault_path(&self) -> &Path {
        &self.path
    }
}

pub fn validate_master_password(password: &str) -> Result<(), VaultError> {
    if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(VaultError::WeakPassword(format!(
            "Master password must be at least {} characters. Prefer a 4–6 word passphrase.",
            MIN_MASTER_PASSWORD_CHARS
        )));
    }
    Ok(())
}

fn validate_file_size(path: &Path) -> Result<(), VaultError> {
    let metadata = fs::metadata(path).map_err(|e| VaultError::Io(e.to_string()))?;
    if metadata.len() > MAX_VAULT_FILE_BYTES {
        return Err(VaultError::InvalidFormat);
    }
    Ok(())
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| VaultError::Io(e.to_string()))?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault.secpass");
    let prefix = format!(".{}.", file_name);

    let mut tmp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|e| VaultError::Io(e.to_string()))?;

    set_private_permissions(tmp.path())?;

    tmp.write_all(bytes)
        .map_err(|e| VaultError::Io(e.to_string()))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|e| VaultError::Io(e.to_string()))?;

    // tempfile::NamedTempFile::persist is used instead of std::fs::rename so the
    // replacement behavior is handled by the crate across platforms.
    let persisted = tmp
        .persist(path)
        .map_err(|e| VaultError::Io(e.error.to_string()))?;
    persisted
        .sync_all()
        .map_err(|e| VaultError::Io(e.to_string()))?;

    set_private_permissions(path)?;
    sync_parent_dir(parent)?;
    Ok(())
}

fn set_private_permissions(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions).map_err(|e| VaultError::Io(e.to_string()))?;
    }
    Ok(())
}

fn sync_parent_dir(parent: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        let dir = File::open(parent).map_err(|e| VaultError::Io(e.to_string()))?;
        dir.sync_all().map_err(|e| VaultError::Io(e.to_string()))?;
    }
    Ok(())
}

#[derive(Debug)]
pub enum VaultError {
    Io(String),
    Crypto(String),
    WrongPassword,
    WeakPassword(String),
    InvalidFormat,
    Corrupt(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(s) => write!(f, "File error: {}", s),
            VaultError::Crypto(s) => write!(f, "Crypto error: {}", s),
            VaultError::WrongPassword => write!(f, "Wrong master password"),
            VaultError::WeakPassword(s) => write!(f, "{}", s),
            VaultError::InvalidFormat => write!(f, "Not a valid SecPass vault file"),
            VaultError::Corrupt(s) => write!(f, "Vault data is corrupted: {}", s),
        }
    }
}

impl std::error::Error for VaultError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_master_password_is_rejected() {
        assert!(matches!(
            validate_master_password("short"),
            Err(VaultError::WeakPassword(_))
        ));
    }

    #[test]
    fn entry_debug_redacts_secrets() {
        let mut entry = Entry::new();
        entry.password = "secret-password".to_string();
        entry.notes = "secret note".to_string();
        entry.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());

        let rendered = format!("{:?}", entry);
        assert!(!rendered.contains("secret-password"));
        assert!(!rendered.contains("secret note"));
        assert!(!rendered.contains("JBSWY3DPEHPK3PXP"));
    }
}
