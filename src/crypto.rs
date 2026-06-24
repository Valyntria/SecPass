// crypto.rs — AES-256-GCM encryption + Argon2id key derivation
// Hardened format: versioned, self-describing KDF parameters, strict validation.

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use zeroize::Zeroizing;

const BLOB_MAGIC: &[u8; 4] = b"SPB2";
const BLOB_VERSION: u8 = 2;

// Argon2id parameters — stored in every encrypted blob so future changes do not
// make old vaults unreadable.
pub const DEFAULT_ARGON2_M_COST: u32 = 65_536; // 64 MiB
pub const DEFAULT_ARGON2_T_COST: u32 = 3;
pub const DEFAULT_ARGON2_P_COST: u32 = 4;

const KEY_LEN: usize = 32; // 256-bit key
const SALT_LEN: usize = 32; // 256-bit salt
const NONCE_LEN: usize = 12; // AES-GCM standard nonce size
const GCM_TAG_LEN: usize = 16;

// Defensive cap for a local password-vault blob. Increase deliberately if you
// later support very large attachments.
const MAX_DECODED_BLOB_BYTES: usize = 64 * 1024 * 1024;
const MAX_BASE64_CHARS: usize = MAX_DECODED_BLOB_BYTES.div_ceil(3) * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub const fn interactive_default() -> Self {
        Self {
            m_cost: DEFAULT_ARGON2_M_COST,
            t_cost: DEFAULT_ARGON2_T_COST,
            p_cost: DEFAULT_ARGON2_P_COST,
        }
    }

    fn validate(self) -> Result<(), CryptoError> {
        // Keep this broad enough for forward compatibility, but reject obviously
        // malicious/unusable parameter sets that could cause denial-of-service.
        if self.m_cost < 19_456 || self.m_cost > 1_048_576 {
            return Err(CryptoError::InvalidFormat);
        }
        if self.t_cost == 0 || self.t_cost > 20 {
            return Err(CryptoError::InvalidFormat);
        }
        if self.p_cost == 0 || self.p_cost > 16 {
            return Err(CryptoError::InvalidFormat);
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::interactive_default()
    }
}

#[derive(Clone)]
pub struct EncryptedBlob {
    kdf: KdfParams,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl std::fmt::Debug for EncryptedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedBlob")
            .field("kdf", &self.kdf)
            .field("salt_len", &self.salt.len())
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl EncryptedBlob {
    fn new(
        kdf: KdfParams,
        salt: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        let blob = Self {
            kdf,
            salt,
            nonce,
            ciphertext,
        };
        blob.validate()?;
        Ok(blob)
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.kdf
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn validate(&self) -> Result<(), CryptoError> {
        self.kdf.validate()?;
        if self.salt.len() != SALT_LEN {
            return Err(CryptoError::InvalidFormat);
        }
        if self.nonce.len() != NONCE_LEN {
            return Err(CryptoError::InvalidFormat);
        }
        if self.ciphertext.len() < GCM_TAG_LEN {
            return Err(CryptoError::InvalidFormat);
        }
        Ok(())
    }

    /// Serialize to a single base64 string.
    ///
    /// Binary format before base64:
    /// SPB2 || version_u8 || m_cost_be || t_cost_be || p_cost_be || salt_32 || nonce_12 || ciphertext
    pub fn to_base64(&self) -> String {
        // `EncryptedBlob` can only be created through validated constructors, so
        // this should not fail unless a future maintainer breaks invariants.
        debug_assert!(self.validate().is_ok());

        let mut buf = Vec::with_capacity(
            BLOB_MAGIC.len() + 1 + 12 + SALT_LEN + NONCE_LEN + self.ciphertext.len(),
        );
        buf.extend_from_slice(BLOB_MAGIC);
        buf.push(BLOB_VERSION);
        buf.extend_from_slice(&self.kdf.m_cost.to_be_bytes());
        buf.extend_from_slice(&self.kdf.t_cost.to_be_bytes());
        buf.extend_from_slice(&self.kdf.p_cost.to_be_bytes());
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        BASE64.encode(&buf)
    }

    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        let s = s.trim();
        if s.is_empty() || s.len() > MAX_BASE64_CHARS {
            return Err(CryptoError::InvalidFormat);
        }

        let buf = BASE64.decode(s).map_err(|_| CryptoError::InvalidFormat)?;
        if buf.len() > MAX_DECODED_BLOB_BYTES {
            return Err(CryptoError::InvalidFormat);
        }

        if buf.starts_with(BLOB_MAGIC) {
            Self::parse_v2(&buf)
        } else {
            // Backward-compatible read path for the original prototype format:
            // base64(salt_len_u8 || salt || nonce_len_u8 || nonce || ciphertext)
            Self::parse_legacy_v1(&buf)
        }
    }

    fn parse_v2(buf: &[u8]) -> Result<Self, CryptoError> {
        let min_len = BLOB_MAGIC.len() + 1 + 12 + SALT_LEN + NONCE_LEN + GCM_TAG_LEN;
        if buf.len() < min_len {
            return Err(CryptoError::InvalidFormat);
        }

        let mut cursor = BLOB_MAGIC.len();
        let version = *buf.get(cursor).ok_or(CryptoError::InvalidFormat)?;
        cursor += 1;
        if version != BLOB_VERSION {
            return Err(CryptoError::InvalidFormat);
        }

        let m_cost = read_u32_be(buf, &mut cursor)?;
        let t_cost = read_u32_be(buf, &mut cursor)?;
        let p_cost = read_u32_be(buf, &mut cursor)?;
        let kdf = KdfParams {
            m_cost,
            t_cost,
            p_cost,
        };

        let salt = take(buf, &mut cursor, SALT_LEN)?.to_vec();
        let nonce = take(buf, &mut cursor, NONCE_LEN)?.to_vec();
        let ciphertext = buf.get(cursor..).ok_or(CryptoError::InvalidFormat)?.to_vec();

        Self::new(kdf, salt, nonce, ciphertext)
    }

    fn parse_legacy_v1(buf: &[u8]) -> Result<Self, CryptoError> {
        let mut cursor = 0usize;

        let salt_len = *buf.get(cursor).ok_or(CryptoError::InvalidFormat)? as usize;
        cursor += 1;
        let salt = take(buf, &mut cursor, salt_len)?.to_vec();

        let nonce_len = *buf.get(cursor).ok_or(CryptoError::InvalidFormat)? as usize;
        cursor += 1;
        let nonce = take(buf, &mut cursor, nonce_len)?.to_vec();

        let ciphertext = buf.get(cursor..).ok_or(CryptoError::InvalidFormat)?.to_vec();

        // Strictly validate legacy blobs too. This prevents malformed files from
        // reaching `Nonce::from_slice` and crashing the app.
        Self::new(KdfParams::interactive_default(), salt, nonce, ciphertext)
    }
}

#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed, // Wrong password or corrupted data
    InvalidFormat,
    KeyDerivationFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Wrong password or corrupted vault"),
            CryptoError::InvalidFormat => write!(f, "Invalid vault format"),
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

fn derive_key(password: &str, salt: &[u8], kdf: KdfParams) -> Result<[u8; KEY_LEN], CryptoError> {
    kdf.validate()?;
    if salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidFormat);
    }

    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(key)
}

/// Encrypt plaintext bytes with a password. Returns an EncryptedBlob.
pub fn encrypt(plaintext: &[u8], password: &str) -> Result<EncryptedBlob, CryptoError> {
    encrypt_with_params(plaintext, password, KdfParams::interactive_default())
}

pub fn encrypt_with_params(
    plaintext: &[u8],
    password: &str,
    kdf: KdfParams,
) -> Result<EncryptedBlob, CryptoError> {
    kdf.validate()?;

    let mut rng = OsRng;

    let mut salt = vec![0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    let key_bytes = Zeroizing::new(derive_key(password, &salt, kdf)?);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes[..]);
    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut rng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    EncryptedBlob::new(kdf, salt, nonce.to_vec(), ciphertext)
}

/// Decrypt an EncryptedBlob with a password. Returns plaintext bytes.
pub fn decrypt(blob: &EncryptedBlob, password: &str) -> Result<Vec<u8>, CryptoError> {
    blob.validate()?;

    let key_bytes = Zeroizing::new(derive_key(password, blob.salt(), blob.kdf_params())?);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes[..]);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(blob.nonce());

    cipher
        .decrypt(nonce, blob.ciphertext())
        .map_err(|_| CryptoError::DecryptionFailed)
}

fn read_u32_be(buf: &[u8], cursor: &mut usize) -> Result<u32, CryptoError> {
    let bytes = take(buf, cursor, 4)?;
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| CryptoError::InvalidFormat)?,
    ))
}

fn take<'a>(buf: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], CryptoError> {
    let end = cursor.checked_add(len).ok_or(CryptoError::InvalidFormat)?;
    let out = buf.get(*cursor..end).ok_or(CryptoError::InvalidFormat)?;
    *cursor = end;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let blob = encrypt(b"hello", "correct horse battery staple").unwrap();
        let plaintext = decrypt(&blob, "correct horse battery staple").unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn wrong_password_fails() {
        let blob = encrypt(b"hello", "right password").unwrap();
        assert!(matches!(
            decrypt(&blob, "wrong password"),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn rejects_bad_nonce_length_without_panic() {
        let blob = EncryptedBlob {
            kdf: KdfParams::interactive_default(),
            salt: vec![0u8; SALT_LEN],
            nonce: vec![0u8; 1],
            ciphertext: vec![0u8; GCM_TAG_LEN],
        };

        assert!(matches!(
            decrypt(&blob, "password"),
            Err(CryptoError::InvalidFormat)
        ));
    }

    #[test]
    fn rejects_empty_ciphertext_without_panic() {
        let blob = EncryptedBlob {
            kdf: KdfParams::interactive_default(),
            salt: vec![0u8; SALT_LEN],
            nonce: vec![0u8; NONCE_LEN],
            ciphertext: vec![],
        };

        assert!(matches!(
            decrypt(&blob, "password"),
            Err(CryptoError::InvalidFormat)
        ));
    }
}
