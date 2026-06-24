// totp.rs — TOTP/2FA code generation

use totp_rs::{Algorithm, Secret, TOTP};

const TOTP_PERIOD_SECONDS: u64 = 30;
const MIN_TOTP_SECRET_BYTES: usize = 10; // 80 bits; common minimum for TOTP seeds.

#[derive(Debug)]
pub enum TotpError {
    InvalidSecret,
    GenerationFailed,
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TotpError::InvalidSecret => write!(f, "Invalid TOTP secret"),
            TotpError::GenerationFailed => write!(f, "Failed to generate TOTP code"),
        }
    }
}

impl std::error::Error for TotpError {}

/// Accepts either a raw Base32 secret or a basic otpauth:// URI and returns a
/// normalized uppercase Base32 secret without whitespace.
pub fn normalize_secret(input: &str) -> Option<String> {
    let raw = input.trim();
    if raw.is_empty() {
        return None;
    }

    let candidate = if raw.to_ascii_lowercase().starts_with("otpauth://") {
        extract_secret_from_otpauth_uri(raw)?
    } else {
        raw.to_string()
    };

    let normalized: String = candidate
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();

    let decoded = Secret::Encoded(normalized.clone()).to_bytes().ok()?;
    if decoded.len() < MIN_TOTP_SECRET_BYTES {
        return None;
    }

    Some(normalized)
}

/// Generate the current TOTP code from a Base32 secret string or otpauth URI.
pub fn generate_code(secret_input: &str) -> Result<String, TotpError> {
    let secret_base32 = normalize_secret(secret_input).ok_or(TotpError::InvalidSecret)?;
    let secret = Secret::Encoded(secret_base32)
        .to_bytes()
        .map_err(|_| TotpError::InvalidSecret)?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,                   // digits
        1,                   // allowed clock skew periods
        TOTP_PERIOD_SECONDS, // period in seconds
        secret,
    )
    .map_err(|_| TotpError::InvalidSecret)?;

    totp.generate_current()
        .map_err(|_| TotpError::GenerationFailed)
}

/// Returns how many seconds remain in the current 30-second TOTP window.
pub fn seconds_remaining() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    TOTP_PERIOD_SECONDS - (now % TOTP_PERIOD_SECONDS)
}

/// Validate that a TOTP secret is well-formed and has a minimally reasonable size.
pub fn validate_secret(secret: &str) -> bool {
    normalize_secret(secret).is_some()
}

fn extract_secret_from_otpauth_uri(uri: &str) -> Option<String> {
    let query = uri.split_once('?')?.1;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key.eq_ignore_ascii_case("secret") {
            return percent_decode(value);
        }
    }
    None
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = from_hex(bytes[i + 1])?;
                let lo = from_hex(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }

    String::from_utf8(out).ok()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_base32_secret() {
        assert_eq!(
            normalize_secret("jbswy3dpehpk3pxp"),
            Some("JBSWY3DPEHPK3PXP".to_string())
        );
    }

    #[test]
    fn accepts_otpauth_uri() {
        let uri = "otpauth://totp/Example:alice?secret=jbswy3dpehpk3pxp&issuer=Example";
        assert_eq!(
            normalize_secret(uri),
            Some("JBSWY3DPEHPK3PXP".to_string())
        );
    }

    #[test]
    fn rejects_too_short_secret() {
        assert!(!validate_secret("JBSWY3DPEH"));
    }
}
