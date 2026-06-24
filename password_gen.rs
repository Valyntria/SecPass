// password_gen.rs — Cryptographically secure password generator

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

pub const MIN_GENERATED_PASSWORD_LEN: usize = 8;
pub const MAX_GENERATED_PASSWORD_LEN: usize = 128;

#[derive(Clone)]
pub struct PasswordOptions {
    pub length: usize,
    pub use_uppercase: bool,
    pub use_digits: bool,
    pub use_symbols: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            use_uppercase: true,
            use_digits: true,
            use_symbols: true,
        }
    }
}

pub fn generate(opts: &PasswordOptions) -> String {
    let mut rng = ChaCha20Rng::from_entropy();

    let mut charset: Vec<u8> = LOWERCASE.to_vec();
    let mut required: Vec<u8> = Vec::new();

    // Always require at least one lowercase character.
    required.push(*LOWERCASE.choose(&mut rng).expect("LOWERCASE is non-empty"));

    if opts.use_uppercase {
        charset.extend_from_slice(UPPERCASE);
        required.push(*UPPERCASE.choose(&mut rng).expect("UPPERCASE is non-empty"));
    }
    if opts.use_digits {
        charset.extend_from_slice(DIGITS);
        required.push(*DIGITS.choose(&mut rng).expect("DIGITS is non-empty"));
    }
    if opts.use_symbols {
        charset.extend_from_slice(SYMBOLS);
        required.push(*SYMBOLS.choose(&mut rng).expect("SYMBOLS is non-empty"));
    }

    let length = opts
        .length
        .clamp(MIN_GENERATED_PASSWORD_LEN, MAX_GENERATED_PASSWORD_LEN)
        .max(required.len());

    let fill_len = length - required.len();
    let mut password: Vec<u8> = (0..fill_len)
        .map(|_| *charset.choose(&mut rng).expect("charset is non-empty"))
        .collect();

    password.extend_from_slice(&required);
    password.shuffle(&mut rng);

    // All selected character sets are ASCII, so this cannot fail.
    String::from_utf8(password).expect("generated password uses ASCII character sets")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_requested_length() {
        let opts = PasswordOptions::default();
        assert_eq!(generate(&opts).len(), opts.length);
    }

    #[test]
    fn generated_password_respects_minimum_length() {
        let opts = PasswordOptions {
            length: 1,
            ..PasswordOptions::default()
        };
        assert_eq!(generate(&opts).len(), MIN_GENERATED_PASSWORD_LEN);
    }
}
