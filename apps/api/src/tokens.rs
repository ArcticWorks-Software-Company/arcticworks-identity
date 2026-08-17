//! Token and secret generation. Nothing here is ever stored in plaintext by
//! callers: opaque tokens are hashed (SHA-256) at rest and compared in
//! constant time.

use base64::Engine;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// 32 random bytes, base64url without padding. Use for opaque bearer tokens
/// (session tokens, auth codes, refresh tokens, invitation/verify/reset
/// tokens, enrollment tokens).
pub fn random_token() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Generate a prefixed secret (client secrets, service account credentials,
/// device credentials). The prefix makes leaked values recognizable.
pub fn random_secret(prefix: &str) -> SecretString {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    SecretString::from(format!("{prefix}_{body}"))
}

/// SHA-256 hex digest — the at-rest representation of an opaque token.
pub fn hash_token(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// Constant-time equality for token verification.
pub fn tokens_equal(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Short display hint for a secret (last 4 characters).
pub fn secret_preview(secret: &str) -> String {
    let end = secret.len().min(4);
    let tail: String = secret.chars().rev().take(end).collect::<Vec<_>>().into_iter().rev().collect();
    format!("…{tail}")
}

/// New access-token JTI (revocation identifier).
pub fn new_jti() -> uuid::Uuid {
    uuid::Uuid::now_v7()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_prefixed() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43); // 32 bytes base64url
        let s = random_secret("awcs");
        assert!(s.expose_secret().starts_with("awcs_"));
        assert_ne!(s.expose_secret(), random_secret("awcs").expose_secret());
    }

    #[test]
    fn hashing_and_equality() {
        let t = random_token();
        let h = hash_token(&t);
        assert_ne!(h, t);
        assert!(tokens_equal(&t, &t));
        assert!(!tokens_equal(&t, &random_token()));
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn preview_shows_tail() {
        let s = random_secret("awcs");
        let p = secret_preview(s.expose_secret());
        assert!(
            p.strip_prefix('…')
                .is_some_and(|tail| s.expose_secret().ends_with(tail)),
            "preview {p} must show the tail of the secret"
        );
    }
}
