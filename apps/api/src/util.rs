//! Input validation helpers. Validation is intentionally strict: anything
//! that does not match the documented shape is rejected.

/// Minimal email shape check (presence of exactly one @, non-empty local and
/// domain, no whitespace). Real deliverability is handled by the sending
/// layer; this only prevents junk input.
pub fn is_valid_email(email: &str) -> bool {
    let email = email.trim();
    if email.len() > 254 || email.len() < 3 {
        return false;
    }
    if email.contains(char::is_whitespace) {
        return false;
    }
    let mut parts = email.rsplitn(2, '@');
    let domain = parts.next().unwrap();
    let Some(local) = parts.next() else { return false };
    !local.is_empty() && !domain.is_empty() && domain.contains('.')
}

/// Organization slug: lowercase letters, digits and hyphens, 3..=63 chars,
/// starts and ends with an alphanumeric character.
pub fn is_valid_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    let len = bytes.len();
    if !(3..=63).contains(&len) {
        return false;
    }
    let valid = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
    bytes.iter().all(|&b| valid(b))
        && bytes[0].is_ascii_alphanumeric()
        && bytes[len - 1].is_ascii_alphanumeric()
}

/// Permission identifier: `product.resource.action`, at least three
/// lowercase-dash segments, e.g. `continuity.document.read`.
pub fn is_valid_permission(p: &str) -> bool {
    let segments: Vec<&str> = p.split('.').collect();
    if segments.len() < 3 {
        return false;
    }
    segments.iter().all(|seg| {
        !seg.is_empty()
            && seg.len() <= 32
            && seg.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && seg.starts_with(|c: char| c.is_ascii_lowercase())
    })
}

/// Password policy: 8..=128 characters, UTF-8. Argon2id handles the rest.
pub fn is_valid_password(p: &str) -> bool {
    (8..=128).contains(&p.chars().count())
}

/// Redirect URI policy: must be absolute http(s); http is only allowed for
/// loopback hosts (localhost / 127.0.0.1, any port) for development.
/// Fragments are forbidden (OAuth security requirement).
pub fn is_valid_redirect_uri(uri: &str) -> bool {
    let Ok(url) = url::Url::parse(uri) else {
        return false;
    };
    match url.scheme() {
        "https" => {}
        "http" => {
            let host = url.host_str().unwrap_or("");
            if host != "localhost" && host != "127.0.0.1" && host != "::1" {
                return false;
            }
        }
        _ => return false,
    }
    url.fragment().is_none() && !url.username().is_empty() == false
}

/// Standard OIDC scope validation (subset used by Identity).
pub fn is_valid_scope_set(scopes: &[String]) -> bool {
    const ALLOWED: [&str; 4] = ["openid", "profile", "email", "offline_access"];
    !scopes.is_empty()
        && scopes
            .iter()
            .all(|s| ALLOWED.contains(&s.as_str()) && !s.contains(char::is_whitespace))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails() {
        assert!(is_valid_email("a@b.co"));
        assert!(is_valid_email("first.last+tag@example.com"));
        assert!(!is_valid_email("not-an-email"));
        assert!(!is_valid_email("a@b"));
        assert!(!is_valid_email("sp ace@example.com"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email(""));
    }

    #[test]
    fn slugs() {
        assert!(is_valid_slug("acme"));
        assert!(is_valid_slug("acme-corp-2"));
        assert!(!is_valid_slug("ab"));
        assert!(!is_valid_slug("Acme"));
        assert!(!is_valid_slug("acme_"));
        assert!(!is_valid_slug("a--"));
        assert!(!is_valid_slug("-acme"));
    }

    #[test]
    fn permissions() {
        assert!(is_valid_permission("continuity.document.read"));
        assert!(is_valid_permission("org.members.manage"));
        assert!(is_valid_permission("a.b.c"));
        assert!(!is_valid_permission("continuity.read"));
        assert!(!is_valid_permission("continuity.Document.read"));
        assert!(!is_valid_permission("continuity..read"));
        assert!(!is_valid_permission(""));
    }

    #[test]
    fn passwords() {
        assert!(is_valid_password("12345678"));
        assert!(!is_valid_password("1234567"));
        assert!(!is_valid_password(&"x".repeat(129)));
    }

    #[test]
    fn redirect_uris() {
        assert!(is_valid_redirect_uri("https://app.example.com/callback"));
        assert!(is_valid_redirect_uri("http://localhost:5174/callback"));
        assert!(is_valid_redirect_uri("http://127.0.0.1:8080/cb"));
        assert!(!is_valid_redirect_uri("http://evil.example.com/cb"));
        assert!(!is_valid_redirect_uri("javascript:alert(1)"));
        assert!(!is_valid_redirect_uri("https://app.example.com/cb#fragment"));
        assert!(!is_valid_redirect_uri("not a url"));
        assert!(!is_valid_redirect_uri("/relative/path"));
    }
}
