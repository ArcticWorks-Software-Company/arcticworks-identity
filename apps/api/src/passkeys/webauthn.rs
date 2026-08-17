//! Minimal, pure-Rust WebAuthn verification (attestation `none`).
//!
//! Supports the three credential algorithms advertised in creation options:
//! ES256 (ECDSA P-256), RS256 (RSA PKCS#1 v1.5 SHA-256) and EdDSA (Ed25519).
//! No OpenSSL dependency; the platform builds anywhere.
//!
//! Flow: the server issues a random challenge; the browser signs
//! `authenticatorData || SHA-256(clientDataJSON)`; we verify the signature
//! against the COSE public key captured at registration. Registration with
//! attestation `none` carries no attestation statement to verify — security
//! rests on challenge/origin/rpId binding, which is checked here.

use base64::Engine;
use p256::ecdsa::signature::Verifier as _;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

pub const CHALLENGE_LEN: usize = 32;
pub const TIMEOUT_MS: u64 = 120_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Es256,
    Rs256,
    EdDsa,
}

#[derive(Debug, Clone)]
pub enum CoseKey {
    Ec2 { x: Vec<u8>, y: Vec<u8>, alg: Algorithm },
    Rsa { n: Vec<u8>, e: Vec<u8>, alg: Algorithm },
    Eddsa { x: Vec<u8>, alg: Algorithm },
}

#[derive(Debug)]
pub struct ParsedAuthData {
    pub flags: u8,
    pub counter: u32,
    pub credential_id: Option<Vec<u8>>,
    pub cose_key: Option<CoseKey>,
}

// ------------------------------------------------------------- base64 helpers

pub fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(s: &str) -> ApiResult<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .map_err(|_| ApiError::Validation("invalid base64url value".into()))
}

/// A random challenge, base64url encoded (the value handed to the browser).
pub fn new_challenge() -> String {
    let mut buf = [0u8; CHALLENGE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut buf);
    b64url_encode(&buf)
}

/// The user handle for a user: 16 bytes (the UUID representation).
pub fn user_handle(user_id: Uuid) -> Vec<u8> {
    user_id.as_bytes().to_vec()
}

// ------------------------------------------------------------ clientDataJSON

/// Validate `clientDataJSON` against the expected ceremony type, challenge
/// and origin. `challenge` is the base64url challenge we issued.
pub fn parse_client_data(
    client_data_json: &[u8],
    expected_type: &str,
    challenge: &str,
    rp_origins: &std::collections::HashSet<String>,
) -> ApiResult<()> {
    let cd: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|_| ApiError::Validation("clientDataJSON is not valid JSON".into()))?;

    let ty = cd.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if ty != expected_type {
        return Err(ApiError::Validation("unexpected clientDataJSON type".into()));
    }
    let ch = cd.get("challenge").and_then(|v| v.as_str()).unwrap_or("");
    if ch != challenge {
        return Err(ApiError::Validation("challenge mismatch".into()));
    }
    let origin = cd.get("origin").and_then(|v| v.as_str()).unwrap_or("");
    if !rp_origins.contains(origin) {
        return Err(ApiError::Validation("origin is not allowed".into()));
    }
    if cd.get("crossOrigin").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Err(ApiError::Validation("cross-origin WebAuthn is not allowed".into()));
    }
    Ok(())
}

// ----------------------------------------------------------- authenticatorData

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

/// Parse and validate authenticatorData. `rp_id` is hashed and compared;
/// user presence is required. When `expect_attested` is set, the attested
/// credential data section must be present (registration).
pub fn parse_authenticator_data(
    auth_data: &[u8],
    rp_id: &str,
    expect_attested: bool,
) -> ApiResult<ParsedAuthData> {
    if auth_data.len() < 37 {
        return Err(ApiError::Validation("authenticatorData too short".into()));
    }
    let expected_hash = Sha256::digest(rp_id.as_bytes());
    if auth_data[0..32] != expected_hash[..] {
        return Err(ApiError::Validation("rpIdHash mismatch".into()));
    }
    let flags = auth_data[32];
    if flags & FLAG_UP == 0 {
        return Err(ApiError::Validation("user presence required".into()));
    }
    let counter = u32::from_be_bytes(auth_data[33..37].try_into().expect("4 bytes"));

    if flags & FLAG_AT == 0 {
        if expect_attested {
            return Err(ApiError::Validation("missing attested credential data".into()));
        }
        return Ok(ParsedAuthData {
            flags,
            counter,
            credential_id: None,
            cose_key: None,
        });
    }

    let mut off = 37;
    if auth_data.len() < off + 18 {
        return Err(ApiError::Validation("authenticatorData truncated".into()));
    }
    off += 16; // AAGUID
    let cred_len = u16::from_be_bytes([auth_data[off], auth_data[off + 1]]) as usize;
    off += 2;
    if auth_data.len() < off + cred_len {
        return Err(ApiError::Validation("authenticatorData truncated".into()));
    }
    let credential_id = auth_data[off..off + cred_len].to_vec();
    off += cred_len;

    let cose_key = parse_cose_key(&auth_data[off..])?;

    Ok(ParsedAuthData {
        flags,
        counter,
        credential_id: Some(credential_id),
        cose_key: Some(cose_key),
    })
}

/// Whether user verification was performed (reported by the authenticator).
pub fn user_verified(flags: u8) -> bool {
    flags & FLAG_UV != 0
}

// ------------------------------------------------------------------- COSE

/// Convert a DER-encoded ECDSA signature (SEQUENCE of two INTEGERs, as
/// produced by CTAP2 authenticators) into the raw 64-byte r||s form the
/// WebAuthn spec expects. Returns None when the input is not DER.
fn der_ecdsa_to_raw(sig: &[u8]) -> Option<Vec<u8>> {
    if sig.len() < 8 || sig[0] != 0x30 {
        return None;
    }
    let seq_len = sig[1] as usize;
    if seq_len + 2 != sig.len() {
        return None;
    }
    let mut off = 2;
    let mut parts = Vec::new();
    for _ in 0..2 {
        if off + 2 > sig.len() || sig[off] != 0x02 {
            return None;
        }
        let len = sig[off + 1] as usize;
        off += 2;
        if off + len > sig.len() {
            return None;
        }
        let mut val = sig[off..off + len].to_vec();
        while val.len() > 1 && val[0] == 0 {
            val.remove(0);
        }
        if val.len() > 32 {
            return None;
        }
        while val.len() < 32 {
            val.insert(0, 0);
        }
        parts.push(val);
        off += len;
    }
    if off != sig.len() {
        return None;
    }
    Some(parts.concat())
}

/// Parse a COSE_Key structure (CBOR map) into our representation.
pub fn parse_cose_key(cose: &[u8]) -> ApiResult<CoseKey> {
    let value: ciborium::Value = ciborium::de::from_reader(cose)
        .map_err(|_| ApiError::Validation("invalid COSE key".into()))?;
    let map = value
        .as_map()
        .ok_or_else(|| ApiError::Validation("invalid COSE key".into()))?;

    let get_int = |key: i64| -> ApiResult<i64> {
        map.iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Integer(i) if i128::from(*i) == key as i128))
            .and_then(|(_, v)| match v {
                ciborium::Value::Integer(i) => i64::try_from(i128::from(*i)).ok(),
                _ => None,
            })
            .ok_or_else(|| ApiError::Validation("COSE key missing field".into()))
    };
    let get_bytes = |key: i64| -> ApiResult<Vec<u8>> {
        map.iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Integer(i) if i128::from(*i) == key as i128))
            .and_then(|(_, v)| v.as_bytes())
            .cloned()
            .ok_or_else(|| ApiError::Validation("COSE key missing field".into()))
    };

    let alg = match get_int(3)? {
        -7 => Algorithm::Es256,
        -257 => Algorithm::Rs256,
        -8 => Algorithm::EdDsa,
        other => return Err(ApiError::Validation(format!("unsupported COSE algorithm {other}"))),
    };

    match get_int(1)? {
        2 => {
            // EC2: crv must be P-256 (1) for our advertised algs.
            if get_int(-1)? != 1 {
                return Err(ApiError::Validation("unsupported EC curve".into()));
            }
            Ok(CoseKey::Ec2 {
                x: get_bytes(-2)?,
                y: get_bytes(-3)?,
                alg,
            })
        }
        3 => Ok(CoseKey::Rsa {
            n: get_bytes(-1)?,
            e: get_bytes(-2)?,
            alg,
        }),
        1 => {
            // OKP: crv must be Ed25519 (6).
            if get_int(-1)? != 6 {
                return Err(ApiError::Validation("unsupported OKP curve".into()));
            }
            Ok(CoseKey::Eddsa {
                x: get_bytes(-2)?,
                alg,
            })
        }
        other => Err(ApiError::Validation(format!("unsupported COSE key type {other}"))),
    }
}

// -------------------------------------------------------------- signatures

/// Verify the assertion signature over `authenticatorData || SHA-256(clientDataJSON)`.
pub fn verify_signature(
    key: &CoseKey,
    auth_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> ApiResult<()> {
    let client_hash = Sha256::digest(client_data_json);
    let mut msg = auth_data.to_vec();
    msg.extend_from_slice(&client_hash);

    match key {
        CoseKey::Ec2 { x, y, alg } => {
            if *alg != Algorithm::Es256 {
                return Err(ApiError::Validation("key/algorithm mismatch".into()));
            }
            let x_arr: [u8; 32] = x
                .as_slice()
                .try_into()
                .map_err(|_| ApiError::Validation("invalid P-256 x coordinate".into()))?;
            let y_arr: [u8; 32] = y
                .as_slice()
                .try_into()
                .map_err(|_| ApiError::Validation("invalid P-256 y coordinate".into()))?;
            let point = p256::EncodedPoint::from_affine_coordinates(
                &p256::FieldBytes::from(x_arr),
                &p256::FieldBytes::from(y_arr),
                false,
            );
            let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
                .map_err(|_| ApiError::Validation("invalid P-256 public key".into()))?;
            // Accept both raw r||s (WebAuthn) and DER (CTAP2 authenticators).
            let normalized: Vec<u8> = if signature.len() == 64 {
                signature.to_vec()
            } else {
                der_ecdsa_to_raw(signature)
                    .ok_or_else(|| ApiError::Validation("invalid ES256 signature".into()))?
            };
            let sig = p256::ecdsa::Signature::try_from(normalized.as_slice())
                .map_err(|_| ApiError::Validation("invalid ES256 signature".into()))?;
            vk.verify(&msg, &sig)
                .map_err(|_| ApiError::Validation("ES256 signature verification failed".into()))
        }
        CoseKey::Rsa { n, e, alg } => {
            if *alg != Algorithm::Rs256 {
                return Err(ApiError::Validation("key/algorithm mismatch".into()));
            }
            let n = rsa::BigUint::from_bytes_be(n);
            let e = rsa::BigUint::from_bytes_be(e);
            let pk = rsa::RsaPublicKey::new(n, e)
                .map_err(|_| ApiError::Validation("invalid RSA public key".into()))?;
            let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pk);
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| ApiError::Validation("invalid RS256 signature".into()))?;
            vk.verify(&msg, &sig)
                .map_err(|_| ApiError::Validation("RS256 signature verification failed".into()))
        }
        CoseKey::Eddsa { x, alg } => {
            if *alg != Algorithm::EdDsa {
                return Err(ApiError::Validation("key/algorithm mismatch".into()));
            }
            let x_arr: [u8; 32] = x
                .as_slice()
                .try_into()
                .map_err(|_| ApiError::Validation("invalid Ed25519 public key".into()))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&x_arr)
                .map_err(|_| ApiError::Validation("invalid Ed25519 public key".into()))?;
            let sig = ed25519_dalek::Signature::try_from(signature)
                .map_err(|_| ApiError::Validation("invalid EdDSA signature".into()))?;
            vk.verify(&msg, &sig)
                .map_err(|_| ApiError::Validation("EdDSA signature verification failed".into()))
        }
    }
}

/// Parse an attestationObject (registration): requires `fmt == "none"`.
pub fn parse_attestation_object(attestation_object: &[u8]) -> ApiResult<Vec<u8>> {
    let value: ciborium::Value = ciborium::de::from_reader(attestation_object)
        .map_err(|_| ApiError::Validation("invalid attestationObject".into()))?;
    let map = value
        .as_map()
        .ok_or_else(|| ApiError::Validation("invalid attestationObject".into()))?;

    let fmt = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("fmt"))
        .and_then(|(_, v)| v.as_text())
        .unwrap_or("");
    if fmt != "none" {
        return Err(ApiError::Validation("only attestation format 'none' is supported".into()));
    }

    map.iter()
        .find(|(k, _)| k.as_text() == Some("authData"))
        .and_then(|(_, v)| v.as_bytes())
        .cloned()
        .ok_or_else(|| ApiError::Validation("attestationObject missing authData".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::{Signer, Verifier as _};
    use p256::ecdsa::{SigningKey, VerifyingKey};

    fn build_auth_data(rp_id: &str, counter: u32, with_credential: bool, cred_id: &[u8], cose: &[u8]) -> Vec<u8> {
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut out = rp_hash.to_vec();
        let mut flags = FLAG_UP;
        if with_credential {
            flags |= FLAG_AT;
        }
        out.push(flags);
        out.extend_from_slice(&counter.to_be_bytes());
        if with_credential {
            out.extend_from_slice(&[0u8; 16]); // aaguid
            out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
            out.extend_from_slice(cred_id);
            out.extend_from_slice(cose);
        }
        out
    }

    fn cose_key_ec2(x: &[u8], y: &[u8]) -> Vec<u8> {
        use ciborium::value::Integer as CborInt;
        use ciborium::Value as V;
        let value = V::Map(vec![
            (V::Integer(CborInt::from(1)), V::Integer(CborInt::from(2))),
            (V::Integer(CborInt::from(3)), V::Integer(CborInt::from(-7))),
            (V::Integer(CborInt::from(-1)), V::Integer(CborInt::from(1))),
            (V::Integer(CborInt::from(-2)), V::Bytes(x.to_vec())),
            (V::Integer(CborInt::from(-3)), V::Bytes(y.to_vec())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf).unwrap();
        buf
    }

    #[test]
    fn es256_signature_roundtrip() {
        let rp_id = "localhost";
        let origin = "http://localhost:5173";
        let origins: std::collections::HashSet<String> =
            [origin.to_string()].into_iter().collect();
        let challenge = new_challenge();

        // Client data exactly as the browser would produce it.
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": origin,
        });
        let client_data_bytes = serde_json::to_vec(&client_data).unwrap();

        // A real P-256 key; the public part becomes the COSE key.
        let mut rng = rand_core::OsRng;
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let point = verifying_key.to_encoded_point(false);
        let (x, y) = (
            point.x().unwrap().to_vec(),
            point.y().unwrap().to_vec(),
        );
        let cose = cose_key_ec2(&x, &y);
        let key = parse_cose_key(&cose).expect("parse COSE key");

        // Authenticator data (no attested credential on auth).
        let auth_data = build_auth_data(rp_id, 42, false, &[], &[]);
        let parsed = parse_authenticator_data(&auth_data, rp_id, false).expect("parse auth data");
        assert_eq!(parsed.counter, 42);

        // The authenticator signs authData || SHA-256(clientDataJSON).
        let mut msg = auth_data.clone();
        msg.extend_from_slice(&Sha256::digest(&client_data_bytes));
        let (signature, _) = signing_key.sign(&msg);
        let raw_sig: Vec<u8> = signature.to_bytes().to_vec();
        assert_eq!(raw_sig.len(), 64);

        // Verify with our implementation.
        parse_client_data(&client_data_bytes, "webauthn.get", &challenge, &origins).expect("client data");
        verify_signature(&key, &auth_data, &client_data_bytes, &raw_sig).expect("verify");

        // Full store -> reload roundtrip, exactly as the passkey module does:
        // serialize the parsed key to COSE bytes, store as base64url, parse
        // again at authentication time.
        let stored = crate::passkeys::cose_key_to_bytes(&key).expect("serialize");
        let reloaded = parse_cose_key(&base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &stored).unwrap())
            .expect("reparse stored key");
        verify_signature(&reloaded, &auth_data, &client_data_bytes, &raw_sig).expect("verify after reload");
    }
}
