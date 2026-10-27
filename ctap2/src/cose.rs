//! COSE_Key support (RFC 8152 §7) for the two key shapes CTAP2
//! moves around: EC2 P-256 keys — credential public keys in
//! attested credential data and ephemeral key-agreement keys in
//! the PIN protocol and the hmac-secret extension.
//!
//! COSE_Key for a P-256 public key is a CBOR map with integer
//! labels: `1: kty = 2 (EC2)`, `3: alg` (-7 ES256 for credential
//! keys, -25 ECDH-ES+HKDF-256 for key-agreement keys),
//! `-1: crv = 1 (P-256)`, `-2: x`, `-3: y`.

extern crate alloc;

use alloc::vec::Vec;

use crate::cbor::{encode, Value};
use crate::Error;

/// COSE kty for elliptic-curve keys (RFC 8152 §13).
pub const KTY_EC2: i64 = 2;
/// COSE alg ES256 (ECDSA P-256 + SHA-256) — credential keys.
pub const ALG_ES256: i64 = -7;
/// COSE alg ECDH-ES + HKDF-256 — key-agreement keys.
pub const ALG_ECDH_ES_HKDF_256: i64 = -25;
/// COSE crv P-256.
pub const CRV_P256: i64 = 1;

/// COSE label: key type.
pub const LABEL_KTY: i64 = 1;
/// COSE label: algorithm.
pub const LABEL_ALG: i64 = 3;
/// COSE label: curve.
pub const LABEL_CRV: i64 = -1;
/// COSE label: x coordinate.
pub const LABEL_X: i64 = -2;
/// COSE label: y coordinate.
pub const LABEL_Y: i64 = -3;

/// Build the COSE_Key map value for a P-256 public key given as
/// X || Y (the `AffinePoint::to_encoded` form).
pub fn ec2_key_value(public_encoded: &[u8; 64], alg: i64) -> Value {
    Value::Map(alloc::vec![
        (Value::int(LABEL_KTY), Value::int(KTY_EC2)),
        (Value::int(LABEL_ALG), Value::int(alg)),
        (Value::int(LABEL_CRV), Value::int(CRV_P256)),
        (
            Value::int(LABEL_X),
            Value::Bytes(public_encoded[..32].to_vec())
        ),
        (
            Value::int(LABEL_Y),
            Value::Bytes(public_encoded[32..].to_vec())
        ),
    ])
}

/// Encode a P-256 public key as a COSE_Key byte string.
pub fn encode_ec2_key(public_encoded: &[u8; 64], alg: i64) -> Vec<u8> {
    encode(&ec2_key_value(public_encoded, alg))
}

/// Parse a COSE_Key map into its X || Y public point, validating
/// kty/crv. Returns the algorithm too — callers pin the one they
/// expected (-7 for credential keys, -25 for key agreement).
pub fn parse_ec2_key(map: &Value) -> Result<([u8; 64], i64), Error> {
    let kty = map
        .get_int(LABEL_KTY)
        .and_then(|v| v.as_int())
        .ok_or(Error::Protocol("cose: missing kty"))?;
    if kty != KTY_EC2 {
        return Err(Error::Protocol("cose: kty is not EC2"));
    }
    let crv = map
        .get_int(LABEL_CRV)
        .and_then(|v| v.as_int())
        .ok_or(Error::Protocol("cose: missing crv"))?;
    if crv != CRV_P256 {
        return Err(Error::Protocol("cose: crv is not P-256"));
    }
    let alg = map
        .get_int(LABEL_ALG)
        .and_then(|v| v.as_int())
        .ok_or(Error::Protocol("cose: missing alg"))?;
    let x = map
        .get_int_key_bytes(LABEL_X)
        .ok_or(Error::Protocol("cose: missing x"))?;
    let y = map
        .get_int_key_bytes(LABEL_Y)
        .ok_or(Error::Protocol("cose: missing y"))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::Protocol("cose: coordinate length"));
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(x);
    out[32..].copy_from_slice(y);
    Ok((out, alg))
}
