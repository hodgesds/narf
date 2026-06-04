//! TPM 2.0 object types — TPM2B_PUBLIC, TPM2B_PRIVATE, key templates.
//!
//! These types represent the wire-format blobs that the TPM returns
//! from `TPM2_Create` / `TPM2_ReadPublic` and that callers pass back
//! to `TPM2_Load`.
//!
//! ## Key types supported
//!
//! - RSA-2048 (restricted/unrestricted signing + decryption)
//! - ECC P-256 (NIST_P256) — secp256r1
//! - ECC P-384 (NIST_P384) — secp384r1
//!
//! ## Reference
//!
//! TCG TPM Library Specification, Family 2.0, Rev 1.59:
//! Part 2 §12 (Key/Object complex); Part 2 §11 (TPM2B structures).

extern crate alloc;

use super::{
    TPM_ALG_ECC, TPM_ALG_NULL, TPM_ALG_RSA, TPM_ALG_SHA256, TPM_ECC_NIST_P256, TPM_ECC_NIST_P384,
};
use alloc::vec::Vec;

// ── TPMA_OBJECT attribute bits — Part 2 §8.3 ─────────────────────────

/// Object is fixed under the parent (cannot be duplicated).
pub const OBJ_FIXED_TPM: u32 = 1 << 1;
/// Object's hierarchy will not change.
pub const OBJ_ST_CLEAR: u32 = 1 << 2;
/// Object is fixed parent (parent cannot be evicted).
pub const OBJ_FIXED_PARENT: u32 = 1 << 4;
/// Object was created with a sensitive area.
pub const OBJ_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
/// Object may be used only with specific authorization.
pub const OBJ_USER_WITH_AUTH: u32 = 1 << 6;
/// Object is a restricted key (signing PCR data, etc.).
pub const OBJ_RESTRICTED: u32 = 1 << 16;
/// Object can decrypt.
pub const OBJ_DECRYPT: u32 = 1 << 17;
/// Object can sign.
pub const OBJ_SIGN: u32 = 1 << 18;

/// Typical attribute set for a storage key (parent of other keys).
pub const OBJ_ATTR_STORAGE: u32 = OBJ_FIXED_TPM
    | OBJ_ST_CLEAR
    | OBJ_FIXED_PARENT
    | OBJ_SENSITIVE_DATA_ORIGIN
    | OBJ_USER_WITH_AUTH
    | OBJ_RESTRICTED
    | OBJ_DECRYPT;

/// Typical attribute set for a sealing / data object.
pub const OBJ_ATTR_SEAL: u32 = OBJ_FIXED_TPM
    | OBJ_ST_CLEAR
    | OBJ_FIXED_PARENT
    | OBJ_SENSITIVE_DATA_ORIGIN
    | OBJ_USER_WITH_AUTH;

// ── Key type selector ─────────────────────────────────────────────────

/// The set of key algorithms NARF supports natively.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    /// RSA-2048 with RSASSA-PKCS1v1_5 (SHA-256 nameAlg).
    Rsa2048,
    /// ECDSA on NIST P-256 (secp256r1).
    EccP256,
    /// ECDSA on NIST P-384 (secp384r1).
    EccP384,
}

impl KeyType {
    /// Return the `TPM_ALG_ID` for this key type's asymmetric algorithm.
    pub fn tpm_alg(&self) -> u16 {
        match self {
            KeyType::Rsa2048 => TPM_ALG_RSA,
            KeyType::EccP256 | KeyType::EccP384 => TPM_ALG_ECC,
        }
    }

    /// Return the `TPM_ECC_CURVE` for ECC types, or 0 for RSA.
    pub fn ecc_curve(&self) -> u16 {
        match self {
            KeyType::EccP256 => TPM_ECC_NIST_P256,
            KeyType::EccP384 => TPM_ECC_NIST_P384,
            KeyType::Rsa2048 => 0,
        }
    }

    /// Return the signing/decryption digest algorithm ID.
    pub fn digest_alg(&self) -> u16 {
        TPM_ALG_SHA256
    }
}

// ── TPM2B wrappers ────────────────────────────────────────────────────

/// `TPM2B_PUBLIC` — the public part of an asymmetric key as returned
/// by `TPM2_Create` or `TPM2_ReadPublic`. The inner bytes are a
/// serialised `TPMT_PUBLIC` structure (Part 2 §12.2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tpm2bPublic {
    /// Raw `TPMT_PUBLIC` bytes (without the TPM2B size prefix).
    pub inner: Vec<u8>,
}

impl Tpm2bPublic {
    /// Wrap a raw `TPMT_PUBLIC` byte slice.
    pub fn from_bytes(b: &[u8]) -> Self {
        Self { inner: b.to_vec() }
    }

    /// Encode as a `TPM2B_PUBLIC` on the wire: u16 size + inner bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.inner.len());
        out.extend_from_slice(&(self.inner.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.inner);
        out
    }

    /// Parse `algorithm` field (bytes 0..1 of the inner TPMT_PUBLIC).
    pub fn algorithm(&self) -> Option<u16> {
        if self.inner.len() >= 2 {
            Some(u16::from_be_bytes([self.inner[0], self.inner[1]]))
        } else {
            None
        }
    }

    /// Parse `nameAlg` (bytes 2..3 of the inner TPMT_PUBLIC).
    pub fn name_alg(&self) -> Option<u16> {
        if self.inner.len() >= 4 {
            Some(u16::from_be_bytes([self.inner[2], self.inner[3]]))
        } else {
            None
        }
    }

    /// Parse `objectAttributes` (bytes 4..7).
    pub fn object_attributes(&self) -> Option<u32> {
        if self.inner.len() >= 8 {
            Some(u32::from_be_bytes([
                self.inner[4],
                self.inner[5],
                self.inner[6],
                self.inner[7],
            ]))
        } else {
            None
        }
    }
}

/// `TPM2B_PRIVATE` — the encrypted private part of a key returned by
/// `TPM2_Create`. Opaque to the host; the TPM decrypts it on `Load`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tpm2bPrivate {
    /// Raw encrypted private-area bytes (without the TPM2B size prefix).
    pub inner: Vec<u8>,
}

impl Tpm2bPrivate {
    pub fn from_bytes(b: &[u8]) -> Self {
        Self { inner: b.to_vec() }
    }

    /// Encode as a `TPM2B_PRIVATE` on the wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.inner.len());
        out.extend_from_slice(&(self.inner.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.inner);
        out
    }
}

/// Pair of public + private key blobs returned by `TPM2_Create`.
#[derive(Clone, Debug)]
pub struct KeyBlobs {
    pub public: Tpm2bPublic,
    pub private: Tpm2bPrivate,
}

// ── TPMT_PUBLIC template builders ────────────────────────────────────

/// Encode a `TPMT_PUBLIC` template for an RSA-2048 decryption key
/// (unrestricted, no policy). This is the inner bytes of
/// `TPM2B_PUBLIC`; wrap with `Tpm2bPublic::from_bytes()`.
pub fn rsa2048_template(attributes: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    v.extend_from_slice(&TPM_ALG_RSA.to_be_bytes()); // type
    v.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // nameAlg
    v.extend_from_slice(&attributes.to_be_bytes()); // objectAttributes
    v.extend_from_slice(&0u16.to_be_bytes()); // authPolicy size = 0
                                              // TPMS_RSA_PARMS: symmetric(alg+keyBits+mode) + scheme + keyBits + exponent
    v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric = NULL
    v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // scheme = NULL
    v.extend_from_slice(&2048u16.to_be_bytes()); // keyBits = 2048
    v.extend_from_slice(&0u32.to_be_bytes()); // exponent = 0 (→ 65537)
                                              // unique (TPM2B_PUBLIC_KEY_RSA): size = 0 (new key)
    v.extend_from_slice(&0u16.to_be_bytes());
    v
}

/// Encode a `TPMT_PUBLIC` template for an ECC signing key on the
/// given curve. `curve` should be `TPM_ECC_NIST_P256` or
/// `TPM_ECC_NIST_P384`.
pub fn ecc_template(curve: u16, attributes: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    v.extend_from_slice(&TPM_ALG_ECC.to_be_bytes()); // type
    v.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // nameAlg
    v.extend_from_slice(&attributes.to_be_bytes()); // objectAttributes
    v.extend_from_slice(&0u16.to_be_bytes()); // authPolicy size = 0
                                              // TPMS_ECC_PARMS: symmetric + scheme + curveID + kdf
    v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric = NULL
    v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // scheme = NULL
    v.extend_from_slice(&curve.to_be_bytes()); // curveID
    v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf = NULL
                                                      // unique (TPMS_ECC_POINT): x(TPM2B) + y(TPM2B), both size=0
    v.extend_from_slice(&0u16.to_be_bytes()); // x size = 0
    v.extend_from_slice(&0u16.to_be_bytes()); // y size = 0
    v
}
