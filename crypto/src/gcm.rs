//! AES-GCM and GMAC (NIST SP 800-38D) with a 96-bit nonce and a 128-bit
//! tag, for 802.11 GCMP-128/256 (IEEE 802.11-2020 §12.5.5) and
//! BIP-GMAC-128/256 (§12.5.4): a 128- or 256-bit key selects the variant.
//!
//! The block cipher and GHASH are the RustCrypto `aes` / `polyval` backends
//! behind `aes-gcm`. Both are constant-time in this build: `aes` is the
//! fixsliced (fully bitsliced, no lookup tables) software implementation,
//! pinned by `--cfg aes_force_soft` on x86_64 and the default (no
//! `aes_armv8`) on aarch64; `polyval` is BearSSL's `ghash_ctmul64`
//! carry-less multiply with no secret-indexed table, pinned by
//! `--cfg polyval_force_soft` on x86_64 and the default (no
//! `polyval_armv8`) on aarch64. Tag comparison is `subtle::ConstantTimeEq`.
//!
//! Callers own nonce uniqueness (the 48-bit PN/IPN) and commit replay
//! state only after `open` / a GMAC comparison succeeds.

use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use alloc::boxed::Box;
use subtle::ConstantTimeEq;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The key is neither 16 nor 32 octets.
    Key,
    /// The message exceeds the GCM length bound.
    Length,
    Authentication,
}

/// Boxed: the expanded key schedules differ in size.
enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}
impl Cipher {
    fn new(key: &[u8]) -> Result<Self, Error> {
        match key.len() {
            16 => Ok(Self::Aes128(Box::new(Aes128Gcm::new(
                GenericArray::from_slice(key),
            )))),
            32 => Ok(Self::Aes256(Box::new(Aes256Gcm::new(
                GenericArray::from_slice(key),
            )))),
            _ => Err(Error::Key),
        }
    }
    fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        let nonce = GenericArray::from_slice(nonce);
        let tag = match self {
            Self::Aes128(cipher) => cipher.encrypt_in_place_detached(nonce, aad, body),
            Self::Aes256(cipher) => cipher.encrypt_in_place_detached(nonce, aad, body),
        }
        .map_err(|_| Error::Length)?;
        Ok(tag.into())
    }
    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        let nonce = GenericArray::from_slice(nonce);
        let tag = GenericArray::from_slice(tag);
        // aes-gcm compares the tag over the ciphertext (constant time)
        // before it applies the keystream: a failure leaves `body` as is.
        match self {
            Self::Aes128(cipher) => cipher.decrypt_in_place_detached(nonce, aad, body, tag),
            Self::Aes256(cipher) => cipher.decrypt_in_place_detached(nonce, aad, body, tag),
        }
        .map_err(|_| Error::Authentication)
    }
}

/// Encrypt `body` in place and return the detached tag. A nonce must never
/// be reused with the same key.
pub fn seal(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    body: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    Cipher::new(key)?.seal(nonce, aad, body)
}

/// Authenticate and decrypt in place. Every error leaves `body` unchanged.
pub fn open(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    body: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), Error> {
    Cipher::new(key)?.open(nonce, aad, body, tag)
}

/// GMAC: GCM over `aad` with an empty plaintext (SP 800-38D §3).
pub fn gmac(key: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8]) -> Result<[u8; TAG_LEN], Error> {
    Cipher::new(key)?.seal(nonce, aad, &mut [])
}

/// Check a received GMAC in constant time.
pub fn gmac_verify(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    mic: &[u8; TAG_LEN],
) -> Result<(), Error> {
    let expected = gmac(key, nonce, aad)?;
    if bool::from(expected.ct_eq(mic)) {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}

#[path = "gcm_tests.rs"]
mod tests;
