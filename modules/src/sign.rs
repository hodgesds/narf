//! Module signature trailer and verification policy.
//!
//! A signed `.ko` ends with a fixed 104-byte trailer. Ed25519 signs
//! `BLAKE3(payload)`; payload is either the raw ELF or the complete compressed
//! envelope. The SHA-256 public-key fingerprint selects a key from the
//! build-time trust store.
//!
//! ```text
//! payload | signature[64] | signer[32] | version:u16 | alg:u16 | "NRFM"
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;

use narf_capabilities::{Cap, Read};
use narf_crypto::{Ed25519Verify, Key};
use narf_lib::sync::IrqSafeSpinLock;

/// Trailing magic identifying a signed NARF module.
pub const MODULE_TRAILER_MAGIC: [u8; 4] = *b"NRFM";
/// Current signature trailer version.
pub const MODULE_TRAILER_VERSION: u16 = 1;
/// Ed25519-over-BLAKE3 algorithm identifier.
pub const MODULE_TRAILER_ALG_ED25519_BLAKE3: u16 = 1;
/// Fixed signature trailer length.
pub const MODULE_TRAILER_LEN: usize = 64 + 32 + 2 + 2 + 4;

/// Verifier result. `Allow` means the module is trusted to load;
/// `Reject(reason)` aborts the load with the supplied diagnostic.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyDecision {
    Allow,
    Reject(&'static str),
}

/// Pluggable verification policy. Tests may install a deterministic policy;
/// normal boot installs [`Ed25519Verifier`].
pub trait ModuleVerifier: Send + Sync {
    fn verify(&self, image: &[u8]) -> VerifyDecision;
}

/// Test-only permissive policy. Production boot never installs this policy.
#[derive(Debug, Default)]
pub struct AcceptAll;

impl ModuleVerifier for AcceptAll {
    fn verify(&self, _image: &[u8]) -> VerifyDecision {
        VerifyDecision::Allow
    }
}

/// Production verifier: trusted Ed25519 signatures are required unless the
/// developer/CI-only `module-allow-unsigned` feature is enabled.
#[derive(Debug, Default)]
pub struct Ed25519Verifier;

impl ModuleVerifier for Ed25519Verifier {
    fn verify(&self, image: &[u8]) -> VerifyDecision {
        let trailer = match decode(image) {
            Ok(trailer) => trailer,
            Err(DecodeError::Missing) if cfg!(feature = "module-allow-unsigned") => {
                return VerifyDecision::Allow;
            }
            Err(DecodeError::Missing) => return VerifyDecision::Reject("module is unsigned"),
            Err(DecodeError::Malformed) => {
                return VerifyDecision::Reject("malformed module signature trailer");
            }
        };
        let Some(pubkey) = trusted_signer_pubkey(&trailer.signer) else {
            return VerifyDecision::Reject("module signer is not trusted");
        };
        let Some(cap) = verify_key_cap() else {
            return VerifyDecision::Reject("module verification key unavailable");
        };
        let digest = narf_crypto::blake3_hash(trailer.payload);
        match narf_crypto::ed25519_verify(&cap, &pubkey, &digest, &trailer.signature) {
            Ok(()) => VerifyDecision::Allow,
            Err(_) => VerifyDecision::Reject("module signature is invalid"),
        }
    }
}

/// Borrowed view of a decoded module trailer.
#[derive(Debug)]
pub struct ModuleTrailer<'a> {
    pub payload: &'a [u8],
    pub signature: [u8; 64],
    pub signer: [u8; 32],
}

/// Trailer decode failure. `Missing` is the legacy/raw unsigned form;
/// `Malformed` means the image claimed the NARF format but violated it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Missing,
    Malformed,
}

/// Decode, but do not authenticate, the fixed trailer.
pub fn decode(image: &[u8]) -> Result<ModuleTrailer<'_>, DecodeError> {
    if image.len() < 4 || image[image.len() - 4..] != MODULE_TRAILER_MAGIC {
        return Err(DecodeError::Missing);
    }
    if image.len() < MODULE_TRAILER_LEN {
        return Err(DecodeError::Malformed);
    }
    let start = image.len() - MODULE_TRAILER_LEN;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&image[start..start + 64]);
    let mut signer = [0u8; 32];
    signer.copy_from_slice(&image[start + 64..start + 96]);
    let version = u16::from_le_bytes([image[start + 96], image[start + 97]]);
    let algorithm = u16::from_le_bytes([image[start + 98], image[start + 99]]);
    if version != MODULE_TRAILER_VERSION || algorithm != MODULE_TRAILER_ALG_ED25519_BLAKE3 {
        return Err(DecodeError::Malformed);
    }
    Ok(ModuleTrailer {
        payload: &image[..start],
        signature,
        signer,
    })
}

static VERIFIER: IrqSafeSpinLock<Option<Box<dyn ModuleVerifier>>> = IrqSafeSpinLock::new(None);

/// Install a verifier, replacing any previous installation.
///
/// Crate-private by design: another subsystem must not be able to replace the
/// production verifier after boot and thereby mint module-loading authority.
pub(crate) fn install_verifier(verifier: Box<dyn ModuleVerifier>) {
    *VERIFIER.lock() = Some(verifier);
}

/// Verify an image. Absence of an installed policy fails closed.
pub fn verify(image: &[u8]) -> VerifyDecision {
    let g = VERIFIER.lock();
    match g.as_ref() {
        Some(verifier) => verifier.verify(image),
        None => VerifyDecision::Reject("module verifier is not initialized"),
    }
}

/// Return the bytes authenticated by a successfully completed verification.
///
/// Unsigned developer fixtures return the whole image. A structurally valid
/// trailer is stripped. A malformed trailer remains an error even if a
/// test-only custom verifier allowed it, so no caller can accidentally feed
/// signature metadata into a compressed payload.
pub(crate) fn payload_after_verify(image: &[u8]) -> Result<&[u8], &'static str> {
    match decode(image) {
        Ok(trailer) => Ok(trailer.payload),
        Err(DecodeError::Missing) => Ok(image),
        Err(DecodeError::Malformed) => Err("malformed module signature trailer"),
    }
}

#[derive(Clone, Debug)]
struct TrustedSigner {
    fingerprint: [u8; 32],
    pubkey: [u8; 32],
}

static TRUSTED_SIGNERS: IrqSafeSpinLock<Vec<TrustedSigner>> = IrqSafeSpinLock::new(Vec::new());
static VERIFY_KEY_CAP: IrqSafeSpinLock<Option<Cap<Key<Ed25519Verify>, Read>>> =
    IrqSafeSpinLock::new(None);

include!(concat!(env!("OUT_DIR"), "/trusted_keys.rs"));

/// Install public keys embedded from `NARF_MODULE_TRUSTED_KEYS`.
pub(crate) fn install_build_trusted_signers() {
    // Cache authority during the boot initcall. `Cap::bootstrap` must never
    // appear in the load hot path: holding this derived cap proves prior
    // grant, while `ed25519_verify` performs the current-validity check.
    let write: Cap<Key<Ed25519Verify>, narf_capabilities::Write> = Cap::bootstrap();
    *VERIFY_KEY_CAP.lock() = write.derive().ok();
    for key in BUILD_TRUSTED_KEYS {
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(key);
        register_trusted_signer(hash.finalize(), *key);
    }
}

/// Register or replace a trusted signer by SHA-256 fingerprint.
///
/// Runtime trust-root mutation is intentionally not part of the public API;
/// production roots come only from the build-time file. Kernel smokes in this
/// crate use this helper for independent public test vectors.
pub(crate) fn register_trusted_signer(fingerprint: [u8; 32], pubkey: [u8; 32]) {
    let mut signers = TRUSTED_SIGNERS.lock();
    if let Some(entry) = signers
        .iter_mut()
        .find(|entry| entry.fingerprint == fingerprint)
    {
        entry.pubkey = pubkey;
    } else {
        signers.push(TrustedSigner {
            fingerprint,
            pubkey,
        });
    }
}

/// Number of installed module trust roots.
pub fn trusted_signer_count() -> usize {
    TRUSTED_SIGNERS.lock().len()
}

fn trusted_signer_pubkey(fingerprint: &[u8; 32]) -> Option<[u8; 32]> {
    let signers = TRUSTED_SIGNERS.lock();
    for signer in signers.iter() {
        let mut difference = 0u8;
        for (actual, expected) in signer.fingerprint.iter().zip(fingerprint.iter()) {
            difference |= actual ^ expected;
        }
        if difference == 0 {
            return Some(signer.pubkey);
        }
    }
    None
}

fn verify_key_cap() -> Option<Cap<Key<Ed25519Verify>, Read>> {
    *VERIFY_KEY_CAP.lock()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    TRUSTED_SIGNERS.lock().clear();
    *VERIFY_KEY_CAP.lock() = None;
    *VERIFIER.lock() = None;
}
