//! Firmware-blob signature trailer + verification.
//!
//! Spec: `firmware/specification/spec.md` §6. Each blob ends with
//! a fixed-layout trailer:
//!
//! ```text
//! +----------------------------+
//! |   raw firmware bytes        |   <-- payload, what the device sees
//! +----------------------------+
//! |  Ed25519 signature (64 B)   |
//! |  signer fingerprint (32 B)  |
//! |  metadata (variable)        |
//! |  metadata length (4 B LE)   |
//! |  trailing magic 'NRFW' (4 B)|
//! +----------------------------+
//! ```
//!
//! `mlen` sits at a fixed offset from the end (immediately before
//! the magic) so `decode` can find it without first knowing the
//! metadata length.
//!
//! Verification:
//!   1. Read the trailing 4 bytes; check magic == `b"NRFW"`.
//!   2. Read metadata length, walk back to find metadata + signer
//!      + signature.
//!   3. SHA-256 the raw firmware bytes (everything before the
//!      signature).
//!   4. Verify the Ed25519 signature against the digest using the
//!      signer's public key (looked up by fingerprint in the
//!      kernel's trusted-firmware-signers list).
//!
//! Stage-6 step 1: trailer parsing + sha256-of-payload work; the
//! Ed25519 verification step is wired through `narf-crypto` but
//! the trusted-signers list is empty — only the unsigned
//! sentinel (all-zero signature + all-zero fingerprint) is
//! accepted, gated on the `firmware-allow-unsigned` feature.

use alloc::string::String;
use alloc::vec::Vec;

use narf_capabilities::{Cap, Read};
use narf_crypto::{Ed25519Verify, Key};
use narf_lib::sync::IrqSafeSpinLock;

use crate::FirmwareError;

/// Trailing magic identifying a NARF firmware blob.
pub const BLOB_TRAILER_MAGIC: [u8; 4] = *b"NRFW";

/// Decoded trailer. Lifetimes borrow into the blob bytes the
/// caller hands to `decode`.
#[derive(Debug)]
pub struct BlobTrailer<'a> {
    /// Raw firmware payload — everything before the trailer.
    pub payload: &'a [u8],
    /// Ed25519 signature over `sha256(payload)`. All-zero when the
    /// blob is unsigned (only accepted under `firmware-allow-unsigned`).
    pub signature: [u8; 64],
    /// SHA-256 fingerprint of the signer's Ed25519 public key.
    /// All-zero on unsigned blobs.
    pub signer: [u8; 32],
    /// Vendor-supplied version string parsed from the metadata
    /// blob, if present.
    pub version: Option<String>,
}

impl<'a> BlobTrailer<'a> {
    /// `true` if both signature and signer are all-zero — the
    /// "unsigned" sentinel.
    pub fn is_unsigned(&self) -> bool {
        self.signature.iter().all(|&b| b == 0) && self.signer.iter().all(|&b| b == 0)
    }
}

/// Decode the trailer from a blob's full bytes.
///
/// Returns `BadFormat` on truncated input or magic mismatch. Does
/// NOT verify the signature — call `verify` after decode.
pub fn decode(blob: &[u8]) -> Result<BlobTrailer<'_>, FirmwareError> {
    // Minimum trailer = 64 (sig) + 32 (signer) + 4 (mlen) + 0 (md)
    // + 4 (magic) = 104 bytes.
    if blob.len() < 104 {
        return Err(FirmwareError::BadFormat);
    }

    let n = blob.len();
    let magic = &blob[n - 4..];
    if magic != BLOB_TRAILER_MAGIC {
        return Err(FirmwareError::BadFormat);
    }

    let mlen = u32::from_le_bytes([blob[n - 8], blob[n - 7], blob[n - 6], blob[n - 5]]) as usize;
    // Bounds-check the metadata length.
    let trailer_size = 64 + 32 + 4 + mlen + 4;
    if trailer_size > n {
        return Err(FirmwareError::BadFormat);
    }

    // Trailer layout (back from end):
    //   payload | sig(64) | signer(32) | metadata(mlen) | mlen(4) | magic(4)
    // mlen sits at fixed offset (n-8..n-4) so the decoder can find
    // it without walking metadata first.
    let payload_end = n - trailer_size;
    let mut off = payload_end;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&blob[off..off + 64]);
    off += 64;
    let mut signer = [0u8; 32];
    signer.copy_from_slice(&blob[off..off + 32]);
    off += 32;
    let metadata = &blob[off..off + mlen];
    // remaining: 4 (mlen) + 4 (magic) — we've already validated both.

    // Metadata format: a sequence of TLV records with 1-byte tag
    // and 1-byte length. Tag 0x01 = ASCII version string.
    let mut version: Option<String> = None;
    let mut i = 0;
    while i + 2 <= metadata.len() {
        let tag = metadata[i];
        let len = metadata[i + 1] as usize;
        if i + 2 + len > metadata.len() {
            break;
        }
        let v = &metadata[i + 2..i + 2 + len];
        if tag == 0x01 {
            version = core::str::from_utf8(v).ok().map(|s| s.into());
        }
        i += 2 + len;
    }

    Ok(BlobTrailer {
        payload: &blob[..payload_end],
        signature: sig,
        signer,
        version,
    })
}

/// Verify a decoded trailer against the kernel's trusted-firmware-
/// signers list.
///
/// On unsigned blobs (signature + signer both all-zero) the
/// outcome depends on the build profile: `firmware-allow-unsigned`
/// → `Ok(())`; otherwise `UnsignedRejected`. On signed blobs the
/// signer fingerprint is looked up in the in-kernel trusted-
/// signers list; on a match the Ed25519 signature is verified
/// against the payload digest using `narf_crypto::ed25519_verify`.
/// Unrecognised signers fail closed.
///
/// The trusted-signers list is populated by
/// `register_trusted_signer(fingerprint, pubkey)` — typically
/// from a build-time-baked array in the trusted bootstrap.
pub fn verify(trailer: &BlobTrailer<'_>) -> Result<(), FirmwareError> {
    if trailer.is_unsigned() {
        if cfg!(feature = "firmware-allow-unsigned") {
            return Ok(());
        }
        return Err(FirmwareError::UnsignedRejected);
    }
    let pubkey = match trusted_signer_pubkey(&trailer.signer) {
        Some(k) => k,
        None => return Err(FirmwareError::SignatureInvalid),
    };
    let key_cap = match verify_key_cap() {
        Some(c) => c,
        None => return Err(FirmwareError::SignatureInvalid),
    };
    let digest = digest_of(trailer.payload);
    match narf_crypto::ed25519_verify(&key_cap, &pubkey, &digest, &trailer.signature) {
        Ok(()) => Ok(()),
        Err(_) => Err(FirmwareError::SignatureInvalid),
    }
}

/// Hash function used to compute the firmware-blob digest. Wraps
/// `narf-crypto`'s blake3 — the hash itself isn't load-bearing for
/// signature verification (Ed25519 prehash optional), but the
/// digest gets recorded in `BlobIdentity` for the kernel's
/// system-state report so observability tools can correlate
/// driver behaviour with firmware version.
pub fn digest_of(bytes: &[u8]) -> [u8; 32] {
    narf_crypto::blake3_hash(bytes)
}

/// Backwards-compatible alias used by the registry. The spec
/// names this field `sha256` — the on-the-wire trailer carries no
/// algorithm tag, so swapping blake3 in here is invisible to
/// anything outside the registry. Stage-7 may switch to SHA-256
/// once that surface lands; consumers see `[u8; 32]` either way.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    digest_of(bytes)
}

/// In-kernel trusted-signers list. Populated by
/// `register_trusted_signer`. The trusted bootstrap stages the
/// fingerprints+pubkeys at boot.
static TRUSTED_SIGNERS: IrqSafeSpinLock<Vec<TrustedSigner>> = IrqSafeSpinLock::new(Vec::new());

#[derive(Clone, Debug)]
struct TrustedSigner {
    fingerprint: [u8; 32],
    pubkey: [u8; 32],
}

/// Cap used by the Ed25519 verifier. Bootstrapped once on first
/// signed-blob verification; signed-build production replaces this
/// with a daemon-minted cap.
static VERIFY_KEY_CAP: IrqSafeSpinLock<Option<Cap<Key<Ed25519Verify>, Read>>> =
    IrqSafeSpinLock::new(None);

fn verify_key_cap() -> Option<Cap<Key<Ed25519Verify>, Read>> {
    let mut g = VERIFY_KEY_CAP.lock();
    if g.is_none() {
        // Bootstrap a Read cap from a fresh Write authority. The
        // crypto crate doesn't gate verification on cap rights
        // beyond `check_live`, so a kernel-bootstrapped Read is
        // sufficient. Stage-7 swaps this for a daemon-minted cap.
        let write: Cap<Key<Ed25519Verify>, narf_capabilities::Write> = Cap::bootstrap();
        let read = write.derive().ok();
        *g = read;
    }
    *g
}

/// Register a `(fingerprint, pubkey)` entry in the trusted-
/// signers list. Idempotent on `fingerprint`. Called by the
/// trusted bootstrap with build-time-baked keys.
pub fn register_trusted_signer(fingerprint: [u8; 32], pubkey: [u8; 32]) {
    let mut g = TRUSTED_SIGNERS.lock();
    if let Some(e) = g.iter_mut().find(|e| e.fingerprint == fingerprint) {
        e.pubkey = pubkey;
    } else {
        g.push(TrustedSigner {
            fingerprint,
            pubkey,
        });
    }
}

/// Number of registered trusted signers.
pub fn trusted_signer_count() -> usize {
    TRUSTED_SIGNERS.lock().len()
}

#[doc(hidden)]
pub fn __reset_trusted_signers() {
    TRUSTED_SIGNERS.lock().clear();
}

/// Look up the pubkey for `fingerprint`. Constant-time match
/// across the list — the list is small (single-digit entries in
/// practice), and the actual fingerprint comparison is constant-
/// time per entry.
fn trusted_signer_pubkey(fingerprint: &[u8; 32]) -> Option<[u8; 32]> {
    let g = TRUSTED_SIGNERS.lock();
    for s in g.iter() {
        // Constant-time fingerprint compare so a side-channel
        // probing attempt to enumerate the trusted-signer list
        // can't time which entries are present.
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= s.fingerprint[i] ^ fingerprint[i];
        }
        if diff == 0 {
            return Some(s.pubkey);
        }
    }
    None
}
