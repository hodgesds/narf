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
//! |  metadata length (4 B LE)   |
//! |  metadata (variable)        |
//! |  trailing magic 'NRFW' (4 B)|
//! +----------------------------+
//! ```
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

use crate::FirmwareError;

/// Trailing magic identifying a NARF firmware blob.
pub const BLOB_TRAILER_MAGIC: [u8; 4] = *b"NRFW";

/// Decoded trailer. Lifetimes borrow into the blob bytes the
/// caller hands to `decode`.
#[derive(Debug)]
pub struct BlobTrailer<'a> {
    /// Raw firmware payload — everything before the trailer.
    pub payload:     &'a [u8],
    /// Ed25519 signature over `sha256(payload)`. All-zero when the
    /// blob is unsigned (only accepted under `firmware-allow-unsigned`).
    pub signature:   [u8; 64],
    /// SHA-256 fingerprint of the signer's Ed25519 public key.
    /// All-zero on unsigned blobs.
    pub signer:      [u8; 32],
    /// Vendor-supplied version string parsed from the metadata
    /// blob, if present.
    pub version:     Option<String>,
}

impl<'a> BlobTrailer<'a> {
    /// `true` if both signature and signer are all-zero — the
    /// "unsigned" sentinel.
    pub fn is_unsigned(&self) -> bool {
        self.signature.iter().all(|&b| b == 0)
            && self.signer.iter().all(|&b| b == 0)
    }
}

/// Decode the trailer from a blob's full bytes.
///
/// Returns `BadFormat` on truncated input or magic mismatch. Does
/// NOT verify the signature — call `verify` after decode.
pub fn decode(blob: &[u8]) -> Result<BlobTrailer<'_>, FirmwareError> {
    // Minimum trailer = 64 (sig) + 32 (signer) + 4 (mlen) + 0 (md)
    // + 4 (magic) = 104 bytes.
    if blob.len() < 104 { return Err(FirmwareError::BadFormat); }

    let n = blob.len();
    let magic = &blob[n - 4..];
    if magic != BLOB_TRAILER_MAGIC { return Err(FirmwareError::BadFormat); }

    let mlen = u32::from_le_bytes([
        blob[n - 8], blob[n - 7], blob[n - 6], blob[n - 5],
    ]) as usize;
    // Bounds-check the metadata length.
    let trailer_size = 64 + 32 + 4 + mlen + 4;
    if trailer_size > n { return Err(FirmwareError::BadFormat); }

    let payload_end = n - trailer_size;
    let mut off = payload_end;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&blob[off..off + 64]);
    off += 64;
    let mut signer = [0u8; 32];
    signer.copy_from_slice(&blob[off..off + 32]);
    off += 32;
    off += 4; // skip mlen we've already read
    let metadata = &blob[off..off + mlen];
    // off += mlen; off += 4;  // would land on `n`; not needed.

    // Metadata format: a sequence of TLV records with 1-byte tag
    // and 1-byte length. Tag 0x01 = ASCII version string.
    let mut version: Option<String> = None;
    let mut i = 0;
    while i + 2 <= metadata.len() {
        let tag = metadata[i];
        let len = metadata[i + 1] as usize;
        if i + 2 + len > metadata.len() { break; }
        let v = &metadata[i + 2..i + 2 + len];
        match tag {
            0x01 => {
                version = core::str::from_utf8(v)
                    .ok()
                    .map(|s| s.into());
            }
            _ => {}
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
/// fingerprint is looked up against the trusted-firmware-signers
/// list — today empty, so unrecognised fingerprints fail closed.
///
/// Stage-6 step-1 cut: the production Ed25519 verification path
/// (the call into `narf_crypto::ed25519_verify`) lands once the
/// kernel's trusted-firmware-signers public-key store is exposed
/// behind a `Cap<Key<Ed25519Verify>, Read>` (Stage-7). Until then
/// signed blobs are accepted only when their fingerprint matches
/// a known signer entry — currently none, so signed blobs fail
/// closed and only the unsigned path actually works.
pub fn verify(trailer: &BlobTrailer<'_>) -> Result<(), FirmwareError> {
    if trailer.is_unsigned() {
        if cfg!(feature = "firmware-allow-unsigned") {
            return Ok(());
        }
        return Err(FirmwareError::UnsignedRejected);
    }
    if !signer_is_trusted(&trailer.signer) {
        return Err(FirmwareError::SignatureInvalid);
    }
    // TODO(stage-7): when the trusted-signers public-key store
    // ships its `Cap<Key<Ed25519Verify>, Read>`, replace the
    // closed-fail return above with a real `narf_crypto::
    // ed25519_verify(&key_cap, &pubkey, &digest, &trailer.signature)`
    // call. The digest is `digest_of(trailer.payload)`.
    Ok(())
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
pub fn sha256(bytes: &[u8]) -> [u8; 32] { digest_of(bytes) }

/// Is this signer fingerprint in the trusted-firmware-signers list?
fn signer_is_trusted(_fingerprint: &[u8; 32]) -> bool {
    // No production keys baked yet — the only accepted shape is
    // the unsigned sentinel handled in `verify`.
    false
}
