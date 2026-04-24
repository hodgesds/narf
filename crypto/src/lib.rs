//! narf-crypto — primitives, cap-gated keys, and the SecureRing skeleton.
//!
//! Spec: `crypto/specification/spec.md`. Stage-3 surface lands the
//! cap-gated wrappers around RustCrypto primitives (Ed25519 verify,
//! ChaCha20-Poly1305 AEAD, HKDF-SHA-256), the un-gated BLAKE3 content
//! hash, and a per-task `ChaCha20Rng` helper. The full SecureRing impl
//! is deferred to Stage 4 — see the `secure_ring` module for the
//! handshake / replay-window deferrals.
//!
//! Non-goals for Stage 3:
//!
//! - Hardware acceleration probe + dispatch (spec §3.5). RustCrypto
//!   uses portable Rust; AES-NI / SHA-NI / ARMv8 crypto extensions
//!   land with the dispatch shim in Stage 4.
//! - TPM 2.0 / measured-boot integration (spec §3.7).
//! - Full key-management surface (`generate`, `import`, `derive`
//!   producing typed `Cap<Key, _>`). Stage 3 covers verify + seal/open
//!   + KDF expand on caps the caller already holds; Stage 4 wires the
//!   key-store and cap mint path.
//! - X25519 handshake + replay-window for SecureRing (spec §3.6).
//! - SP 800-90B health tests on the entropy source (spec §3.2).
//! - FIPS-mode decision (spec §9).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

pub mod tpm;
pub mod pq;

extern crate alloc;

use core::marker::PhantomData;

use alloc::vec::Vec;

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant, Read};

// ── Algorithm markers + Key<Alg> ─────────────────────────────────────
//
// Per spec §3.1: cap kinds are type-parametric — the algorithm goes in
// the `Badge` (or, here, the type parameter on `Key<Alg>`), and every
// algorithm maps to `CapKind::Key` so the runtime cap table needs only
// one entry. The Rust-level `Key<Alg>` keeps callers honest at compile
// time: a `Cap<Key<Ed25519Verify>, Read>` cannot be passed where a
// `Cap<Key<ChaCha20Poly1305>, Grant>` is expected.

/// Compact runtime tag for a key's algorithm. Exists so the cap badge
/// can record the algorithm even when the type parameter is erased
/// (e.g. wire-format manifests). Stable `#[repr(u32)]` per the
/// `CapKind` discipline in `capabilities/`.
#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyAlg {
    Ed25519Verify       = 0x01,
    Ed25519Sign         = 0x02,
    AesGcm256           = 0x03,
    ChaCha20Poly1305    = 0x04,
    Hkdf                = 0x05,
}

/// Marker trait every algorithm tag implements; the constant lets the
/// `Key<Alg>` type expose its algorithm at runtime without dragging in
/// trait objects.
pub trait KeyAlgorithm: 'static {
    const ALG: KeyAlg;
}

/// Type-level marker: Ed25519 public-key verification.
#[derive(Copy, Clone, Debug)]
pub struct Ed25519Verify;
impl KeyAlgorithm for Ed25519Verify { const ALG: KeyAlg = KeyAlg::Ed25519Verify; }

/// Type-level marker: Ed25519 secret-key signing. Stage 3 reserves the
/// type; the actual sign path lands once the key-store is wired.
#[derive(Copy, Clone, Debug)]
pub struct Ed25519Sign;
impl KeyAlgorithm for Ed25519Sign { const ALG: KeyAlg = KeyAlg::Ed25519Sign; }

/// Type-level marker: AES-256-GCM AEAD. Stage 3 type-only; primitive
/// dispatch lands when AES-NI / ARMv8 AES are wired (Stage 4).
#[derive(Copy, Clone, Debug)]
pub struct AesGcm256;
impl KeyAlgorithm for AesGcm256 { const ALG: KeyAlg = KeyAlg::AesGcm256; }

/// Type-level marker: ChaCha20-Poly1305 AEAD.
#[derive(Copy, Clone, Debug)]
pub struct ChaCha20Poly1305Alg;
impl KeyAlgorithm for ChaCha20Poly1305Alg { const ALG: KeyAlg = KeyAlg::ChaCha20Poly1305; }

/// Type-level marker: HKDF-SHA-256 KDF (input-keying-material handle).
#[derive(Copy, Clone, Debug)]
pub struct Hkdf;
impl KeyAlgorithm for Hkdf { const ALG: KeyAlg = KeyAlg::Hkdf; }

/// Phantom-typed key handle. The actual key bytes live behind the cap
/// table in `DomainId::KEYS` (spec §5); this struct never carries
/// secret material directly.
#[derive(Copy, Clone, Debug, Default)]
pub struct Key<Alg: KeyAlgorithm> {
    _alg: PhantomData<fn() -> Alg>,
}

// All algorithms map to `CapKind::Key` — the algorithm distinction is
// type-level, per spec §3.1's "type-parametric rule". The runtime cap
// table needs exactly one slot per key, regardless of algorithm.
impl<Alg: KeyAlgorithm> CapType for Key<Alg> {
    const KIND: CapKind = CapKind::Key;
}

// ── CryptoError ──────────────────────────────────────────────────────

/// Failures returned by every cap-gated primitive. `KeyUnavailable`
/// folds in `CapError::Revoked` so callers see one error type at the
/// crypto surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Signature verify rejected the message.
    InvalidSignature,
    /// AEAD seal or open failed (open: tag mismatch; seal: backend error).
    AeadFailure,
    /// Cap was revoked between mint and use, or never live.
    KeyUnavailable,
    /// Output buffer too small for the requested operation.
    InsufficientOutputBuffer,
    /// Primitive backend disabled at compile time (e.g. no_std-broken
    /// dependency stubbed out). Should never fire in a well-configured
    /// build.
    BackendUnavailable,
}

impl From<CapError> for CryptoError {
    fn from(_: CapError) -> Self { CryptoError::KeyUnavailable }
}

// ── Ed25519 verify ───────────────────────────────────────────────────
//
// Verify-only path: the cap proves authority to use the public key; the
// key bytes themselves are not yet plumbed through the cap table (Stage
// 4). Stage 3 takes the public-key bytes inline so manifest verification
// can land alongside the cap-gated surface.

/// Verify an Ed25519 signature. The cap proves the caller is allowed to
/// use the verify-key handle; the actual public key + message + sig
/// arrive inline. Stage 4 promotes `verifying_key` to live behind the
/// cap and reads it from the `DomainId::KEYS` allocator.
pub fn ed25519_verify(
    cap: &Cap<Key<Ed25519Verify>, Read>,
    verifying_key: &[u8; 32],
    msg: &[u8],
    sig: &[u8; 64],
) -> Result<(), CryptoError> {
    cap.check_live()?;

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let vk = VerifyingKey::from_bytes(verifying_key)
        .map_err(|_| CryptoError::InvalidSignature)?;
    let signature = Signature::from_bytes(sig);
    vk.verify(msg, &signature).map_err(|_| CryptoError::InvalidSignature)
}

// ── ChaCha20-Poly1305 AEAD ───────────────────────────────────────────
//
// poly1305's auto-detected AVX2 backend SIGILLs LLVM under
// `code-model=kernel`; we pin the soft Poly1305 backend via the
// `--cfg poly1305_force_soft` rustflag in `.cargo/config.toml`. With
// that, the dep compiles clean on both arches and we expose the real
// in-place AEAD seal/open. Stage 4 promotes `key_bytes` to live behind
// the cap once the key-store is wired.

/// AEAD seal in place. `plaintext` is encrypted and the 16-byte
/// Poly1305 tag is appended; final length is `plaintext.len() + 16`.
pub fn chacha20_seal(
    cap: &Cap<Key<ChaCha20Poly1305Alg>, Grant>,
    key_bytes: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &mut Vec<u8>,
    aad: &[u8],
) -> Result<(), CryptoError> {
    cap.check_live()?;

    use chacha20poly1305::{
        aead::{AeadInPlace, KeyInit},
        ChaCha20Poly1305, Key as AeadKey, Nonce,
    };

    let key = AeadKey::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let n = Nonce::from_slice(nonce);
    cipher.encrypt_in_place(n, aad, plaintext)
        .map_err(|_| CryptoError::AeadFailure)
}

/// AEAD open in place. `ciphertext` carries the trailing 16-byte tag;
/// on success the tag is stripped and the buffer holds the plaintext.
/// On tag-mismatch the buffer is left untouched and `AeadFailure` is
/// returned (RustCrypto's `decrypt_in_place` clears on failure — we do
/// not rely on the partial state either way).
pub fn chacha20_open(
    cap: &Cap<Key<ChaCha20Poly1305Alg>, Grant>,
    key_bytes: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &mut Vec<u8>,
    aad: &[u8],
) -> Result<(), CryptoError> {
    cap.check_live()?;

    use chacha20poly1305::{
        aead::{AeadInPlace, KeyInit},
        ChaCha20Poly1305, Key as AeadKey, Nonce,
    };

    let key = AeadKey::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let n = Nonce::from_slice(nonce);
    cipher.decrypt_in_place(n, aad, ciphertext)
        .map_err(|_| CryptoError::AeadFailure)
}

// ── HKDF-SHA-256 ─────────────────────────────────────────────────────

/// HKDF-Expand using SHA-256. Stage-3 takes `ikm` inline; Stage 4
/// promotes the ikm to live behind the cap.
pub fn hkdf_expand(
    cap: &Cap<Key<Hkdf>, Read>,
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    cap.check_live()?;

    use hkdf::Hkdf as HkdfImpl;
    use sha2::Sha256;

    // RFC 5869: Extract-then-Expand. `Hkdf::new` does Extract; `expand`
    // does Expand. Output length is bounded by 255 * HashLen (8160 bytes
    // for SHA-256) — exceed that and we surface InsufficientOutputBuffer.
    let hk = HkdfImpl::<Sha256>::new(Some(salt), ikm);
    let mut out = alloc::vec![0u8; out_len];
    hk.expand(info, &mut out).map_err(|_| CryptoError::InsufficientOutputBuffer)?;
    Ok(out)
}

// ── BLAKE3 (un-gated content hash) ───────────────────────────────────

/// BLAKE3 over a single message, returning the 32-byte default digest.
/// Un-gated per spec — content hashes name reproducible build artefacts
/// and feed measured-boot, neither of which can require a cap.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

// ── Per-task RNG ─────────────────────────────────────────────────────
//
// Stage-3 placeholder: we seed a `ChaCha20Rng` from the monotonic cycle
// counter. **This is not cryptographically secure** — `narf_time::now_cycles`
// is observable to the adversary and replay-able. Stage 4 must wire the
// `arch/` HW entropy surface (RDSEED on x86_64, RNDR on aarch64) and
// the SP 800-90B health-test discipline before any user-facing crypto
// depends on `per_task_rng`. The fallback exists so the rest of the
// Stage-3 surface can compile and be exercised end-to-end; callers
// touching real key material must check `arch::has_hw_entropy()` (not
// yet exposed) and refuse if false.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Construct a per-task RNG. Stage 3 seeds from the monotonic cycle
/// counter; Stage 4 must replace the seed source with the arch HW
/// entropy path. Marked safe because the underlying ChaCha20 stream is
/// safe — the *seed quality* is the open issue.
pub fn per_task_rng() -> ChaCha20Rng {
    // Mix cycles into a 32-byte seed by stretching across the buffer.
    // Two independent reads + a constant tag keep the seed at least
    // distinct across rapid successive calls within one task; this is
    // emphatically not the same thing as adversarial unpredictability.
    let mut seed = [0u8; 32];
    let c0 = narf_time::now_cycles();
    let c1 = narf_time::now_cycles().wrapping_add(0x9E37_79B9_7F4A_7C15); // golden-ratio splash
    seed[..8].copy_from_slice(&c0.to_le_bytes());
    seed[8..16].copy_from_slice(&c1.to_le_bytes());
    seed[16..24].copy_from_slice(&c0.wrapping_mul(0x100000001B3).to_le_bytes());
    seed[24..32].copy_from_slice(&c1.wrapping_mul(0xCBF29CE484222325).to_le_bytes());
    ChaCha20Rng::from_seed(seed)
}

// ── SecureRing skeleton ──────────────────────────────────────────────

/// SecureRing — AEAD-on-each-slot wrapper over a Narf-Ring producer /
/// consumer pair (spec §3.6).
///
/// **Stage 3 status: skeleton only.** The full impl needs:
///
/// 1. An X25519 (or co-trusted-peers shortcut) handshake to establish
///    per-direction AEAD keys. This requires `Cap<Key<X25519>, _>` and
///    a key-exchange surface that does not yet exist in `crypto/`.
/// 2. A replay-detection sliding window on the receive side (spec §3.6),
///    keyed off the per-message epoch counter + direction bit.
/// 3. Two-mode payload handling: small payloads inline AEAD over the
///    slot, large payloads hand off a `Cap<DmaBuffer, _>` + `Tag`.
///    Today's `narf-ipc` ring is fixed-`T`; we will need either a
///    `Ring<SecureFrame>` enum or a second ring for the cap+tag path.
///
/// The type alias here lets downstream Stage-4 consumers name the
/// wrapper; the body is intentionally `()` until the dependencies land.
pub mod secure_ring {
    /// Placeholder marker type. Once the handshake + replay window are
    /// implemented, this becomes `pub struct SecureRing<T, const N: usize> { ... }`.
    /// The marker exists so docs and downstream module paths can stabilise.
    #[derive(Debug, Default)]
    pub struct SecureRing<T> {
        _t: core::marker::PhantomData<fn() -> T>,
    }

    impl<T> SecureRing<T> {
        /// Stub constructor. Stage 4 replaces the body with the full
        /// handshake + AEAD-key-derivation path.
        pub const fn new() -> Self {
            Self { _t: core::marker::PhantomData }
        }
    }
}
