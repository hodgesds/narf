//! Post-quantum algorithm plan — Stage-4 structural shape.
//!
//! Spec: `crypto/specification/spec.md` (Stage-4 post-quantum
//! algorithm plan). NARF's PQ posture: hybrid ECDH+ML-KEM for
//! handshake, ML-DSA for signatures, SPHINCS+ as a hash-based
//! signature fallback for code-signing. None of the primitives
//! ship here in Stage-4 structural — the type surface pins the
//! identifiers and `Cap<Key<T>, _>` wiring so the first
//! implementation drops in without churning consumers.
//!
//! FIPS-mode decision: runtime flag reported by `fips_mode()`;
//! Stage-4 leaves it `false` because none of the NARF primitives
//! have been through the NIST validation process yet. A future
//! FIPS-enabled build flips the constant and gates non-FIPS
//! algorithms behind `fips_allowed()`.

use narf_capabilities::{CapKind, CapType};

/// Post-quantum key-encapsulation mechanism marker.
#[derive(Copy, Clone, Debug)]
pub struct MlKem768;

impl CapType for MlKem768 {
    const KIND: CapKind = CapKind::Key;
}

/// Post-quantum digital-signature marker. ML-DSA-65 is the NIST
/// CNSA 2.0 recommendation.
#[derive(Copy, Clone, Debug)]
pub struct MlDsa65;

impl CapType for MlDsa65 {
    const KIND: CapKind = CapKind::Key;
}

/// Hash-based signature marker for code-signing where public-key
/// posture must survive ML-DSA cryptanalytic advances.
#[derive(Copy, Clone, Debug)]
pub struct SphincsPlus;

impl CapType for SphincsPlus {
    const KIND: CapKind = CapKind::Key;
}

/// Hybrid handshake preference — run both classical ECDH(P-256 /
/// X25519) and PQ ML-KEM, combine shared secrets via HKDF.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HybridMode {
    /// Classical only — pre-PQ rollout.
    ClassicalOnly,
    /// PQ KEM only — post-PQ rollout, classical deprecated.
    PqOnly,
    /// Concatenate classical + PQ shared secrets through HKDF.
    /// NIST-recommended interim posture.
    Hybrid,
}

/// Runtime FIPS-mode flag. Stage-4 stays `false`; a future
/// FIPS-enabled build flips this after primitives are validated.
#[inline]
pub const fn fips_mode() -> bool {
    false
}

/// Is `alg` permitted in the current FIPS posture? Stage-4 returns
/// `true` for every algorithm because `fips_mode()` is `false`; in
/// a FIPS build this gates non-validated algorithms.
#[inline]
pub const fn fips_allowed(alg: PqAlg) -> bool {
    if !fips_mode() {
        return true;
    }
    match alg {
        PqAlg::MlKem768 => true,
        PqAlg::MlDsa65 => true,
        PqAlg::SphincsPlus => true,
    }
}

/// Algorithm identifier for FIPS gating.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PqAlg {
    MlKem768,
    MlDsa65,
    SphincsPlus,
}
