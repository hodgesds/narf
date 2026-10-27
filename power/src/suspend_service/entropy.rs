//! The service's entropy seam — and its one production source.
//!
//! The suspend service generates long-term key material (the slot
//! master secret, per-image keys), so it draws exclusively from
//! `narf-crypto`'s key-material surface (issue #996, crypto spec
//! §3.2): seed-grade architectural entropy (RDSEED / RNDR) under SP
//! 800-90B health discipline, refusing with a typed error — no
//! fallback — when no healthy source exists. The design's standing
//! invariant (power-suspend design §1.4 / §3.1) is that there is no
//! other path: no `per_task_rng`, no cycle counter, no private probe
//! of the RNG instructions.
//!
//! [`KeyEntropy`] exists so fixtures can script the surface's two
//! states (seed-grade present / absent) the way crypto's own fixtures
//! script its word source. It is not a second entropy policy: the
//! production implementation, [`HwKeyEntropy`], is a direct delegate
//! to the `narf-crypto` surface, and key generation inside the
//! service goes through the seam the service was constructed with.

use super::ServiceError;

/// The entropy operations key generation needs, behind a seam for
/// fixtures. Implementations must fail closed: an unavailable source
/// is an error, never weaker bytes.
pub trait KeyEntropy {
    /// Whether a seed-grade source is present and healthy right now
    /// (crypto's `has_hw_entropy` semantics for the production impl).
    fn has_seed_grade(&self) -> bool;

    /// Fill `out` with key-material bytes, or refuse. On refusal the
    /// implementation must not leave partially valid material in
    /// `out` (the production surface zeroizes it; scripted fixtures
    /// model the same contract).
    fn fill_key_material(&self, out: &mut [u8]) -> Result<(), ServiceError>;
}

/// Production entropy: the `narf-crypto` key-material surface and
/// nothing else.
#[derive(Copy, Clone, Debug, Default)]
pub struct HwKeyEntropy;

impl KeyEntropy for HwKeyEntropy {
    fn has_seed_grade(&self) -> bool {
        narf_crypto::has_hw_entropy()
    }

    fn fill_key_material(&self, out: &mut [u8]) -> Result<(), ServiceError> {
        // The key-material surface's only failure mode is a missing
        // or unhealthy seed-grade source (crypto spec §3.2); map any
        // error onto the service's refusal — there is no other path.
        narf_crypto::try_fill_key_material(out).map_err(|_| ServiceError::EntropyUnavailable)
    }
}
