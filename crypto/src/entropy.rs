//! Fresh hardware-seeded ChaCha20 streams for protocol secrets.
//!
//! This narrow adapter trusts the architectural RNG. It does not implement the
//! system entropy pool, jitter collection, or SP 800-90B health-test service.
//! Unsupported instructions and bounded entropy starvation return an error;
//! timing counters are never accepted as seed material.

use crate::CryptoError;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use zeroize::{Zeroize, Zeroizing};

/// Construct a ChaCha20 stream using a fresh 256-bit architectural RNG seed.
/// No cycle-counter fallback is permitted. The temporary seed is zeroized.
/// This stream is independent of the legacy Stage-3 `per_task_rng` helper.
pub fn try_per_task_rng() -> Result<ChaCha20Rng, CryptoError> {
    rng_with(hardware_seed)
}

/// Fill protocol secret/nonce bytes from a freshly hardware-seeded stream.
/// On entropy failure the entire output is zeroized, and callers must abort
/// the operation. An empty request succeeds without consulting the source.
pub fn try_fill_random_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
    fill_with(out, hardware_seed)
}

fn rng_with(
    source: impl FnOnce(&mut [u8; 32]) -> Result<(), CryptoError>,
) -> Result<ChaCha20Rng, CryptoError> {
    let mut seed = Zeroizing::new([0; 32]);
    source(&mut seed)?;
    Ok(ChaCha20Rng::from_seed(*seed))
}

fn fill_with(
    out: &mut [u8],
    source: impl FnOnce(&mut [u8; 32]) -> Result<(), CryptoError>,
) -> Result<(), CryptoError> {
    if out.is_empty() {
        return Ok(());
    }
    let mut rng = match rng_with(source) {
        Ok(rng) => rng,
        Err(e) => {
            out.zeroize();
            return Err(e);
        }
    };
    rng.fill_bytes(out);
    Ok(())
}

/// Each successful word must come from the selected architectural source.
/// A short source never leaves a partially valid seed for its caller.
fn seed_words(seed: &mut [u8; 32], mut next: impl FnMut() -> Option<u64>) -> bool {
    for word in seed.chunks_exact_mut(8) {
        let Some(value) = next() else {
            seed.zeroize();
            return false;
        };
        word.copy_from_slice(&value.to_le_bytes());
    }
    true
}

#[cfg(target_arch = "x86_64")]
fn hardware_seed(seed: &mut [u8; 32]) -> Result<(), CryptoError> {
    use narf_arch::x86_64::{cpuid::Features, hwrng};
    // SAFETY: probing CPUID has no memory or privilege preconditions.
    let features = unsafe { Features::probe() };
    if features.rdseed
        && seed_words(seed, || {
            // SAFETY: this CPU advertises RDSEED. Each read has a bounded retry.
            let low = unsafe { hwrng::rdseed_u32() }?;
            // SAFETY: same feature gate as above.
            let high = unsafe { hwrng::rdseed_u32() }?;
            Some(u64::from(low) | (u64::from(high) << 32))
        })
    {
        return Ok(());
    }
    if features.rdrand
        && seed_words(seed, || {
            // SAFETY: this CPU advertises RDRAND. Each read has a bounded retry.
            let low = unsafe { hwrng::rdrand_u32() }?;
            // SAFETY: same current-CPU feature gate as above.
            let high = unsafe { hwrng::rdrand_u32() }?;
            Some(u64::from(low) | (u64::from(high) << 32))
        })
    {
        return Ok(());
    }
    seed.zeroize();
    Err(CryptoError::EntropyUnavailable)
}

#[cfg(target_arch = "aarch64")]
fn hardware_seed(seed: &mut [u8; 32]) -> Result<(), CryptoError> {
    use narf_arch::aarch64::rndr;
    fn retry(mut read: impl FnMut() -> Option<u64>) -> Option<u64> {
        for _ in 0..16 {
            if let Some(word) = read() {
                return Some(word);
            }
            core::hint::spin_loop();
        }
        None
    }
    // Both wrappers gate the instruction on this CPU's ID_AA64ISAR0_EL1.
    if seed_words(seed, || retry(rndr::try_rndrrs)) || seed_words(seed, || retry(rndr::try_rndr)) {
        return Ok(());
    }
    seed.zeroize();
    Err(CryptoError::EntropyUnavailable)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn hardware_seed(seed: &mut [u8; 32]) -> Result<(), CryptoError> {
    seed.zeroize();
    Err(CryptoError::EntropyUnavailable)
}

#[path = "entropy_tests.rs"]
mod tests;
