//! Fresh hardware-seeded ChaCha20 streams for protocol secrets, plus the
//! health-checked key-material entropy surface (issue #996).
//!
//! The protocol adapter trusts the architectural RNG. It does not implement
//! the system entropy pool or jitter collection. Unsupported instructions
//! and bounded entropy starvation return an error; timing counters are
//! never accepted as seed material.
//!
//! The key-material surface at the bottom of this module is stricter: it
//! draws only from the seed-grade source (RDSEED on x86_64 — never the
//! RDRAND fallback — and RNDR/RNDRRS on aarch64) and subjects every byte
//! it releases to SP 800-90B health tests (spec §3.2). SMS/SMK-class key
//! generation must use it, and it refuses with a typed error — no
//! fallback — when no healthy source exists.

use core::sync::atomic::{AtomicU8, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;

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
fn rndr_retry(mut read: impl FnMut() -> Option<u64>) -> Option<u64> {
    for _ in 0..16 {
        if let Some(word) = read() {
            return Some(word);
        }
        core::hint::spin_loop();
    }
    None
}

#[cfg(target_arch = "aarch64")]
fn hardware_seed(seed: &mut [u8; 32]) -> Result<(), CryptoError> {
    use narf_arch::aarch64::rndr;
    // Both wrappers gate the instruction on this CPU's ID_AA64ISAR0_EL1.
    if seed_words(seed, || rndr_retry(rndr::try_rndrrs))
        || seed_words(seed, || rndr_retry(rndr::try_rndr))
    {
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

// ── Key-material entropy surface (issue #996) ────────────────────────
//
// The only sanctioned source for SMS/SMK-class key material
// (power-suspend design §1.4, lane P0). Two disciplines separate it from
// the protocol adapter above:
//
// * Seed-grade source only. x86_64 draws RDSEED and never falls back to
//   RDRAND (a conditioned DRBG output per spec §6, not an entropy
//   source); aarch64 draws RNDRRS/RNDR. Availability is probed from
//   CPUID / ID_AA64ISAR0_EL1 on every draw — never assumed.
// * SP 800-90B health tests (spec §3.2) cover every released byte: a
//   startup test over 1024 drawn-and-discarded bytes before the first
//   release, then continuous tests for the life of the boot. A failure
//   latches the source off permanently; absence, starvation, and health
//   failure all return `CryptoError::EntropyUnavailable` — the spec §5
//   starvation rule. There is no path from here to the cycle-counter
//   placeholder behind `per_task_rng`.

/// Repetition Count Test cutoff: 33 consecutive identical bytes
/// (SP 800-90B §4.4.1, `1 + ⌈−log2(α)/H⌉` at α = 2^-32, H = 1 bit/byte).
const RCT_CUTOFF: u32 = 33;
/// Adaptive Proportion Test window in bytes (SP 800-90B §4.4.2).
const APT_WINDOW: usize = 512;
/// Adaptive Proportion Test cutoff: a window fails when its reference
/// (first) byte occurs 326 times in the window — the Bin(511, 2^-1)
/// critical value at α = 2^-32 (mean 255.5 + 6.2σ, σ ≈ 11.3), again at
/// the conservative assumed min-entropy H = 1 bit/byte.
const APT_CUTOFF: u32 = 326;
/// Startup test length: bytes drawn and discarded through the health
/// tests before the first key-material byte may be released.
const STARTUP_BYTES: usize = 1024;

/// SP 800-90B RCT + APT state, fed one raw byte at a time. The tests run
/// over the unexpanded source stream — each 64-bit source word
/// contributes eight little-endian bytes — because they exist to catch
/// a failing *source* (stuck-at, degrading, or starved output), not to
/// audit the ChaCha20 expansion seeded from it.
#[derive(Debug)]
struct HealthTests {
    failed: bool,
    run_value: u8,
    run_len: u32,
    apt_ref: u8,
    apt_count: u32,
    apt_filled: usize,
}

impl HealthTests {
    const fn new() -> Self {
        Self {
            failed: false,
            run_value: 0,
            run_len: 0,
            apt_ref: 0,
            apt_count: 0,
            apt_filled: 0,
        }
    }

    fn feed(&mut self, byte: u8) -> Result<(), CryptoError> {
        if self.failed {
            return Err(CryptoError::EntropyUnavailable);
        }
        // Repetition Count Test: one value repeating RCT_CUTOFF times in
        // a row is a failed source, full stop.
        if self.run_len > 0 && byte == self.run_value {
            self.run_len += 1;
            if self.run_len >= RCT_CUTOFF {
                self.failed = true;
                return Err(CryptoError::EntropyUnavailable);
            }
        } else {
            self.run_value = byte;
            self.run_len = 1;
        }
        // Adaptive Proportion Test: within each window, count how often
        // the window's first byte recurs; a dominant value means the
        // source's distribution has collapsed.
        if self.apt_filled == 0 {
            self.apt_ref = byte;
            self.apt_count = 1;
            self.apt_filled = 1;
        } else {
            if byte == self.apt_ref {
                self.apt_count += 1;
                if self.apt_count >= APT_CUTOFF {
                    self.failed = true;
                    return Err(CryptoError::EntropyUnavailable);
                }
            }
            self.apt_filled += 1;
            if self.apt_filled == APT_WINDOW {
                self.apt_filled = 0;
            }
        }
        Ok(())
    }

    fn feed_all(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        for byte in bytes {
            self.feed(*byte)?;
        }
        Ok(())
    }
}

const PHASE_UNTESTED: u8 = 0;
const PHASE_HEALTHY: u8 = 1;
const PHASE_FAILED: u8 = 2;

/// Health state for the key-material source: a one-way phase latch over
/// the continuous test state. UNTESTED runs the startup test on first
/// use; FAILED is terminal for the boot — a source that failed its
/// health tests is never trusted again, per spec §3.2's "failure
/// disables the primary source" with no in-kernel fallback to take over.
#[derive(Debug)]
struct EntropyHealth {
    phase: AtomicU8,
    tests: IrqSafeSpinLock<HealthTests>,
}

impl EntropyHealth {
    const fn new() -> Self {
        Self {
            phase: AtomicU8::new(PHASE_UNTESTED),
            tests: IrqSafeSpinLock::new(HealthTests::new()),
        }
    }

    fn failed(&self) -> bool {
        self.phase.load(Ordering::Acquire) == PHASE_FAILED
    }

    /// Feed bytes through the continuous tests, latching FAILED on a
    /// trip. Used for the startup stream and for every released seed.
    fn observe(&self, bytes: &[u8]) -> Result<(), CryptoError> {
        let result = self.tests.lock().feed_all(bytes);
        if result.is_err() {
            self.phase.store(PHASE_FAILED, Ordering::Release);
        }
        result
    }

    /// Run the startup test once: draw STARTUP_BYTES from the source
    /// and discard them through the health tests before anything is
    /// released. Starvation leaves the phase UNTESTED (a later draw
    /// retries); a health-test trip latches FAILED via `observe`.
    fn ensure_started(
        &self,
        next_word: &mut impl FnMut() -> Option<u64>,
    ) -> Result<(), CryptoError> {
        match self.phase.load(Ordering::Acquire) {
            PHASE_HEALTHY => return Ok(()),
            PHASE_FAILED => return Err(CryptoError::EntropyUnavailable),
            _ => {}
        }
        for _ in 0..STARTUP_BYTES / 8 {
            let Some(word) = next_word() else {
                return Err(CryptoError::EntropyUnavailable);
            };
            self.observe(&word.to_le_bytes())?;
        }
        // A concurrent startup may have latched FAILED on shared state.
        if self.failed() {
            return Err(CryptoError::EntropyUnavailable);
        }
        self.phase.store(PHASE_HEALTHY, Ordering::Release);
        Ok(())
    }
}

static KEY_MATERIAL_HEALTH: EntropyHealth = EntropyHealth::new();

/// Is the seed-grade architectural source present (CPUID leaf 7
/// EBX:18 RDSEED / ID_AA64ISAR0_EL1.RNDR)? Probed, never assumed; the
/// protocol adapter's RDRAND does not count.
#[cfg(target_arch = "x86_64")]
fn seed_source_present() -> bool {
    // SAFETY: probing CPUID has no memory or privilege preconditions.
    unsafe { narf_arch::x86_64::cpuid::Features::probe() }.rdseed
}

#[cfg(target_arch = "aarch64")]
fn seed_source_present() -> bool {
    narf_arch::aarch64::rndr::supported()
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn seed_source_present() -> bool {
    false
}

/// One 64-bit word from the seed-grade source, or `None` when the
/// source is absent or its bounded retries are exhausted. Key material
/// never sees RDRAND on x86_64 (see the section comment above).
#[cfg(target_arch = "x86_64")]
fn hw_key_word() -> Option<u64> {
    use narf_arch::x86_64::{cpuid::Features, hwrng};
    // SAFETY: probing CPUID has no memory or privilege preconditions.
    let features = unsafe { Features::probe() };
    if !features.rdseed {
        return None;
    }
    // SAFETY: this CPU advertises RDSEED. Each read has a bounded retry.
    let low = unsafe { hwrng::rdseed_u32() }?;
    // SAFETY: same feature gate as above.
    let high = unsafe { hwrng::rdseed_u32() }?;
    Some(u64::from(low) | (u64::from(high) << 32))
}

#[cfg(target_arch = "aarch64")]
fn hw_key_word() -> Option<u64> {
    use narf_arch::aarch64::rndr;
    // Both wrappers gate the instruction on this CPU's ID_AA64ISAR0_EL1.
    // RNDRRS (reseeding) is preferred; RNDR is the same seed-grade source.
    rndr_retry(rndr::try_rndrrs).or_else(|| rndr_retry(rndr::try_rndr))
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn hw_key_word() -> Option<u64> {
    None
}

/// Draw one 32-byte seed from `next_word` under `health`: startup test
/// first (once), continuous tests over the seed bytes before they are
/// released to the caller. Any error zeroizes the seed buffer; a short
/// source leaves no partial seed (`seed_words` guarantees that too).
fn key_seed_with(
    health: &EntropyHealth,
    next_word: &mut impl FnMut() -> Option<u64>,
    seed: &mut [u8; 32],
) -> Result<(), CryptoError> {
    if health.failed() {
        seed.zeroize();
        return Err(CryptoError::EntropyUnavailable);
    }
    if let Err(error) = health.ensure_started(next_word) {
        seed.zeroize();
        return Err(error);
    }
    if !seed_words(seed, || next_word()) {
        return Err(CryptoError::EntropyUnavailable);
    }
    if let Err(error) = health.observe(seed) {
        seed.zeroize();
        return Err(error);
    }
    Ok(())
}

fn key_rng_with(
    health: &EntropyHealth,
    mut next_word: impl FnMut() -> Option<u64>,
) -> Result<ChaCha20Rng, CryptoError> {
    let mut seed = Zeroizing::new([0; 32]);
    key_seed_with(health, &mut next_word, &mut seed)?;
    Ok(ChaCha20Rng::from_seed(*seed))
}

fn fill_key_material_with(
    out: &mut [u8],
    health: &EntropyHealth,
    next_word: impl FnMut() -> Option<u64>,
) -> Result<(), CryptoError> {
    if out.is_empty() {
        return Ok(());
    }
    let mut rng = match key_rng_with(health, next_word) {
        Ok(rng) => rng,
        Err(error) => {
            out.zeroize();
            return Err(error);
        }
    };
    rng.fill_bytes(out);
    Ok(())
}

/// Whether key material may be generated on this machine right now:
/// the seed-grade architectural source is present, the SP 800-90B
/// startup test passes, and the continuous tests have not latched the
/// source off. The first call performs (and discards) the startup draw,
/// so this is also the cheapest way for a caller such as the suspend
/// service to learn, before enrollment, that generation would refuse.
pub fn has_hw_entropy() -> bool {
    if !seed_source_present() {
        return false;
    }
    KEY_MATERIAL_HEALTH.ensure_started(&mut hw_key_word).is_ok()
}

/// Fill `out` with key-material bytes expanded from a fresh,
/// health-checked architectural seed. This is the fill the suspend
/// service's SMS/SMK generation (and any other long-term secret
/// generation) must use; it fails closed — whole output zeroized,
/// `CryptoError::EntropyUnavailable` — when the seed-grade source is
/// absent, starved, or health-latched off. An empty request succeeds
/// without consulting the source. Key material must never come from
/// `per_task_rng` or be mixed with its output.
pub fn try_fill_key_material(out: &mut [u8]) -> Result<(), CryptoError> {
    fill_key_material_with(out, &KEY_MATERIAL_HEALTH, hw_key_word)
}

/// Construct a ChaCha20 stream seeded from a fresh, health-checked
/// architectural seed, for key-generation loops that need a stream
/// rather than a fill. Same refusal semantics as
/// [`try_fill_key_material`]: no healthy seed-grade source, no stream.
pub fn key_material_rng() -> Result<ChaCha20Rng, CryptoError> {
    key_rng_with(&KEY_MATERIAL_HEALTH, hw_key_word)
}

#[path = "entropy_tests.rs"]
mod tests;
