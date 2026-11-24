//! Entropy for the kernel-free build (`default-features = false`).
//!
//! The kernel build draws randomness from the architectural RNG behind SP
//! 800-90B health tests (`entropy.rs`). That code needs `narf-arch` and a
//! kernel lock, so a loadable module — which links only the KABI — cannot
//! carry it. Instead the module installs its source once at init, normally a
//! wrapper over the kernel's DRBG export, and [`try_fill_random_bytes`] keeps
//! the kernel build's name and contract for the protocol code above it (SAE
//! commit scalars, EAPOL nonces).
//!
//! Fail-closed: with no source installed, or when the source reports
//! failure, the call returns [`CryptoError::EntropyUnavailable`] and the
//! output is zeroed — the same refusal the kernel build gives when no healthy
//! architectural source exists. There is no deterministic fallback.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::CryptoError;

/// A secure randomness source: fill every byte of the slice with
/// unpredictable output and return `true`, or return `false`.
pub type EntropySource = fn(&mut [u8]) -> bool;

/// The installed [`EntropySource`], as an address; zero means none.
static SOURCE: AtomicUsize = AtomicUsize::new(0);

/// Install the source [`try_fill_random_bytes`] draws from. Later calls
/// replace it. A module calls this from `narf_module_init`, before any
/// protocol code that needs randomness can run.
pub fn install_entropy_source(source: EntropySource) {
    SOURCE.store(source as usize, Ordering::Release);
}

/// Whether a source has been installed.
pub fn has_entropy_source() -> bool {
    SOURCE.load(Ordering::Acquire) != 0
}

/// Fill `out` with secure random bytes from the installed source.
pub fn try_fill_random_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
    let addr = SOURCE.load(Ordering::Acquire);
    if addr != 0 {
        // SAFETY: `SOURCE` only ever holds zero or the address of an
        // `EntropySource` stored by `install_entropy_source`.
        let source: EntropySource = unsafe { core::mem::transmute::<usize, EntropySource>(addr) };
        if source(out) {
            return Ok(());
        }
    }
    out.fill(0);
    Err(CryptoError::EntropyUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failing(_: &mut [u8]) -> bool {
        false
    }

    fn counting(out: &mut [u8]) -> bool {
        for (i, b) in out.iter_mut().enumerate() {
            *b = i as u8 ^ 0x5a;
        }
        true
    }

    #[test]
    fn fails_closed_and_zeroes_until_a_source_succeeds() {
        // One test owns the global so ordering is deterministic.
        let mut buf = [0xffu8; 8];
        if !has_entropy_source() {
            assert_eq!(
                try_fill_random_bytes(&mut buf),
                Err(CryptoError::EntropyUnavailable)
            );
            assert_eq!(buf, [0; 8]);
        }
        install_entropy_source(failing);
        buf = [0xff; 8];
        assert_eq!(
            try_fill_random_bytes(&mut buf),
            Err(CryptoError::EntropyUnavailable)
        );
        assert_eq!(buf, [0; 8]);
        install_entropy_source(counting);
        assert_eq!(try_fill_random_bytes(&mut buf), Ok(()));
        assert_eq!(buf[1], 1 ^ 0x5a);
    }
}
