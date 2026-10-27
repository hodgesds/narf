//! KEYS-domain custody for suspend key material.
//!
//! The suspend service's secrets (the per-epoch slot master secret and
//! per-image keys) live in [`Secret32`], which copies the `VkBytes`
//! discipline from `block/src/encrypted.rs` exactly (power-suspend
//! design §1.4 / §3.1): the constructor asserts the caller runs in
//! `DomainId::KEYS` (accepting `FRAME` as the forward-compatible gate,
//! the same stop-gap `VkBytes` documents until the arch domain hook
//! returns real PKRS/MTE values), the bytes are yielded only to a
//! closure — there is no `as_slice` and no `Deref` — and the storage
//! zeroizes on drop so a reused heap/stack slot carries no residue.

use core::fmt;
use narf_lib::assert::current_domain;
use narf_lib::id::DomainId;
use zeroize::Zeroizing;

/// A 32-byte secret held under KEYS-domain custody discipline.
///
/// Construct via [`Secret32::mint`]; consume via
/// [`Secret32::with_bytes`]. The wrapper is deliberately not `Clone`:
/// a second copy of a secret is a new custody decision, never a
/// side effect of moving data around.
pub struct Secret32 {
    bytes: Zeroizing<[u8; 32]>,
}

impl Secret32 {
    /// Mint a custody wrapper from raw material. Asserts the active
    /// domain is `DomainId::KEYS` — release builds panic on mismatch
    /// (a security bug, not a correctness bug). `DomainId::FRAME` is
    /// accepted as the same forward-compatible gate `VkBytes` uses:
    /// until the `narf_arch_current_domain` hook returns real
    /// PKRS/MTE-derived values, kernel bring-up callers read back
    /// FRAME regardless of the active domain.
    pub fn mint(bytes: [u8; 32]) -> Self {
        let dom = current_domain();
        if dom != DomainId::KEYS && dom != DomainId::FRAME {
            panic!(
                "Secret32::mint: caller must be in DomainId::KEYS, observed {} (security bug)",
                dom.raw(),
            );
        }
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Yield the secret bytes to `f` for the duration of the call.
    /// The slice cannot escape the closure.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        f(&self.bytes)
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32(<redacted>)")
    }
}
