//! Synchronous device-owner bridge to CPU alias revocation.
use crate::FsError;
use alloc::sync::Arc;
use narf_lib::sync::IrqSafeSpinLock;
pub use narf_memory::address_space::{
    DeviceAliasCensus, DeviceFrameRefault, DeviceFrameRevocation, DeviceRefaultError,
    DeviceRefaultFuture,
};

pub type RelocationHook = fn(
    &[u64],
    &[u64],
    fn(u64) -> usize,
    &mut dyn FnMut() -> Result<(), FsError>,
) -> Result<(), FsError>;
static HOOK: IrqSafeSpinLock<Option<RelocationHook>> = IrqSafeSpinLock::new(None);
type AliasHooks = (fn(u64) -> bool, fn(u64) -> bool);
const MAX_ALIAS_PROVIDERS: usize = 8;
struct AliasRegistry {
    hooks: [Option<AliasHooks>; MAX_ALIAS_PROVIDERS],
}
impl AliasRegistry {
    const fn new() -> Self {
        Self {
            hooks: [None; MAX_ALIAS_PROVIDERS],
        }
    }
    fn register(
        &mut self,
        retain: fn(u64) -> bool,
        release: fn(u64) -> bool,
    ) -> Result<(), FsError> {
        if let Some((_, old_release)) = self
            .hooks
            .iter()
            .flatten()
            .find(|(old, _)| core::ptr::fn_addr_eq(*old, retain))
        {
            return if core::ptr::fn_addr_eq(*old_release, release) {
                Ok(())
            } else {
                Err(FsError::InvalidData)
            };
        }
        let slot = self
            .hooks
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(FsError::NoSpace)?;
        *slot = Some((retain, release));
        Ok(())
    }
}
static ALIASES: IrqSafeSpinLock<AliasRegistry> = IrqSafeSpinLock::new(AliasRegistry::new());

/// Register one permanent device-frame owner. Repeated identical registration
/// is idempotent; an existing retain callback cannot change its release partner.
/// Providers own disjoint physical frames and keep a claimed frame registered
/// until its final alias is released. No unregister/replacement is permitted.
/// Callbacks run after the registry lock is dropped, in registration order.
pub fn register_alias_hooks(
    retain: fn(u64) -> bool,
    release: fn(u64) -> bool,
) -> Result<(), FsError> {
    ALIASES.lock().register(retain, release)
}

/// Compatibility installer for an infallible, card-lifetime provider. New
/// mapping providers should use the fallible registration before publication.
pub fn install_alias_hooks(retain: fn(u64) -> bool, release: fn(u64) -> bool) {
    register_alias_hooks(retain, release).expect("device alias provider registration failed");
}
pub fn retain_alias(phys: u64) -> bool {
    let hooks = ALIASES.lock().hooks;
    hooks.into_iter().flatten().any(|(retain, _)| retain(phys))
}
pub fn release_alias(phys: u64) -> bool {
    let hooks = ALIASES.lock().hooks;
    hooks
        .into_iter()
        .flatten()
        .any(|(_, release)| release(phys))
}

/// The VM owner installs this before admitting revocable device mappings.
pub fn install(hook: RelocationHook) {
    *HOOK.lock() = Some(hook);
}

/// Swap the VM hook, returning the previous one. Tests that substitute a VM
/// owner must restore the returned hook before finishing.
pub fn replace(hook: Option<RelocationHook>) -> Option<RelocationHook> {
    core::mem::replace(&mut *HOOK.lock(), hook)
}

/// Freeze all CPU aliases and call `commit` only after global invalidation.
/// The hook must restore the old aliases on error and install `new` on success.
/// Neither the hook nor commit may await. Source and destination allocations
/// must stay owned until this call returns.
pub fn relocate(
    old: &[u64],
    new: &[u64],
    aliases: fn(u64) -> usize,
    commit: &mut dyn FnMut() -> Result<(), FsError>,
) -> Result<(), FsError> {
    let hook = (*HOOK.lock()).ok_or(FsError::Unsupported)?;
    hook(old, new, aliases, commit)
}

/// `(start, len, census, refault)`: see [`revoke`].
pub type RevocationHook = fn(
    u64,
    u64,
    DeviceAliasCensus,
    Arc<dyn DeviceFrameRefault>,
) -> Result<DeviceFrameRevocation, FsError>;
static REVOCATION: IrqSafeSpinLock<Option<RevocationHook>> = IrqSafeSpinLock::new(None);

/// The VM owner installs this beside [`install`].
pub fn install_revocation(hook: RevocationHook) {
    *REVOCATION.lock() = Some(hook);
}

/// Swap the revocation hook, returning the previous one, for tests that
/// substitute a VM owner.
pub fn replace_revocation(hook: Option<RevocationHook>) -> Option<RevocationHook> {
    core::mem::replace(&mut *REVOCATION.lock(), hook)
}

/// Linux `unmap_mapping_range` over a device aperture for runtime suspend:
/// remove every user CPU translation of `[start, start + len)` in every
/// process and keep the range revoked until the returned handle drops; new
/// mappings of the range stay unmapped too. A later CPU access calls
/// `refault`, which must resume the device and drop the handle before its
/// future completes. `census` reports every aliased frame of the range with
/// its metadata-alias count (the provider's alias registry), from inside the
/// VM transaction; it may take only leaf locks and must not allocate. `Busy`
/// means an alias the snapshot could not see (retry later).
///
/// Before any device mapping exists the VM owner has not installed its hook
/// (it does so on the first device mmap). The revocation is then taken over
/// an empty address-space snapshot, which the census proves complete: any
/// alias of the range would be reported and refused as unseen.
pub fn revoke(
    start: u64,
    len: u64,
    census: DeviceAliasCensus,
    refault: Arc<dyn DeviceFrameRefault>,
) -> Result<DeviceFrameRevocation, FsError> {
    let hook = *REVOCATION.lock();
    if let Some(hook) = hook {
        return hook(start, len, census, refault);
    }
    // SAFETY: the caller owns the aperture for the handle's lifetime; with
    // no address space named, the census refuses any existing alias.
    unsafe {
        narf_memory::address_space::revoke_device_frames(
            &[],
            narf_memory::PhysAddr::new(start),
            len,
            census,
            refault,
        )
    }
    .map_err(|error| match error {
        narf_memory::AddressSpaceError::AllocationFailed => FsError::OutOfMemory,
        narf_memory::AddressSpaceError::AlignmentMismatch => FsError::InvalidData,
        _ => FsError::Busy,
    })
}

#[path = "mmap_relocation_tests.rs"]
mod tests;
