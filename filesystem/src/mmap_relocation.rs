//! Synchronous device-owner bridge to CPU alias revocation.
use crate::FsError;
use narf_lib::sync::IrqSafeSpinLock;

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

#[path = "mmap_relocation_tests.rs"]
mod tests;
