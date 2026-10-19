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
static ALIASES: IrqSafeSpinLock<Option<AliasHooks>> = IrqSafeSpinLock::new(None);

/// Install the device-frame registry's metadata lifetime hooks.
pub fn install_alias_hooks(retain: fn(u64) -> bool, release: fn(u64) -> bool) {
    let mut hooks = ALIASES.lock();
    if let Some((old, _)) = *hooks {
        assert!(
            core::ptr::fn_addr_eq(old, retain),
            "device alias owner replaced"
        );
    } else {
        *hooks = Some((retain, release));
    }
}
pub fn retain_alias(phys: u64) -> bool {
    let hooks = *ALIASES.lock();
    hooks.is_some_and(|(retain, _)| retain(phys))
}
pub fn release_alias(phys: u64) -> bool {
    let hooks = *ALIASES.lock();
    hooks.is_some_and(|(_, release)| release(phys))
}

/// The VM owner installs this before admitting revocable device mappings.
pub fn install(hook: RelocationHook) {
    *HOOK.lock() = Some(hook);
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
