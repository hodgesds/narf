//! Module-management syscalls.
//!
//! Linux ref: `linux/kernel/module/main.c::SYSCALL_DEFINE3(init_module)`
//! (`main.c:3580`) + `SYSCALL_DEFINE3(finit_module)` (`main.c:3700`) +
//! `SYSCALL_DEFINE2(delete_module)` (`main.c:3045`).
//!
//! These functions are the pure-Rust kernel side; the userspace
//! syscall dispatcher in `narf-userspace` calls them with the
//! caller's arguments already extracted from the trap frame.

use alloc::sync::Arc;

use crate::loader::{self, LoadError, Module};
use crate::registry;

/// `sys_init_module(image_ptr, len, params_ptr)` — load a module
/// from an in-memory image. The caller's address space must already
/// hold the image bytes; the kernel copies them into its own buffer
/// before parsing.
///
/// Returns the freshly-loaded module on success.
///
/// # Safety
/// `bytes` must be a valid slice for `len` bytes. Caller checks the
/// user pointer first (this function is the kernel-side wrapper, not
/// the syscall trap directly).
pub fn sys_init_module(bytes: &[u8]) -> Result<Arc<Module>, ModuleSyscallError> {
    let module = loader::load_image(bytes).map_err(ModuleSyscallError::Load)?;

    if registry::contains(module.name()) {
        return Err(ModuleSyscallError::Load(LoadError::AlreadyLoaded(
            module.name().into(),
        )));
    }
    registry::insert(module.clone());

    // Call the init function; if it fails, unregister and surface the
    // error. SAFETY: we just loaded the module and own its placements.
    // SAFETY: Valid memory or trusted environment
    let invoke = unsafe { loader::invoke_init(&module) };
    if let Err(e) = invoke {
        registry::remove(module.name());
        return Err(ModuleSyscallError::InitFailed(e));
    }
    Ok(module)
}

/// `sys_finit_module(fd, params, flags)` — Linux variant that reads
/// the image from a file descriptor. NARF surfaces this as a thin
/// wrapper that asks the FS layer for the bytes; once read, the
/// load path is identical to `sys_init_module`.
pub fn sys_finit_module(bytes: &[u8]) -> Result<Arc<Module>, ModuleSyscallError> {
    sys_init_module(bytes)
}

/// `sys_delete_module(name, flags)` — unload `name` if its refcount
/// is zero. Linux's `flags` carries `O_NONBLOCK` etc.; NARF ignores
/// those today (we never block).
///
/// Sequence mirrors `linux/kernel/module/main.c::free_module`:
///   1. invoke_exit (state Going → Dead)
///   2. sweep KSYMTAB — `unregister_exports_of` removes all entries
///      owned by this module, preventing use-after-free on any later
///      `resolve` call (DESIGN.md §6)
///   3. remove from registry (drops the Arc, freeing placements)
pub fn sys_delete_module(name: &str) -> Result<(), ModuleSyscallError> {
    let module = registry::lookup(name).ok_or(ModuleSyscallError::NotFound)?;

    // SAFETY: registry::lookup gave us an Arc<Module> that owns its
    // placements; we hold it until invoke_exit returns, after which
    // registry::remove drops the registry's reference.
    // SAFETY: Valid memory or trusted environment
    unsafe { loader::invoke_exit(&module) }.map_err(ModuleSyscallError::ExitFailed)?;

    // Sweep all KSYMTAB entries registered by this module during its
    // init.  Must happen before the Arc is dropped so that if the
    // module's exit handler re-exported anything, those are gone too.
    let _removed = crate::symbols::unregister_exports_of(module.id);

    registry::remove(name);

    // Unmap the image last. Everything above has already made the module
    // unreachable — it is out of the registry and its exports are gone — so
    // this is the point at which returning the frames is safe.
    //
    // NOT yet safe against a CPU still *executing* module code: a task that
    // entered the module before `invoke_exit` and is preempted inside it
    // would resume on unmapped text. Closing that needs an RCU grace period
    // between the sweep above and this free, which is the same gap
    // `DESIGN.md` records for inter-module symbol references. Linux serialises
    // this differently — `delete_module` refuses unless the refcount is zero
    // *and* the module is quiesced via `stop_machine` on
    // `CONFIG_MODULE_UNLOAD_TAINT_TRACKING` kernels.
    //
    // SAFETY: `invoke_exit` returned, the refcount was zero, the exports are
    // swept, and the registry no longer names this module.
    unsafe { loader::release_image(&module) };
    Ok(())
}

/// User-facing error type. Each variant maps to a stable negative
/// errno in the syscall trap shim.
#[derive(Debug, PartialEq, Eq)]
pub enum ModuleSyscallError {
    Load(LoadError),
    InitFailed(crate::lifecycle::LifecycleError),
    ExitFailed(crate::lifecycle::LifecycleError),
    NotFound,
}

impl ModuleSyscallError {
    /// Whether this failure means "the image is not a NARF-loadable
    /// module" — a foreign Linux `.ko`, a builtin driver's stub, or
    /// anything lacking NARF's `.modinfo` / `narf_module_init`
    /// contract. NARF is monolithic: the drivers `modprobe(8)` and
    /// `systemd-modules-load` ask for (drm, etc.) are either compiled
    /// in or genuinely absent, never side-loadable. Linux answers a
    /// builtin `finit_module` with `EEXIST`, which libkmod/modprobe
    /// treat as success; the userspace shim maps this class to a
    /// success no-op so those units complete instead of failing the
    /// job (which would block dependents past the timeout).
    ///
    /// Genuine NARF modules that fail *after* being recognised as ours
    /// (`InitFailed`, `AlreadyLoaded`, a relocation fault) are NOT in
    /// this class — those surface a real errno.
    pub fn is_foreign_image(&self) -> bool {
        matches!(
            self,
            ModuleSyscallError::Load(LoadError::Header(_))
                | ModuleSyscallError::Load(LoadError::Manifest(_))
                | ModuleSyscallError::Load(LoadError::Domain(_))
                | ModuleSyscallError::Load(LoadError::NoSymbols)
                | ModuleSyscallError::Load(LoadError::BadSection(_))
                | ModuleSyscallError::Load(LoadError::MissingInit)
                | ModuleSyscallError::Load(LoadError::SignatureRejected(_))
        )
    }

    /// Convert to a negative errno suitable for the syscall return
    /// register. The wire numbers match Linux:
    ///   * `-EBUSY = -16` — refcount > 0 in delete_module.
    ///   * `-ENOENT = -2` — module name not found.
    ///   * `-EBADF = -9` — invalid image.
    ///   * `-EINVAL = -22` — manifest / arch / sig rejection.
    ///   * `-EKEYREJECTED = -129` — signature rejected.
    pub fn to_errno(&self) -> i32 {
        match self {
            ModuleSyscallError::Load(LoadError::SignatureRejected(_)) => -129,
            ModuleSyscallError::Load(LoadError::Header(_)) => -8,
            ModuleSyscallError::Load(LoadError::Manifest(_)) => -22,
            ModuleSyscallError::Load(LoadError::Domain(_)) => -22,
            ModuleSyscallError::Load(LoadError::NoSymbols) => -22,
            ModuleSyscallError::Load(LoadError::BadSection(_)) => -22,
            ModuleSyscallError::Load(LoadError::Relocator(_)) => -8,
            ModuleSyscallError::Load(LoadError::AlreadyLoaded(_)) => -17,
            ModuleSyscallError::Load(LoadError::MissingInit) => -22,
            // -ENOMEM: no module VA, no frames, or the image could not be
            // given its final permissions.
            ModuleSyscallError::Load(LoadError::Image(_)) => -12,
            ModuleSyscallError::InitFailed(_) => -22,
            ModuleSyscallError::ExitFailed(crate::lifecycle::LifecycleError::Busy(_)) => -16,
            ModuleSyscallError::ExitFailed(_) => -22,
            ModuleSyscallError::NotFound => -2,
        }
    }
}
