//! SDIO function-driver registration for loadable modules.
//!
//! `bus` sits below the SDIO stack, so it cannot reach the SDIO function-driver
//! registry directly. The registry (`narf-drivers-sdio`) installs one permanent
//! [`Host`] at boot; the `narf_register_sdio_driver` kernel-ABI export forwards
//! through it, and the module loader's unload path calls
//! [`unregister_module_sdio_drivers`] before it unmaps module text — the same
//! ordering contract as [`crate::unregister_module_pci_drivers`] and
//! [`crate::module_usb::unregister_module_usb_drivers`].
//!
//! A module's probe never runs directly: the SDIO dispatcher calls it through
//! [`call_module_sdio_probe`], i.e. the module subsystem's probe call gate,
//! which pins the module Live and enters its effective protection domain.
//! Registration-only for now — no SDIO datapath export accepts the opaque
//! `dev_token` yet, so a module probe can match and claim but not drive.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::driver_match::{call_module_probe, intern_name, ModuleProbeFn};

/// One SDIO function-driver match: the card's `(vendor, device)` behind the
/// given SDIO function number (F1..=F7; F0 is the common control function and
/// is never a driver's claim).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ModuleSdioMatch {
    pub vendor: u16,
    pub device: u16,
    pub function: u8,
}

impl ModuleSdioMatch {
    /// Validate the function number the way `register_function_driver` does;
    /// `-EINVAL` for F0 or a function above F7.
    pub fn new(vendor: u16, device: u16, function: u8) -> Result<Self, i32> {
        if function == 0 || function > 7 {
            return Err(-22);
        }
        Ok(Self {
            vendor,
            device,
            function,
        })
    }
}

/// Permanent, kernel-resident registry adapter. No hook may point into
/// unloadable text. `register` returns 0 or a negative errno; `unregister`
/// removes every match `owner` registered and must be idempotent.
#[derive(Debug)]
pub struct Host {
    pub register:
        fn(owner: u64, name: &'static str, m: ModuleSdioMatch, probe: ModuleProbeFn) -> i32,
    pub unregister: fn(owner: u64),
}

static HOST: AtomicUsize = AtomicUsize::new(0);

/// Install the SDIO registry adapter. One host for the kernel's lifetime:
/// re-installing the same host is a no-op success, a different one `-EBUSY`.
pub fn register(host: &'static Host) -> Result<(), i32> {
    let new = host as *const Host as usize;
    match HOST.compare_exchange(0, new, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(old) if old == new => Ok(()),
        Err(_) => Err(-16),
    }
}

fn host() -> Option<&'static Host> {
    let raw = HOST.load(Ordering::Acquire);
    // SAFETY: only `register` stores here, and it stores a `&'static Host`.
    (raw != 0).then(|| unsafe { &*(raw as *const Host) })
}

/// Register a module's SDIO match. Reached from the `narf_register_sdio_driver`
/// export. `-EINVAL` for a null probe, `-ENODEV` when this kernel has no SDIO
/// stack (no host installed), otherwise the host's result.
///
/// # Safety
/// `probe` must be a valid [`ModuleProbeFn`] address that stays mapped for as
/// long as the match is registered (the loader unregisters it before unmap).
pub unsafe fn register_module_sdio_driver(
    owner: u64,
    name: &str,
    m: ModuleSdioMatch,
    probe: usize,
) -> i32 {
    if probe == 0 {
        return -22;
    }
    let Some(host) = host() else {
        return -19;
    };
    // SAFETY: the caller promises `probe` is a valid `ModuleProbeFn` address.
    let thunk: ModuleProbeFn = unsafe { core::mem::transmute(probe) };
    (host.register)(owner, intern_name(name), m, thunk)
}

/// Remove every SDIO match owned by one loadable module. The caller runs the
/// module's exit hook first and calls this before unmapping module text.
pub fn unregister_module_sdio_drivers(owner: u64) {
    if let Some(host) = host() {
        (host.unregister)(owner);
    }
}

/// Call a module's SDIO probe through the module subsystem's call gate.
/// `-ENODEV` when no gate is installed: module text never runs without it.
pub fn call_module_sdio_probe(owner: u64, probe: ModuleProbeFn, dev_token: u64) -> i32 {
    call_module_probe(owner, probe, dev_token, 0)
}

#[doc(hidden)]
/// Test-only: forget the installed host so a smoke can prove `-ENODEV`.
pub fn __reset_host_for_test() {
    HOST.store(0, Ordering::Release);
}
