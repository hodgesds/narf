//! USB class-driver registration for loadable modules.
//!
//! `bus` sits below the USB stack, so it cannot reach the USB class-driver
//! registry directly. The registry (`narf-drivers-usb`) installs one
//! permanent [`Host`] at boot; the `narf_register_usb_driver` kernel-ABI
//! export forwards through it, and the module loader's unload path calls
//! [`unregister_module_usb_drivers`] before it unmaps module text — the same
//! ordering contract as [`crate::unregister_module_pci_drivers`].
//!
//! A module's probe never runs directly: the USB dispatcher calls it through
//! [`call_module_usb_probe`], i.e. the module subsystem's probe call gate,
//! which pins the module Live and enters its effective protection domain.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::driver_match::{call_module_probe, intern_name, ModuleProbeFn};

/// Match on `(idVendor, idProduct)`. Linux `USB_DEVICE_ID_MATCH_DEVICE`.
pub const MATCH_VENDOR_PRODUCT: u16 = 1 << 0;
/// Match an interface's `bInterfaceClass`. Linux `USB_DEVICE_ID_MATCH_INT_CLASS`.
pub const MATCH_INT_CLASS: u16 = 1 << 1;
/// Match an interface's `bInterfaceSubClass`.
pub const MATCH_INT_SUBCLASS: u16 = 1 << 2;
/// Match an interface's `bInterfaceProtocol`.
pub const MATCH_INT_PROTOCOL: u16 = 1 << 3;
/// Every flag a module may set.
pub const MATCH_ALL: u16 =
    MATCH_VENDOR_PRODUCT | MATCH_INT_CLASS | MATCH_INT_SUBCLASS | MATCH_INT_PROTOCOL;

/// One validated module match entry. Fields a flag does not select are
/// "match any"; without [`MATCH_VENDOR_PRODUCT`] the VID/PID are 0, the USB
/// registry's explicit wildcard (VID 0 is not assignable to a device).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ModuleUsbMatch {
    pub vendor_id: u16,
    pub product_id: u16,
    pub class: Option<u8>,
    pub subclass: Option<u8>,
    pub protocol: Option<u8>,
}

impl ModuleUsbMatch {
    /// Build a match from the export's flag-encoded arguments. `-EINVAL` for
    /// unknown flags, no flags at all (a module may not claim every device),
    /// or a vendor/product match on the reserved VID 0.
    pub fn from_flags(
        flags: u16,
        vendor_id: u16,
        product_id: u16,
        class: u8,
        subclass: u8,
        protocol: u8,
    ) -> Result<Self, i32> {
        if flags == 0 || flags & !MATCH_ALL != 0 {
            return Err(-22);
        }
        let by_id = flags & MATCH_VENDOR_PRODUCT != 0;
        if by_id && vendor_id == 0 {
            return Err(-22);
        }
        Ok(Self {
            vendor_id: if by_id { vendor_id } else { 0 },
            product_id: if by_id { product_id } else { 0 },
            class: (flags & MATCH_INT_CLASS != 0).then_some(class),
            subclass: (flags & MATCH_INT_SUBCLASS != 0).then_some(subclass),
            protocol: (flags & MATCH_INT_PROTOCOL != 0).then_some(protocol),
        })
    }
}

/// Permanent, kernel-resident registry adapter. No hook may point into
/// unloadable text. `register` returns 0 or a negative errno; `unregister`
/// removes every match `owner` registered and must be idempotent.
#[derive(Debug)]
pub struct Host {
    pub register:
        fn(owner: u64, name: &'static str, m: ModuleUsbMatch, probe: ModuleProbeFn) -> i32,
    pub unregister: fn(owner: u64),
}

static HOST: AtomicUsize = AtomicUsize::new(0);

/// Install the USB registry adapter. One host for the kernel's lifetime:
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

/// Register a module's USB match. Reached from the `narf_register_usb_driver`
/// export. `-EINVAL` for a null probe, `-ENODEV` when this kernel has no USB
/// stack (no host installed), otherwise the host's result.
///
/// # Safety
/// `probe` must be a valid [`ModuleProbeFn`] address that stays mapped for as
/// long as the match is registered (the loader unregisters it before unmap).
pub unsafe fn register_module_usb_driver(
    owner: u64,
    name: &str,
    m: ModuleUsbMatch,
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

/// Remove every USB match owned by one loadable module. The caller runs the
/// module's exit hook first and calls this before unmapping module text.
pub fn unregister_module_usb_drivers(owner: u64) {
    if let Some(host) = host() {
        (host.unregister)(owner);
    }
}

/// Call a module's USB probe through the module subsystem's call gate.
/// `-ENODEV` when no gate is installed: module text never runs without it.
pub fn call_module_usb_probe(owner: u64, probe: ModuleProbeFn, dev_token: u64) -> i32 {
    call_module_probe(owner, probe, dev_token, 0)
}

#[doc(hidden)]
/// Test-only: forget the installed host so a smoke can prove `-ENODEV`.
pub fn __reset_host_for_test() {
    HOST.store(0, Ordering::Release);
}
