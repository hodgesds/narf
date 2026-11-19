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
//!
//! Once a probe accepts a device, the module drives it through the
//! [`Datapath`] hooks below (URB-style control/bulk/interrupt requests and a
//! module-backed serial node), which the same USB stack installs.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::driver_match::{call_module_probe, intern_name, ModuleCallbackFn, ModuleProbeFn};

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

// ── Transfer datapath (URB-style submit / poll / cancel) ────────────
//
// A module's USB probe runs inside the async attach cascade, and module
// text cannot produce or await a `Future`. So every transfer is a
// kernel-owned request ("URB"): the module submits it and gets an opaque,
// never-reused id; the USB stack runs the transfer in its own tasks; when
// the request reaches a terminal state the kernel optionally calls the
// module's completion callback (task context, through the module callback
// gate); the module collects the result with `poll`. The module never sees
// a `USBDevice`, a DMA page or a kernel pointer, and every transfer buffer
// is kernel memory: an unloaded module's text and data are never a DMA
// target.

/// Largest single transfer or control data stage. One xHCI endpoint page.
pub const MAX_TRANSFER: usize = 4096;
/// Largest configuration descriptor copied to a module.
pub const MAX_CONFIG_DESCRIPTOR: usize = 4096;
/// Most endpoints one `configure` request may name (DCI 2..=31).
pub const MAX_CONFIGURE_ENDPOINTS: usize = 30;

/// Optional task-context completion notification. The callback is module
/// text and only ever runs through [`call_module_usb_callback`].
#[derive(Copy, Clone, Debug)]
pub struct Completion {
    /// `extern "C" fn(cookie) -> i32`; the return value is ignored.
    pub callback: Option<ModuleCallbackFn>,
    pub cookie: u64,
}

/// `(owner, token, setup, data, done)` → request id. See [`control`].
pub type ControlHook =
    fn(owner: u64, token: u64, setup: [u8; 8], data: &[u8], done: Completion) -> Result<u64, i32>;

/// `(owner, token, endpoint, data, len, done)` → request id. See [`transfer`].
pub type TransferHook = fn(
    owner: u64,
    token: u64,
    endpoint: u8,
    data: &[u8],
    len: usize,
    done: Completion,
) -> Result<u64, i32>;

/// Permanent, kernel-resident datapath hooks, installed by the USB stack.
/// Every hook re-validates `(owner, token)` against a context the stack
/// minted for that module's probe; a forged or stale token is `-ENODEV`.
/// `poll` returns `(status, length)`: `-EAGAIN` pending, `-ENOBUFS` with the
/// required length (the result is retained), otherwise the terminal status,
/// after which the request id is consumed.
#[derive(Debug)]
pub struct Datapath {
    /// `(0, len)` after copying, or `(-ENOBUFS, required_len)`.
    pub config_descriptor: fn(owner: u64, token: u64, out: &mut [u8]) -> (i32, usize),
    pub configure:
        fn(owner: u64, token: u64, endpoints: &[u8], done: Completion) -> Result<u64, i32>,
    pub control: ControlHook,
    pub transfer: TransferHook,
    pub poll: fn(owner: u64, token: u64, urb: u64, out: &mut [u8]) -> (i32, usize),
    pub cancel: fn(owner: u64, token: u64, urb: u64) -> i32,
    pub serial_register:
        fn(owner: u64, token: u64, family: u32, kick: Completion) -> Result<u32, i32>,
    pub serial_tx: fn(owner: u64, token: u64, port: u32, out: &mut [u8]) -> Result<usize, i32>,
    pub serial_rx: fn(owner: u64, token: u64, port: u32, data: &[u8]) -> Result<usize, i32>,
    /// Poll one callback-less bulk/interrupt request inline until it is
    /// terminal (0, then collect it with `poll`) or `timeout_ns` passes.
    pub wait: fn(owner: u64, token: u64, urb: u64, timeout_ns: u64) -> i32,
    /// Whether `owner` holds a live context for `token`.
    pub context_live: fn(owner: u64, token: u64) -> bool,
}

static DATAPATH: AtomicUsize = AtomicUsize::new(0);

/// Install the USB stack's datapath hooks. Same one-host rule as
/// [`register`]: the same table is a no-op success, a different one `-EBUSY`.
pub fn register_datapath(datapath: &'static Datapath) -> Result<(), i32> {
    let new = datapath as *const Datapath as usize;
    match DATAPATH.compare_exchange(0, new, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(old) if old == new => Ok(()),
        Err(_) => Err(-16),
    }
}

fn datapath() -> Result<&'static Datapath, i32> {
    let raw = DATAPATH.load(Ordering::Acquire);
    if raw == 0 {
        return Err(-19);
    }
    // SAFETY: only `register_datapath` stores here, and it stores a
    // `&'static Datapath`.
    Ok(unsafe { &*(raw as *const Datapath) })
}

/// Copy the configuration descriptor the device was probed with:
/// `(0, len)`, or `(-ENOBUFS, required_len)` with nothing copied.
pub fn config_descriptor(owner: u64, token: u64, out: &mut [u8]) -> (i32, usize) {
    match datapath() {
        Ok(d) => (d.config_descriptor)(owner, token, out),
        Err(e) => (e, 0),
    }
}

/// Request xHCI endpoint configuration for endpoint addresses taken from
/// the probed configuration descriptor. Attributes come from that
/// descriptor, never from the module.
pub fn configure(owner: u64, token: u64, endpoints: &[u8], done: Completion) -> Result<u64, i32> {
    if endpoints.is_empty() || endpoints.len() > MAX_CONFIGURE_ENDPOINTS {
        return Err(-22);
    }
    (datapath()?.configure)(owner, token, endpoints, done)
}

/// Submit one control transfer on EP0. Direction comes from bit 7 of
/// `bmRequestType`; an OUT data stage is copied before this returns.
pub fn control(
    owner: u64,
    token: u64,
    setup: [u8; 8],
    data: &[u8],
    done: Completion,
) -> Result<u64, i32> {
    if data.len() > MAX_TRANSFER {
        return Err(-22);
    }
    (datapath()?.control)(owner, token, setup, data, done)
}

/// Submit one bulk or interrupt transfer on a configured endpoint. For IN
/// endpoints `len` is the receive capacity and `data` is empty; for OUT
/// endpoints `data` is copied before this returns.
pub fn transfer(
    owner: u64,
    token: u64,
    endpoint: u8,
    data: &[u8],
    len: usize,
    done: Completion,
) -> Result<u64, i32> {
    if endpoint & 0x0f == 0 || len == 0 || len > MAX_TRANSFER {
        return Err(-22);
    }
    (datapath()?.transfer)(owner, token, endpoint, data, len, done)
}

/// Poll one request; see [`Datapath`] for the status contract.
pub fn poll(owner: u64, token: u64, urb: u64, out: &mut [u8]) -> (i32, usize) {
    match datapath() {
        Ok(d) => (d.poll)(owner, token, urb, out),
        Err(e) => (e, 0),
    }
}

/// Request cancellation. The request stays pollable until it is terminal.
pub fn cancel(owner: u64, token: u64, urb: u64) -> i32 {
    match datapath() {
        Ok(d) => (d.cancel)(owner, token, urb),
        Err(e) => e,
    }
}

/// Publish a `/dev/ttyUSB<N>` node backed by this module device. `kick`
/// runs (task context, module gate) whenever a writer queues bytes.
pub fn serial_register(owner: u64, token: u64, family: u32, kick: Completion) -> Result<u32, i32> {
    (datapath()?.serial_register)(owner, token, family, kick)
}

/// Take queued TX bytes written to the module's serial node.
pub fn serial_tx(owner: u64, token: u64, port: u32, out: &mut [u8]) -> Result<usize, i32> {
    (datapath()?.serial_tx)(owner, token, port, out)
}

/// Deliver received bytes to readers of the module's serial node.
pub fn serial_rx(owner: u64, token: u64, port: u32, data: &[u8]) -> Result<usize, i32> {
    if data.len() > MAX_TRANSFER {
        return Err(-22);
    }
    (datapath()?.serial_rx)(owner, token, port, data)
}

/// Wait for one request submitted without a completion callback by
/// polling it inline, so the wait never depends on another task being
/// scheduled. 0 once it is terminal (collect it with [`poll`]); `-ETIMEDOUT`;
/// `-EINVAL` for an unknown request, one with a callback, or a timeout
/// outside 1 ns..=1 s; `-EOPNOTSUPP` for control/configure requests, which
/// complete in kernel tasks and are collected through their callback.
pub fn wait(owner: u64, token: u64, urb: u64, timeout_ns: u64) -> i32 {
    if timeout_ns == 0 || timeout_ns > 1_000_000_000 {
        return -22;
    }
    match datapath() {
        Ok(d) => (d.wait)(owner, token, urb, timeout_ns),
        Err(e) => e,
    }
}

/// Whether `owner` holds a live USB context for `token`. Subsystem sinks
/// outside the USB stack (module block disks) gate registration on it.
pub fn context_live(owner: u64, token: u64) -> bool {
    datapath().is_ok_and(|d| (d.context_live)(owner, token))
}

/// Run a module completion/kick callback through the module callback gate
/// (pins the module Live, enters its effective domain). `-ENODEV` without a
/// gate or once the module is no longer Live: module text never runs then.
pub fn call_module_usb_callback(owner: u64, callback: ModuleCallbackFn, cookie: u64) -> i32 {
    crate::driver_match::call_module_callback(owner, callback, cookie)
}

#[doc(hidden)]
/// Test-only: forget the installed datapath so a smoke can prove `-ENODEV`.
pub fn __reset_datapath_for_test() {
    DATAPATH.store(0, Ordering::Release);
}
