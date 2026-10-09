//! PCIe driver-match registry.
//!
//! Each PCIe driver registers a `PciMatch` describing which devices
//! it claims (by exact `(vendor, device)`, by class triple, or by
//! vendor-only) plus a probe function. At boot, a TCB-trusted entry
//! point — `probe_all` — walks `bus::devices()`, finds the first
//! match for each device, mints a `Cap<BusDeviceCap, Write>`, and
//! invokes the probe.
//!
//! This is the bus-level analogue of Linux's `pci_driver` table +
//! `pci_register_driver`. It's distinct from `narf_drivers::Driver`,
//! which models a driver's *lifecycle* (start / quiesce). Match-based
//! probes can either complete synchronously (as the Stage-3 NVMe
//! probe does — bring up the controller and stash it in a static)
//! or hand off to the lifecycle framework.
//!
//! Cap-gating: `probe_all` requires a `Cap<BusRegistryCap, Grant>` —
//! the same authority `claim_device_cap` consults — because issuing
//! probes is the registry-wide action of binding drivers to
//! hardware. Individual probe entries don't need a cap to register
//! (they're statically declared by trusted in-tree drivers); they
//! receive a `Cap<BusDeviceCap, Write>` minted on their behalf.

use alloc::vec::Vec;

use narf_capabilities::{Cap, Grant, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::device::{BusDevice, BusKind};
use crate::registry::{claim_device_cap, devices, BusDeviceCap, BusRegistryCap};

/// Why a probe failed. Drivers return this from their probe fn so
/// `probe_all` can log + continue with the next device, rather than
/// aborting the whole bus walk.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// Driver couldn't allocate memory needed to bring up the device.
    NoMemory,
    /// Device's cfg-space / BAR layout disagrees with what the driver
    /// expected (firmware bug, wrong device ID, etc.).
    BadDevice,
    /// Class-match backstops (e.g. amdgpu's `MatchKind::Class { 0x03 }`
    /// catching every PCI VGA controller) need to bail when the
    /// vendor / device specifics don't actually fit them. Returning
    /// this instead of `BadDevice` keeps the probe trace clean —
    /// `probe_log` skips this variant so a real-HW boot doesn't get
    /// flooded with `BadDevice` lines for every cross-vendor class
    /// match. Not a failure in any meaningful sense; a more
    /// specific match should pick the device up.
    NotForThisDriver,
    /// Generic free-form error message — useful when a probe wants to
    /// surface a one-line reason without a typed variant.
    Other(&'static str),
}

/// Predicate against a `BusDevice`. A `PciMatch` carries one of these
/// plus the probe fn that gets called when the predicate fires.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MatchKind {
    /// Exact `(vendor, device)` pair. Highest specificity — wins over
    /// `Class` / `Vendor` matches when a device matches multiple
    /// entries.
    VendorDevice { vendor: u16, device: u16 },
    /// PCIe base-class match. `class` is the high byte of the class
    /// triple (offset 0x0B); `mask` lets a driver match a class
    /// family (e.g. `class=0x01, mask=0xFF` = "all storage").
    Class { class: u8, mask: u8 },
    /// PCIe full class-triple match — `(class, subclass, prog_if)`
    /// pinned exactly. More specific than `Class` because virtio-blk
    /// (01:00:00), AHCI (01:06:01), and NVMe (01:08:02) all share
    /// `class == 0x01` but have to be distinguished by the lower
    /// bytes. Drivers that previously had to filter inside `probe`
    /// can use this to filter at match time, so the probe-trace
    /// no longer logs spurious `BadDevice` errors for devices the
    /// driver was never going to claim.
    ClassFull {
        class: u8,
        subclass: u8,
        prog_if: u8,
    },
    /// Match every device of a vendor. Lowest specificity.
    Vendor { vendor: u16 },
}

impl MatchKind {
    /// `true` iff `device` matches this kind.
    pub fn matches(&self, device: &BusDevice) -> bool {
        // Match-based dispatch only makes sense for PCIe devices —
        // virtio-mmio uses its own discovery shape.
        if !matches!(device.kind, BusKind::Pcie { .. }) {
            return false;
        }
        match *self {
            MatchKind::VendorDevice {
                vendor,
                device: dev,
            } => device.id.vendor == vendor && device.id.device == dev,
            MatchKind::Class { class, mask } => {
                let dev_class = ((device.id.class >> 16) & 0xFF) as u8;
                (dev_class & mask) == (class & mask)
            }
            MatchKind::ClassFull {
                class,
                subclass,
                prog_if,
            } => {
                let dev_class = ((device.id.class >> 16) & 0xFF) as u8;
                let dev_subclass = ((device.id.class >> 8) & 0xFF) as u8;
                let dev_prog_if = (device.id.class & 0xFF) as u8;
                dev_class == class && dev_subclass == subclass && dev_prog_if == prog_if
            }
            MatchKind::Vendor { vendor } => device.id.vendor == vendor,
        }
    }

    /// Specificity rank — higher means "more specific." Used by
    /// `probe_all` to break ties when a device matches multiple
    /// entries; the more specific one wins.
    pub fn specificity(&self) -> u8 {
        match self {
            MatchKind::VendorDevice { .. } => 3,
            // Full class triple beats base-class-only.
            MatchKind::ClassFull { .. } => 2,
            MatchKind::Class { .. } => 1,
            MatchKind::Vendor { .. } => 0,
        }
    }
}

/// Driver probe signature. The driver receives the discovered device
/// and a freshly-minted authority cap, and returns success / a typed
/// error. The cap is owned by the probe — it can stash it in a
/// static, hand it to a long-lived task, etc.
pub type PciProbeFn =
    fn(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError>;

/// One entry in the driver-match registry.
#[derive(Copy, Clone)]
pub struct PciMatch {
    /// Human-readable driver name. Used in diagnostics + as a
    /// duplicate-registration key.
    pub name: &'static str,
    /// Predicate against discovered devices.
    pub kind: MatchKind,
    /// Probe fn invoked when a matching device is discovered.
    pub probe: PciProbeFn,
}

impl core::fmt::Debug for PciMatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PciMatch")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Backing store for registered drivers. Wave-3a single global
/// list — registration is a boot-time event, so a `IrqSafeSpinLock`
/// is fine.
static REGISTRY: IrqSafeSpinLock<Vec<PciMatch>> = IrqSafeSpinLock::new(Vec::new());

/// Register a driver with the match table. Idempotent on
/// `(name, kind)` — re-registering the same predicate replaces the
/// prior entry, so the test harness can drive multiple smokes that
/// re-add the same driver without leaking entries. Drivers like
/// k10temp that push multiple (vendor, device) entries under one
/// name retain all of them because the kind differs.
pub fn register(m: PciMatch) {
    let mut g = REGISTRY.lock();
    if let Some(pos) = g.iter().position(|e| e.name == m.name && e.kind == m.kind) {
        g[pos] = m;
    } else {
        g.push(m);
    }
}

/// Snapshot of currently-registered drivers. The bus crate clones
/// out of the lock so callers can iterate without holding it.
pub fn registered() -> Vec<PciMatch> {
    REGISTRY.lock().clone()
}

/// Number of registered drivers — handy for tests + diagnostics.
pub fn count() -> usize {
    REGISTRY.lock().len()
}

/// Walk every device in the bus registry, find the highest-specificity
/// matching `PciMatch`, mint a `Cap<BusDeviceCap, Write>`, and invoke
/// the probe. Returns the count of probes that returned `Ok(())`.
///
/// Probes that error are logged via `log_probe_failure` (Wave 3a stub)
/// and the walk continues. A device with no matching driver is
/// silently skipped — drivers can be loaded later, and a re-run of
/// `probe_all` will pick it up.
pub fn probe_all(
    authority: &Cap<BusRegistryCap, Grant>,
) -> Result<u32, narf_capabilities::CapError> {
    authority.check_live()?;
    let drivers = registered();
    let devs = devices();
    let mut bound = 0u32;

    for d in &devs {
        // Find the most specific matching driver.
        let mut best: Option<&PciMatch> = None;
        for m in &drivers {
            if m.kind.matches(d) {
                best = Some(match best {
                    None => m,
                    Some(prev) if m.kind.specificity() > prev.kind.specificity() => m,
                    Some(prev) => prev,
                });
            }
        }
        let Some(m) = best else {
            continue;
        };

        // Mint the per-device cap. We're inside a TCB-trusted
        // entry point (probe_all itself is cap-gated), so calling
        // claim_device_cap with our authority is the canonical
        // path.
        let (_handle, cap) = match claim_device_cap(authority, d.addr) {
            Ok(ok) => ok,
            Err(e) => {
                let _ = e;
                continue;
            }
        };
        // Per-device probe trace through the optional `LogHook`.
        // Off by default; the kernel-test runner / bring-up
        // path enables it via `set_probe_log` to localise hangs
        // inside an individual driver's probe.
        let _name = m.name;
        let _vid = d.id.vendor;
        let _did = d.id.device;
        if PROBE_LOG.load(core::sync::atomic::Ordering::Acquire) {
            probe_log(_name, _vid, _did, /*pre=*/ true, None);
        }
        let result = (m.probe)(*d, cap);
        if PROBE_LOG.load(core::sync::atomic::Ordering::Acquire) {
            // NotForThisDriver = class-backstop saw a device the
            // driver isn't responsible for. Suppress the post-call
            // log line so the trace stays useful on real HW where
            // every VGA / NIC / class-matched device would otherwise
            // emit a `BadDevice`-flavour line per backstop.
            if !matches!(result, Err(ProbeError::NotForThisDriver)) {
                let err_dbg: Option<ProbeError> = result.err();
                probe_log(_name, _vid, _did, /*pre=*/ false, err_dbg);
            }
        }
        match result {
            Ok(()) => bound += 1,
            Err(e) => log_probe_failure(m, d, e),
        }
    }
    Ok(bound)
}

// ── Per-probe trace (verbose-mode boot diagnostic) ───────────────

use core::sync::atomic::AtomicBool;

/// Optional log hook for emitting "probe: <name> [VVVV:DDDD] ..."
/// breadcrumbs. Wired up by the bring-up path (frame::bare_main)
/// when verbose tracing is on.
pub type ProbeLogHook = fn(&str);
static PROBE_LOG_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static PROBE_LOG: AtomicBool = AtomicBool::new(false);

pub fn set_probe_log_hook(h: ProbeLogHook) {
    PROBE_LOG_HOOK.store(h as usize, core::sync::atomic::Ordering::Release);
}

pub fn set_probe_log(on: bool) {
    PROBE_LOG.store(on, core::sync::atomic::Ordering::Release);
}

fn probe_log(name: &str, vid: u16, did: u16, pre: bool, err: Option<ProbeError>) {
    let h = PROBE_LOG_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if h == 0 {
        return;
    }
    // SAFETY: `h` was stored as `ProbeLogHook as usize` via
    // `set_probe_log_hook`.
    // SAFETY: Valid memory or trusted environment
    let f: ProbeLogHook = unsafe { core::mem::transmute(h) };
    let mut buf = [0u8; 256];
    let mut w = TruncatingWriter::new(&mut buf);
    use core::fmt::Write;
    if pre {
        let _ = write!(&mut w, "probe: {} [{:04x}:{:04x}] ...", name, vid, did);
    } else {
        match err {
            None => {
                let _ = write!(&mut w, "probe: {} [{:04x}:{:04x}] -> ok", name, vid, did);
            }
            Some(e) => {
                let _ = write!(
                    &mut w,
                    "probe: {} [{:04x}:{:04x}] -> err: {:?}",
                    name, vid, did, e
                );
            }
        }
    }
    f(w.as_str());
}

struct TruncatingWriter<'a> {
    buf: &'a mut [u8],
    cur: usize,
}
impl<'a> TruncatingWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, cur: 0 }
    }
    fn as_str(&self) -> &str {
        // SAFETY: `cur` only advances over written ASCII via
        // `write_str`, which performs UTF-8 validation.
        // SAFETY: Valid memory or trusted environment
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.cur]) }
    }
}
impl<'a> core::fmt::Write for TruncatingWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let room = self.buf.len().saturating_sub(self.cur);
        let n = room.min(bytes.len());
        self.buf[self.cur..self.cur + n].copy_from_slice(&bytes[..n]);
        self.cur += n;
        Ok(())
    }
}

/// Probe-failure observability hook. Wave-3a stub: drops the
/// failure on the floor (the kernel-test harness can call into the
/// per-driver static state to verify success). Wave-3b can route
/// this through `tracing/` once the trace probe IDs land.
fn log_probe_failure(_m: &PciMatch, _d: &BusDevice, _e: ProbeError) {}

// ── Loadable-module PCI drivers ──────────────────────────────────
//
// A driver built as a `.ko` cannot be handed a `PciProbeFn`: its probe is a
// separately-compiled C-ABI thunk, and `BusDevice` / `Cap` are `repr(Rust)`
// and cannot cross an ABI boundary. So a module registers through
// `register_module_pci_driver` (reached from the kernel-ABI export
// `narf_register_pci_driver`), which records the thunk in a side table keyed
// by `(vendor, device)` and installs ONE shared `PciProbeFn` —
// `module_probe_trampoline` — against the match. At probe time the trampoline
// looks the thunk back up by the discovered device's IDs and calls it with a
// stable device token. The in-tree `PciMatch` probe path above is untouched.

/// C-ABI probe thunk a loadable module supplies. `dev_token` encodes the
/// device's bus address (see [`addr_token`]); `reserved` is 0 today and will
/// carry a device-authority handle once the datapath ABI lands. A `0` return
/// means the module bound the device; a negative errno means it did not.
pub type ModuleProbeFn = extern "C" fn(dev_token: u64, reserved: u64) -> i32;

struct ModuleThunk {
    vendor: u16,
    device: u16,
    thunk: ModuleProbeFn,
}

static MODULE_THUNKS: IrqSafeSpinLock<Vec<ModuleThunk>> = IrqSafeSpinLock::new(Vec::new());

/// Kernel-owned intern table for module-supplied driver names. A module's
/// `.rodata` is unmapped on unload, so a `&str` borrowed from it cannot be
/// stored `'static` in the registry; interning copies it into a kernel-owned
/// allocation that outlives the module. Dedups so repeated registrations of
/// the same name don't grow the table without bound.
static INTERNED_NAMES: IrqSafeSpinLock<Vec<&'static str>> = IrqSafeSpinLock::new(Vec::new());

fn intern_name(name: &str) -> &'static str {
    let mut g = INTERNED_NAMES.lock();
    if let Some(found) = g.iter().copied().find(|n| *n == name) {
        return found;
    }
    let leaked: &'static str = alloc::string::String::from(name).leak();
    g.push(leaked);
    leaked
}

/// Encode a bus address into a stable 64-bit device token for the module ABI.
/// PCIe packs segment/bus/device/function; MMIO passes its physical base.
/// Opaque to the module today.
fn addr_token(addr: crate::addr::BusAddr) -> u64 {
    match addr {
        crate::addr::BusAddr::Pcie(a) => {
            ((a.segment as u64) << 24)
                | ((a.bus as u64) << 16)
                | ((a.device as u64) << 8)
                | (a.function as u64)
        }
        crate::addr::BusAddr::Mmio(p) => p.raw(),
    }
}

/// The single `PciProbeFn` installed for every module-registered match.
/// Dispatches to the module's thunk by the discovered device's IDs.
fn module_probe_trampoline(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), ProbeError> {
    let (vid, did) = (device.id.vendor, device.id.device);
    let thunk = MODULE_THUNKS
        .lock()
        .iter()
        .find(|t| t.vendor == vid && t.device == did)
        .map(|t| t.thunk);
    match thunk {
        // 0 => the module bound the device. A negative errno => it declined;
        // surfaced as a typed error so the probe trace records it without a
        // more-specific driver being implied.
        Some(f) => match f(addr_token(device.addr), 0) {
            0 => Ok(()),
            _ => Err(ProbeError::Other("module probe declined")),
        },
        None => Err(ProbeError::NotForThisDriver),
    }
}

/// Register a PCI driver supplied by a loadable module. Reached from the
/// `narf_register_pci_driver` kernel-ABI export. `probe` is a [`ModuleProbeFn`]
/// passed as a raw address. Returns 0, or `-EINVAL` for a null probe.
///
/// # Safety
/// `probe` must be a valid [`ModuleProbeFn`] pointer that stays mapped for as
/// long as the match is registered.
pub unsafe fn register_module_pci_driver(
    name: &str,
    vendor: u16,
    device: u16,
    probe: usize,
) -> i32 {
    if probe == 0 {
        return -22; // -EINVAL
    }
    // SAFETY: the caller promises `probe` is a valid `ModuleProbeFn` address;
    // mirrors the `set_probe_log_hook` round-trip in this file.
    let thunk: ModuleProbeFn = unsafe { core::mem::transmute(probe) };
    let name = intern_name(name);
    {
        // Dedup on `(vendor, device)` so a re-registration replaces the thunk
        // rather than growing the table (mirrors `register`'s idempotency).
        let mut g = MODULE_THUNKS.lock();
        if let Some(pos) = g
            .iter()
            .position(|t| t.vendor == vendor && t.device == device)
        {
            g[pos].thunk = thunk;
        } else {
            g.push(ModuleThunk {
                vendor,
                device,
                thunk,
            });
        }
    }
    register(PciMatch {
        name,
        kind: MatchKind::VendorDevice { vendor, device },
        probe: module_probe_trampoline,
    });
    0
}

#[doc(hidden)]
/// Test-only: look up a module-registered thunk, so a smoke can confirm the
/// registration round-trip reaches the module's probe.
pub fn __module_thunk_for_test(vendor: u16, device: u16) -> Option<ModuleProbeFn> {
    MODULE_THUNKS
        .lock()
        .iter()
        .find(|t| t.vendor == vendor && t.device == device)
        .map(|t| t.thunk)
}

#[doc(hidden)]
/// Test-only: reset the registry between smokes. Keeps tests
/// hermetic without exposing a public clear path.
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
    MODULE_THUNKS.lock().clear();
    INTERNED_NAMES.lock().clear();
}
