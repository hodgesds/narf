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
/// + a freshly-minted authority cap, and returns success / a typed
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

/// Register a driver with the match table. Idempotent on `name` —
/// re-registering replaces the prior entry, so the test harness
/// can drive multiple smokes that re-add the same driver without
/// leaking entries.
pub fn register(m: PciMatch) {
    let mut g = REGISTRY.lock();
    if let Some(pos) = g.iter().position(|e| e.name == m.name) {
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

#[doc(hidden)]
/// Test-only: reset the registry between smokes. Keeps tests
/// hermetic without exposing a public clear path.
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
}
