//! PCIe driver-match registry.
//!
//! Each PCIe driver registers a `PciMatch` describing which devices
//! it claims (by exact `(vendor, device)`, by class triple, or by
//! vendor-only) plus a probe function. At boot, a TCB-trusted entry
//! point — `probe_all` — walks `bus::devices()`, orders each
//! device's matches by specificity, mints a `Cap<BusDeviceCap,
//! Write>` per attempt, and invokes the probes in order until one
//! binds the device or the candidates run out.
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

use narf_capabilities::{Cap, CapError, CapOp, Grant, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::addr::BusAddr;
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
    /// match. Not a failure in any meaningful sense: the dispatcher
    /// returns the device to the candidate list and attempts the
    /// next-most-specific match (bus spec §9.3).
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

/// Driver remove signature — the detach counterpart of
/// [`PciProbeFn`]. The driver receives the device it bound at probe
/// time and a freshly-minted authority cap, and tears the device
/// down (stop hardware, withdraw publications, release DMA). Removal
/// is best-effort and cannot fail: the device may already be gone,
/// which is precisely when this runs. Linux `pci_driver::remove`.
pub type PciRemoveFn = fn(device: BusDevice, cap: Cap<BusDeviceCap, Write>);

/// Remove hooks, keyed by the registering match's `name` (the same
/// key `register` idempotency uses). A companion registry rather
/// than a field on [`PciMatch`]: the match struct is constructed at
/// ~90 in-tree sites, and a remove hook is the rare exception — only
/// drivers with real teardown register one. A driver with several
/// match entries (e.g. NVMe's per-SKU ids plus its class backstop)
/// registers the same hook under each of its names.
static REMOVE_FNS: IrqSafeSpinLock<Vec<(&'static str, PciRemoveFn)>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register (or replace) the remove hook for match `name`.
pub fn register_remove(name: &'static str, remove: PciRemoveFn) {
    let mut g = REMOVE_FNS.lock();
    if let Some(pos) = g.iter().position(|e| e.0 == name) {
        g[pos] = (name, remove);
    } else {
        g.push((name, remove));
    }
}

/// One device a successful probe bound: the device as discovered
/// plus the name of the match that claimed it. Recorded by
/// `probe_all` so a later detach can route the remove hook to the
/// driver that owns the device — the bound-driver record the
/// hot-plug dispatcher clears on Detach (bus spec §9.6).
struct BoundDevice {
    device: BusDevice,
    name: &'static str,
}

static BOUND: IrqSafeSpinLock<Vec<BoundDevice>> = IrqSafeSpinLock::new(Vec::new());

fn record_binding(device: BusDevice, name: &'static str) {
    let mut g = BOUND.lock();
    if let Some(pos) = g.iter().position(|b| b.device.addr == device.addr) {
        g[pos] = BoundDevice { device, name };
    } else {
        g.push(BoundDevice { device, name });
    }
}

/// Number of devices currently recorded as bound — tests +
/// diagnostics.
pub fn bound_count() -> usize {
    BOUND.lock().len()
}

/// Detach the device at `addr`: drop its binding record and, when
/// the driver that bound it registered a remove hook, invoke the
/// hook with a freshly minted `Cap<BusDeviceCap, Write>` (the same
/// mint `probe_all` performs). Returns `true` when a binding was
/// dropped. A device whose driver registered no hook is simply
/// unbound — module-owned devices keep their own context teardown,
/// and hookless drivers have nothing to release. When the registry
/// no longer offers the device (its record is already gone), the
/// binding is still dropped but the hook cannot be minted a cap and
/// does not run; enumeration removes a device from the registry
/// only after detaching it, so the production hot-plug path always
/// mints.
///
/// Cap-gated on the registry authority, like `probe_all`: unbinding
/// drivers from hardware is a registry-wide action.
pub fn detach(authority: &Cap<BusRegistryCap, Grant>, addr: BusAddr) -> Result<bool, CapError> {
    authority.check_live()?;
    let bound = {
        let mut g = BOUND.lock();
        g.iter()
            .position(|b| b.device.addr == addr)
            .map(|pos| g.remove(pos))
    };
    let Some(bound) = bound else {
        return Ok(false);
    };
    let remove = REMOVE_FNS
        .lock()
        .iter()
        .find(|e| e.0 == bound.name)
        .map(|e| e.1);
    if let Some(remove) = remove {
        if let Ok((_handle, cap)) = claim_device_cap(authority, addr) {
            remove(bound.device, cap);
        }
    }
    Ok(true)
}

/// Walk every device in the bus registry and bind a driver to it.
///
/// For each device, the matching `PciMatch` entries form a
/// candidate list ordered by specificity — highest first,
/// registration order breaking ties (bus spec §9.2). Candidates
/// are attempted in order, each with a freshly minted
/// `Cap<BusDeviceCap, Write>`: a probe returning `Ok(())` binds
/// the device; a probe returning `Err(ProbeError::NotForThisDriver)`
/// declines it, and the next-most-specific candidate is attempted
/// (bus spec §9.3); any other error is logged via
/// `log_probe_failure` (Wave 3a stub) and ends the attempts for
/// that device — the driver engaged the hardware and failed, so
/// handing the same device to a second driver in the same walk
/// is not arbitrated (bus spec §9.3). Returns the count of
/// devices bound by a successful probe.
///
/// A device with no matching driver is silently skipped —
/// drivers can be loaded later, and a re-run of `probe_all`
/// will pick it up.
///
/// The walk is live with respect to the device registry: a
/// probe may append devices while the walk is running — bridge
/// drivers do this, notably Intel VMD enumerating the functions
/// behind the bridge (issue #933). Devices appended by an
/// earlier probe in the same call are attempted, in registry
/// order, before the call returns (bus spec §9.5). Every
/// device is attempted at most once per call: the registry is
/// append-only during a walk (probes append via
/// `append_devices`; `install` is an enumeration / test-setup
/// operation), so the walked prefix never reorders.
pub fn probe_all(
    authority: &Cap<BusRegistryCap, Grant>,
) -> Result<u32, narf_capabilities::CapError> {
    authority.check_live()?;
    let drivers = registered();
    let mut devs = devices();
    let mut bound = 0u32;

    // Index-based walk over a refreshable snapshot (bus spec
    // §9.5): when the walk catches up with the snapshot it
    // re-reads the registry once, so devices a bridge probe
    // appended mid-walk (Intel VMD children, issue #933) are
    // attempted by this same call instead of waiting for a
    // hot-plug re-run that, at boot, never comes.
    let mut idx = 0usize;
    while idx < devs.len() {
        let d = &devs[idx];
        idx += 1;
        // Candidate matches in arbitration order. `sort_by_key`
        // is stable, so equal-specificity candidates keep their
        // registration order — the pre-existing tie behaviour.
        let mut candidates: Vec<&PciMatch> = drivers.iter().filter(|m| m.kind.matches(d)).collect();
        candidates.sort_by_key(|m| core::cmp::Reverse(m.kind.specificity()));

        for m in candidates {
            // Mint the per-device cap. We're inside a TCB-trusted
            // entry point (probe_all itself is cap-gated), so calling
            // claim_device_cap with our authority is the canonical
            // path. A fresh cap per attempt: a declining probe drops
            // its cap unconsumed, exactly as a failed probe did when
            // only the best match was attempted.
            let (_handle, cap) = match claim_device_cap(authority, d.addr) {
                Ok(ok) => ok,
                Err(e) => {
                    let _ = e;
                    break;
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
                Ok(()) => {
                    record_binding(*d, m.name);
                    bound += 1;
                    break;
                }
                // Declined: return the device to the candidate
                // list and attempt the next-most-specific match.
                Err(ProbeError::NotForThisDriver) => continue,
                Err(e) => {
                    log_probe_failure(m, d, e);
                    break;
                }
            }
        }

        if idx == devs.len() {
            // Caught up with the snapshot: pick up anything the
            // probes above appended before declaring the walk
            // done. The registry is append-only during a walk,
            // so a longer snapshot extends the tail in registry
            // order and the walked prefix is never re-attempted;
            // a same-length one ends the walk, and a shorter one
            // (not reachable today) defensively keeps the
            // snapshot already in hand.
            let fresh = devices();
            if fresh.len() > devs.len() {
                devs = fresh;
            }
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
/// device's bus address (see [`addr_token`]); `reserved` is 0 today. A `0`
/// return means the module bound the device; a negative errno means it did not.
pub type ModuleProbeFn = extern "C" fn(dev_token: u64, reserved: u64) -> i32;

/// Kernel-installed call gate for entering the effective isolation domain of
/// `owner` before invoking module text. `bus` deliberately knows module
/// owners only as opaque ids; the module subsystem owns the id -> domain map.
pub type ModuleProbeCallGate = fn(u64, ModuleProbeFn, u64, u64) -> i32;

/// Synchronous module callback used by the IRQ and timer-poller bridges. The
/// callback itself is never invoked from hard-IRQ context: an in-tree task
/// observes the interrupt/timer and enters module text through the call gate.
pub type ModuleCallbackFn = extern "C" fn(cookie: u64) -> i32;

/// Kernel-installed gate that pins a live module and enters its effective
/// load-time domain before calling a non-probe callback.
pub type ModuleCallbackCallGate = fn(u64, ModuleCallbackFn, u64) -> i32;

/// Module transmit callback. The frame pointer is borrowed only for the
/// duration of the call and names kernel-owned, read-only bytes.
pub type ModuleTxFn = extern "C" fn(frame: *const u8, len: usize) -> i32;

/// Domain/lifecycle gate for network-stack transmit callbacks.
pub type ModuleTxCallGate = fn(u64, ModuleTxFn, &[u8]) -> i32;

static MODULE_PROBE_CALL_GATE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static MODULE_CALLBACK_CALL_GATE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static MODULE_TX_CALL_GATE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Install the module subsystem's probe call gate. Idempotent; boot and test
/// reset paths may publish the same function repeatedly.
pub fn set_module_probe_call_gate(gate: ModuleProbeCallGate) {
    MODULE_PROBE_CALL_GATE.store(gate as usize, core::sync::atomic::Ordering::Release);
}

/// Install the module subsystem's task-context callback gate. Idempotent for
/// the same reason as [`set_module_probe_call_gate`].
pub fn set_module_callback_call_gate(gate: ModuleCallbackCallGate) {
    MODULE_CALLBACK_CALL_GATE.store(gate as usize, core::sync::atomic::Ordering::Release);
}

/// Install the module subsystem's network transmit call gate.
pub fn set_module_tx_call_gate(gate: ModuleTxCallGate) {
    MODULE_TX_CALL_GATE.store(gate as usize, core::sync::atomic::Ordering::Release);
}

fn call_module_probe(owner: u64, thunk: ModuleProbeFn, dev_token: u64, reserved: u64) -> i32 {
    let gate = MODULE_PROBE_CALL_GATE.load(core::sync::atomic::Ordering::Acquire);
    if gate == 0 {
        return -19; // -ENODEV: never execute module text without its gate.
    }
    // SAFETY: only `set_module_probe_call_gate` writes this atomic and it
    // stores exactly a `ModuleProbeCallGate` function address.
    let gate: ModuleProbeCallGate = unsafe { core::mem::transmute(gate) };
    gate(owner, thunk, dev_token, reserved)
}

fn call_module_callback(owner: u64, callback: ModuleCallbackFn, cookie: u64) -> i32 {
    let gate = MODULE_CALLBACK_CALL_GATE.load(core::sync::atomic::Ordering::Acquire);
    if gate == 0 {
        return -19;
    }
    // SAFETY: only `set_module_callback_call_gate` writes this atomic and it
    // stores exactly a `ModuleCallbackCallGate` function address.
    let gate: ModuleCallbackCallGate = unsafe { core::mem::transmute(gate) };
    gate(owner, callback, cookie)
}

fn call_module_tx(owner: u64, callback: ModuleTxFn, frame: &[u8]) -> i32 {
    let gate = MODULE_TX_CALL_GATE.load(core::sync::atomic::Ordering::Acquire);
    if gate == 0 {
        return -19;
    }
    // SAFETY: only `set_module_tx_call_gate` writes this atomic and stores a
    // `ModuleTxCallGate` function address.
    let gate: ModuleTxCallGate = unsafe { core::mem::transmute(gate) };
    gate(owner, callback, frame)
}

struct ModuleThunk {
    owner: u64,
    name: &'static str,
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

// ── Device datapath context (datapath C-ABI, Stages 0–4) ─────────────
//
// For the module's probe to actually DRIVE the device (not just register), the
// kernel keeps the rich objects — the per-device `Cap<BusDeviceCap, Write>` and
// the mapped BAR `MmioRegion`s — and hands the module only opaque `u64`
// handles. Every datapath export (below) looks the context up by the device
// token, re-validates the cap by using it, and performs the hardware op in the
// kernel. The module never holds a kernel pointer or a `repr(Rust)` object.
//
// The context is installed by the trampoline before the module's probe runs
// and removed if the probe declines; on success it persists (the module now
// owns the device) until unload tears it down.
struct DeviceCtx {
    owner: u64,
    token: u64,
    device: BusDevice,
    /// The per-device authority minted for the probe. Held so every datapath
    /// op can go through the cap-gated `bus::pci` / `bus::bar` entry points.
    cap: Cap<BusDeviceCap, Write>,
    /// Mapped BARs; the module refers to them by 1-based handle (index + 1).
    bars: Vec<crate::bar::MmioRegion>,
    /// Coherent DMA buffers retained behind revocable capabilities. Slots stay
    /// stable for the lifetime of the context and are never reused, so a
    /// handle remains stale after free instead of aliasing a later allocation.
    dmabufs: Vec<Option<Cap<narf_io::DmaBuffer, Write>>>,
    /// MSI-X objects remain kernel-owned; modules see only bounded vector
    /// numbers and callback cookies.
    msix: Option<crate::msix::MsixTable>,
    irqs: Vec<ModuleIrq>,
    /// At most one periodic poller per device. A unique id prevents a task
    /// from an old registration from matching a replacement.
    poller: Option<ModulePoller>,
    net_iface: Option<ModuleNetIface>,
    next_callback_id: u64,
    callback_invocations: u64,
    callback_failures: u64,
    net_tx_callbacks: u64,
    net_tx_failures: u64,
    net_rx_frames: u64,
    /// Command-register bits enabled through this context. Teardown clears
    /// them before dropping the device capability.
    enabled_bits: u16,
}

#[derive(Copy, Clone)]
struct ModuleIrq {
    table_idx: u16,
    vector: u8,
    callback: Option<ModuleCallbackFn>,
    cookie: u64,
    callback_id: u64,
}

#[derive(Copy, Clone)]
struct ModulePoller {
    callback: ModuleCallbackFn,
    cookie: u64,
    callback_id: u64,
}

struct ModuleNetIface {
    name: alloc::string::String,
    ifindex: u32,
    tx_callback: ModuleTxFn,
}

const MODULE_IRQ_HANDLER_NAME: &str = "module-msix";

fn module_irq_claim_stub(_cookie: u64) -> narf_interrupts::IrqStatus {
    // Dispatch has already advanced fire_count and woken waiters. Module code
    // is deliberately deferred to a normal executor task.
    narf_interrupts::IrqStatus::Handled
}

struct DeviceOp<F>(F);

impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for DeviceOp<F> {
    type Output = T;

    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

struct DmaOp<F>(F);

impl<F: FnOnce(&narf_io::DmaBuffer) -> T, T> CapOp<narf_io::DmaBuffer, Write> for DmaOp<F> {
    type Output = T;

    fn execute(self, cap: &Cap<narf_io::DmaBuffer, Write>) -> Result<Self::Output, CapError> {
        let buffer = narf_io::resolve(cap.slot().index).ok_or(CapError::Revoked)?;
        Ok((self.0)(&buffer))
    }
}

static DEVICE_CTXS: IrqSafeSpinLock<Vec<DeviceCtx>> = IrqSafeSpinLock::new(Vec::new());

fn install_device_ctx(owner: u64, token: u64, device: BusDevice, cap: Cap<BusDeviceCap, Write>) {
    // A reprobe replaces the old ownership record only after disabling the
    // command bits it enabled.
    remove_device_ctx(token);
    let mut g = DEVICE_CTXS.lock();
    g.push(DeviceCtx {
        owner,
        token,
        device,
        cap,
        bars: Vec::new(),
        dmabufs: Vec::new(),
        msix: None,
        irqs: Vec::new(),
        poller: None,
        net_iface: None,
        next_callback_id: 1,
        callback_invocations: 0,
        callback_failures: 0,
        net_tx_callbacks: 0,
        net_tx_failures: 0,
        net_rx_frames: 0,
        enabled_bits: 0,
    });
}

fn remove_device_ctx(token: u64) {
    let removed = {
        let mut g = DEVICE_CTXS.lock();
        g.iter()
            .position(|c| c.token == token)
            .map(|idx| g.remove(idx))
    };
    if let Some(ctx) = removed {
        teardown_device_ctx(ctx);
    }
}

fn teardown_device_ctx(mut ctx: DeviceCtx) {
    if let Some(iface) = ctx.net_iface.take() {
        let _ = narf_net::iface::unregister(&iface.name);
    }
    // Stop new MSI-X delivery before detaching handlers. The module lifecycle
    // gate has already rejected new callbacks when unload reaches here.
    if let Some(msix) = ctx.msix.as_mut() {
        for irq in &ctx.irqs {
            // SAFETY: this context exclusively owns the table and the index
            // was allocated from this exact table.
            let _ = unsafe { msix.mask_vector(irq.table_idx) };
        }
        // SAFETY: same exclusive config-space ownership; every allocated
        // entry was function-masked above.
        unsafe { msix.disable() };
    }
    if ctx.enabled_bits != 0 {
        // Best effort: a revoked cap already prevents further access, which
        // is precisely when clearing config space is no longer possible.
        let _ = ctx.cap.invoke(DeviceOp(|| {
            crate::pci::clear_command(&ctx.cap, &ctx.device, ctx.enabled_bits)
        }));
    }
    for irq in &ctx.irqs {
        narf_interrupts::disable_irq(irq.vector);
        let _ = narf_interrupts::remove_handler(irq.vector, MODULE_IRQ_HANDLER_NAME, ctx.token);
        narf_interrupts::synchronize_irq(irq.vector);
        let _ = narf_interrupts::vector::free(irq.vector);
    }
    // Bus mastering and MSI-X are off before backing frames are returned.
    // Full DMA-ring teardown must additionally drain device-owned descriptors
    // once a module begins submitting them to hardware.
    for cap in ctx.dmabufs.iter().flatten().copied() {
        narf_io::unregister(cap);
    }
    // Epoch revocation invalidates every copied token retained after this
    // device context is removed.
    ctx.cap.revoke();
}

/// Enable PCI command bits (e.g. MEM_SPACE | BUS_MASTER) on a module-owned
/// device. Reached from the `narf_pci_enable` kernel-ABI export. Returns 0, or
/// a negative errno. The op is cap-gated through the context's device cap.
pub fn module_pci_enable(owner: u64, token: u64, bits: u16) -> i32 {
    let mut g = DEVICE_CTXS.lock();
    let Some(ctx) = g.iter_mut().find(|c| c.owner == owner && c.token == token) else {
        return -19; // -ENODEV
    };
    match ctx.cap.invoke(DeviceOp(|| {
        crate::pci::set_command(&ctx.cap, &ctx.device, bits)
    })) {
        Ok(Ok(_)) => {
            ctx.enabled_bits |= bits;
            0
        }
        _ => -5, // -EIO
    }
}

/// Map a BAR of a module-owned device and return a 1-based handle (0 = fail).
/// Reached from `narf_bar_map`.
pub fn module_bar_map(owner: u64, token: u64, idx: u8) -> u64 {
    // Resolve the device under the lock, then map OUTSIDE it (ioremap may take
    // other locks / allocate page tables).
    let (device, cap) = {
        let g = DEVICE_CTXS.lock();
        match g.iter().find(|c| c.owner == owner && c.token == token) {
            Some(c) => (c.device, c.cap),
            None => return 0,
        }
    };
    // SAFETY: the module owns this device — its live `Cap<BusDeviceCap, Write>`
    // is held in the context, giving the exclusive cfg-space ownership
    // `map_bar` requires.
    let region = match cap.invoke(DeviceOp(|| {
        // SAFETY: the live device cap gates the exclusive cfg-space ownership
        // required by `map_bar`.
        unsafe { crate::bar::map_bar(&device, idx) }
    })) {
        Ok(Ok(region)) => region,
        _ => return 0,
    };
    let mut g = DEVICE_CTXS.lock();
    match g.iter_mut().find(|c| c.owner == owner && c.token == token) {
        Some(c) => {
            c.bars.push(region);
            c.bars.len() as u64
        }
        None => 0,
    }
}

fn with_bar<R>(
    owner: u64,
    token: u64,
    handle: u64,
    f: impl FnOnce(&crate::bar::MmioRegion) -> R,
) -> Option<R> {
    let (cap, region) = {
        let g = DEVICE_CTXS.lock();
        let ctx = g.iter().find(|c| c.owner == owner && c.token == token)?;
        let idx = handle.checked_sub(1)? as usize;
        (ctx.cap, *ctx.bars.get(idx)?)
    };
    cap.invoke(DeviceOp(|| f(&region))).ok()
}

/// Read a 32-bit device register from a mapped BAR of a module-owned device.
/// Reached from `narf_mmio_read32`. `None` on a bad token/handle/offset.
pub fn module_mmio_read32(owner: u64, token: u64, handle: u64, off: u64) -> Option<u32> {
    with_bar(owner, token, handle, |region| {
        if off.checked_add(4)? > region.len {
            return None;
        }
        // SAFETY: offset bounds-checked against the mapped region length; the
        // region was produced by `map_bar` for this device.
        Some(unsafe { region.read32(off) })
    })
    .flatten()
}

/// Write a 32-bit device register to a mapped BAR of a module-owned device.
/// Reached from `narf_mmio_write32`. Returns 0 or a negative errno.
pub fn module_mmio_write32(owner: u64, token: u64, handle: u64, off: u64, val: u32) -> i32 {
    with_bar(owner, token, handle, |region| {
        if off.checked_add(4).map(|e| e > region.len).unwrap_or(true) {
            return -22; // -EINVAL
        }
        // SAFETY: offset bounds-checked against the mapped region length.
        unsafe { region.write32(off, val) };
        0
    })
    .unwrap_or(-22)
}

/// Responsively wait until `(read32(off) & mask) == expected`, bounded by a
/// wall-clock timeout. This keeps wait-loop policy in the kernel scheduler
/// instead of asking separately compiled drivers to hand-roll register spins.
pub fn module_mmio_wait32(
    owner: u64,
    token: u64,
    handle: u64,
    off: u64,
    mask: u32,
    expected: u32,
    timeout_ns: u64,
) -> i32 {
    if timeout_ns == 0 || timeout_ns > 1_000_000_000 {
        return -22;
    }
    with_bar(owner, token, handle, |region| {
        if off
            .checked_add(4)
            .map(|end| end > region.len)
            .unwrap_or(true)
        {
            return -22;
        }
        let ready = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: the offset was bounds-checked above; the caller owns
                // this device and selected a register safe to poll.
                (unsafe { region.read32(off) } & mask) == expected
            },
            narf_time::Deadline::after_ns(timeout_ns),
        );
        if ready {
            0
        } else {
            -110
        } // -ETIMEDOUT
    })
    .unwrap_or(-19)
}

/// Allocate coherent DMA memory in the module's effective domain and return a
/// 1-based opaque handle (`0` on failure). The module never receives the CPU
/// pointer; subsequent copies go through the bounded accessors below.
pub fn module_dma_alloc(owner: u64, token: u64, len: usize, domain: narf_lib::id::DomainId) -> u64 {
    let device_cap = {
        let g = DEVICE_CTXS.lock();
        match g.iter().find(|c| c.owner == owner && c.token == token) {
            Some(ctx) => ctx.cap,
            None => return 0,
        }
    };
    if device_cap.invoke(DeviceOp(|| ())).is_err() {
        return 0;
    }
    let buffer = match narf_io::alloc_coherent(len, domain) {
        Ok(buffer) => buffer,
        Err(_) => return 0,
    };
    let dma_cap = narf_io::register_with_cap(buffer);

    let mut g = DEVICE_CTXS.lock();
    let Some(ctx) = g.iter_mut().find(|c| c.owner == owner && c.token == token) else {
        narf_io::unregister(dma_cap);
        return 0;
    };
    ctx.dmabufs.push(Some(dma_cap));
    ctx.dmabufs.len() as u64
}

fn with_dma<R>(
    owner: u64,
    token: u64,
    handle: u64,
    f: impl FnOnce(&narf_io::DmaBuffer) -> R,
) -> Option<R> {
    // Copy both caps out and release the IRQ-safe context lock before a
    // potentially large memcpy. A concurrent free/unload revokes the copied
    // cap; if it races after resolution, the registry's Arc keeps the backing
    // allocation live until this operation returns.
    let (device_cap, dma_cap) = {
        let g = DEVICE_CTXS.lock();
        let ctx = g.iter().find(|c| c.owner == owner && c.token == token)?;
        let idx = handle.checked_sub(1)? as usize;
        (ctx.cap, *ctx.dmabufs.get(idx)?.as_ref()?)
    };
    device_cap
        .invoke(DeviceOp(|| dma_cap.invoke(DmaOp(f))))
        .ok()?
        .ok()
}

/// Resolve a byte offset in a module-owned DMA buffer to the address the
/// device must consume. Returns `None` for stale handles or out-of-range
/// offsets.
pub fn module_dma_addr(owner: u64, token: u64, handle: u64, off: u64) -> Option<u64> {
    with_dma(owner, token, handle, |buffer| {
        if off >= buffer.len() as u64 {
            return None;
        }
        Some(buffer.dma_addr_at(off).raw())
    })
    .flatten()
}

/// Copy bytes from module memory into a coherent DMA buffer. Returns 0 or a
/// negative errno; the entire range is checked before any byte is written.
pub fn module_dma_write(owner: u64, token: u64, handle: u64, off: u64, src: &[u8]) -> i32 {
    with_dma(owner, token, handle, |buffer| {
        let Some(start) = usize::try_from(off).ok() else {
            return -22;
        };
        let Some(end) = start.checked_add(src.len()) else {
            return -22;
        };
        if end > buffer.len() {
            return -22;
        }
        // SAFETY: `[start, end)` was checked against the live buffer length;
        // `src` is a disjoint module slice for the duration of this call.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), buffer.as_mut_ptr().add(start), src.len())
        };
        0
    })
    .unwrap_or(-22)
}

/// Copy bytes from a coherent DMA buffer into module memory. Returns 0 or a
/// negative errno; the entire range is checked before any byte is read.
pub fn module_dma_read(owner: u64, token: u64, handle: u64, off: u64, dst: &mut [u8]) -> i32 {
    with_dma(owner, token, handle, |buffer| {
        let Some(start) = usize::try_from(off).ok() else {
            return -22;
        };
        let Some(end) = start.checked_add(dst.len()) else {
            return -22;
        };
        if end > buffer.len() {
            return -22;
        }
        // SAFETY: `[start, end)` was checked against the live buffer length;
        // `dst` is a disjoint module slice for the duration of this call.
        unsafe {
            core::ptr::copy_nonoverlapping(buffer.as_ptr().add(start), dst.as_mut_ptr(), dst.len())
        };
        0
    })
    .unwrap_or(-22)
}

/// Responsively wait for one device-owned DMA status byte. Used for bounded
/// synchronous TX completion without exposing the CPU mapping to the module.
pub fn module_dma_wait8(
    owner: u64,
    token: u64,
    handle: u64,
    off: u64,
    mask: u8,
    expected: u8,
    timeout_ns: u64,
) -> i32 {
    if timeout_ns == 0 || timeout_ns > 1_000_000_000 {
        return -22;
    }
    with_dma(owner, token, handle, |buffer| {
        let Some(offset) = usize::try_from(off).ok().filter(|off| *off < buffer.len()) else {
            return -22;
        };
        let ready = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: `offset < buffer.len()` above and the allocation is
                // retained by the resolved DMA-cap Arc for this whole wait.
                (unsafe { buffer.as_ptr().add(offset).read_volatile() } & mask) == expected
            },
            narf_time::Deadline::after_ns(timeout_ns),
        );
        if ready {
            0
        } else {
            -110
        }
    })
    .unwrap_or(-22)
}

/// Revoke and free one module-owned DMA buffer. Handles are 1-based and their
/// slots are never reused during this device context's lifetime, so stale
/// handles cannot alias a later allocation.
pub fn module_dma_free(owner: u64, token: u64, handle: u64) -> i32 {
    let cap = {
        let mut g = DEVICE_CTXS.lock();
        let Some(ctx) = g.iter_mut().find(|c| c.owner == owner && c.token == token) else {
            return -19; // -ENODEV
        };
        if ctx.cap.invoke(DeviceOp(|| ())).is_err() {
            return -19;
        }
        let Some(idx) = handle
            .checked_sub(1)
            .and_then(|idx| usize::try_from(idx).ok())
        else {
            return -22;
        };
        let Some(slot) = ctx.dmabufs.get_mut(idx) else {
            return -22;
        };
        let Some(cap) = slot.take() else {
            return -22;
        };
        cap
    };
    narf_io::unregister(cap);
    0
}

/// Discover and retain the MSI-X table for a module-owned device.
pub fn module_msix_enable(owner: u64, token: u64) -> i32 {
    let (device, cap) = {
        let g = DEVICE_CTXS.lock();
        let Some(ctx) = g.iter().find(|c| c.owner == owner && c.token == token) else {
            return -19; // -ENODEV
        };
        if ctx.msix.is_some() {
            return 0;
        }
        (ctx.device, ctx.cap)
    };
    let table = match cap.invoke(DeviceOp(|| crate::msix::enable_msix(&cap, &device))) {
        Ok(Ok(table)) => table,
        Ok(Err(crate::msix::MsixError::CapabilityNotFound | crate::msix::MsixError::NotPcie)) => {
            return -95; // -EOPNOTSUPP
        }
        _ => return -5, // -EIO
    };
    let mut g = DEVICE_CTXS.lock();
    let Some(ctx) = g.iter_mut().find(|c| c.owner == owner && c.token == token) else {
        return -19;
    };
    if ctx.msix.is_none() {
        ctx.msix = Some(table);
    }
    0
}

fn restore_msix_table(owner: u64, token: u64, table: crate::msix::MsixTable) {
    let mut g = DEVICE_CTXS.lock();
    if let Some(ctx) = g.iter_mut().find(|c| c.owner == owner && c.token == token) {
        if ctx.msix.is_none() {
            ctx.msix = Some(table);
        }
    }
}

/// Allocate an interrupt vector, program one MSI-X table entry, install the
/// in-tree hard-IRQ stub, and enable MSI-X. Returns the kernel vector number.
pub fn module_msix_claim(owner: u64, token: u64) -> Result<u16, i32> {
    let (cap, mut table) = {
        let mut g = DEVICE_CTXS.lock();
        let Some(ctx) = g.iter_mut().find(|c| c.owner == owner && c.token == token) else {
            return Err(-19);
        };
        let Some(table) = ctx.msix.take() else {
            return Err(-22);
        };
        (ctx.cap, table)
    };

    let vector = match narf_interrupts::vector::alloc() {
        Ok(vector) => vector,
        Err(_) => {
            restore_msix_table(owner, token, table);
            return Err(-28); // -ENOSPC
        }
    };
    let Some(entry) = table.alloc_vector() else {
        let _ = narf_interrupts::vector::free(vector);
        restore_msix_table(owner, token, table);
        return Err(-28);
    };

    let programmed = cap.invoke(DeviceOp(|| {
        let was_enabled = table.is_enabled();
        // Function-mask the table before writing an unmasked entry. This is
        // required on the second and later claims because `program_vector`
        // writes vector-control last; otherwise the device could target the
        // new vector before its hard handler exists.
        // SAFETY: the context exclusively owns device config space.
        unsafe { table.disable() };
        // SAFETY: the context exclusively owns the MSI-X table; `entry` came
        // from this table and the vector allocator owns `vector`.
        (was_enabled, unsafe {
            table.program_vector(entry.vector, 0, vector)
        })
    }));
    match programmed {
        Ok((_, Ok(_))) => {}
        Ok((was_enabled, Err(_))) => {
            if was_enabled {
                let _ = cap.invoke(DeviceOp(|| {
                    // SAFETY: restore the pre-claim global enable state.
                    unsafe { table.enable() }
                }));
            }
            let _ = narf_interrupts::vector::free(vector);
            restore_msix_table(owner, token, table);
            return Err(-5);
        }
        Err(_) => {
            let _ = narf_interrupts::vector::free(vector);
            restore_msix_table(owner, token, table);
            return Err(-5);
        }
    }

    narf_interrupts::install_handler_named(
        vector,
        MODULE_IRQ_HANDLER_NAME,
        token,
        module_irq_claim_stub,
    );
    let enabled = cap.invoke(DeviceOp(|| {
        // SAFETY: the table entry and hard handler are installed before
        // delivery is enabled, and this context owns device config space.
        unsafe { table.enable() }
    }));
    if !matches!(enabled, Ok(Ok(()))) {
        narf_interrupts::disable_irq(vector);
        let _ = narf_interrupts::remove_handler(vector, MODULE_IRQ_HANDLER_NAME, token);
        narf_interrupts::synchronize_irq(vector);
        let _ = narf_interrupts::vector::free(vector);
        restore_msix_table(owner, token, table);
        return Err(-5);
    }

    let mut g = DEVICE_CTXS.lock();
    let Some(ctx) = g.iter_mut().find(|c| c.owner == owner && c.token == token) else {
        drop(g);
        // SAFETY: we still exclusively own this detached table.
        unsafe { table.disable() };
        narf_interrupts::disable_irq(vector);
        let _ = narf_interrupts::remove_handler(vector, MODULE_IRQ_HANDLER_NAME, token);
        narf_interrupts::synchronize_irq(vector);
        let _ = narf_interrupts::vector::free(vector);
        return Err(-19);
    };
    ctx.irqs.push(ModuleIrq {
        table_idx: entry.vector,
        vector,
        callback: None,
        cookie: 0,
        callback_id: 0,
    });
    ctx.msix = Some(table);
    Ok(vector as u16)
}

fn irq_callback_is_live(
    owner: u64,
    token: u64,
    vector: u8,
    callback: ModuleCallbackFn,
    cookie: u64,
    callback_id: u64,
) -> bool {
    let cap = {
        let g = DEVICE_CTXS.lock();
        let Some(ctx) = g.iter().find(|c| c.owner == owner && c.token == token) else {
            return false;
        };
        let live = ctx.irqs.iter().any(|irq| {
            irq.vector == vector
                && irq.callback.map(|cb| cb as usize) == Some(callback as usize)
                && irq.cookie == cookie
                && irq.callback_id == callback_id
        });
        if !live {
            return false;
        }
        ctx.cap
    };
    cap.invoke(DeviceOp(|| ())).is_ok()
}

fn poller_is_live(
    owner: u64,
    token: u64,
    callback: ModuleCallbackFn,
    cookie: u64,
    callback_id: u64,
) -> bool {
    let cap = {
        let g = DEVICE_CTXS.lock();
        let Some(ctx) = g.iter().find(|c| c.owner == owner && c.token == token) else {
            return false;
        };
        let live = ctx.poller.is_some_and(|poller| {
            poller.callback as usize == callback as usize
                && poller.cookie == cookie
                && poller.callback_id == callback_id
        });
        if !live {
            return false;
        }
        ctx.cap
    };
    cap.invoke(DeviceOp(|| ())).is_ok()
}

fn record_callback_result(owner: u64, token: u64, result: i32) {
    if let Some(ctx) = DEVICE_CTXS
        .lock()
        .iter_mut()
        .find(|c| c.owner == owner && c.token == token)
    {
        ctx.callback_invocations = ctx.callback_invocations.saturating_add(1);
        if result < 0 {
            ctx.callback_failures = ctx.callback_failures.saturating_add(1);
        }
    }
}

fn clear_poller(owner: u64, token: u64, callback_id: u64) {
    let mut g = DEVICE_CTXS.lock();
    let Some(ctx) = g.iter_mut().find(|c| c.owner == owner && c.token == token) else {
        return;
    };
    if ctx.poller.map(|p| p.callback_id) == Some(callback_id) {
        ctx.poller = None;
    }
}

fn clear_irq_callback(owner: u64, token: u64, vector: u8, callback_id: u64) {
    let mut g = DEVICE_CTXS.lock();
    let Some(ctx) = g.iter_mut().find(|c| c.owner == owner && c.token == token) else {
        return;
    };
    let Some(irq) = ctx
        .irqs
        .iter_mut()
        .find(|irq| irq.vector == vector && irq.callback_id == callback_id)
    else {
        return;
    };
    irq.callback = None;
    irq.cookie = 0;
    irq.callback_id = 0;
}

/// Attach a task-context callback to a vector claimed from this device's
/// MSI-X table. The hard handler only accounts/wakes; module code runs here.
pub fn module_irq_set_handler(
    owner: u64,
    token: u64,
    vector: u16,
    callback: ModuleCallbackFn,
    cookie: u64,
) -> i32 {
    let Ok(vector) = u8::try_from(vector) else {
        return -22;
    };
    let callback_id = {
        let mut g = DEVICE_CTXS.lock();
        let Some(ctx) = g.iter_mut().find(|c| c.owner == owner && c.token == token) else {
            return -19;
        };
        if ctx.cap.invoke(DeviceOp(|| ())).is_err() {
            return -19;
        }
        let Some(irq_idx) = ctx.irqs.iter().position(|irq| irq.vector == vector) else {
            return -22;
        };
        if ctx.irqs[irq_idx].callback.is_some() {
            return -16;
        }
        let callback_id = ctx.next_callback_id;
        ctx.next_callback_id = ctx.next_callback_id.saturating_add(1);
        ctx.irqs[irq_idx].callback = Some(callback);
        ctx.irqs[irq_idx].cookie = cookie;
        ctx.irqs[irq_idx].callback_id = callback_id;
        callback_id
    };

    narf_scheduler::spawn(async move {
        let mut observed = narf_interrupts::fire_count(vector);
        loop {
            if !irq_callback_is_live(owner, token, vector, callback, cookie, callback_id) {
                return;
            }
            let current = narf_interrupts::fire_count(vector);
            if current != observed {
                observed = current;
                let result = call_module_callback(owner, callback, cookie);
                record_callback_result(owner, token, result);
                if result != 0 {
                    clear_irq_callback(owner, token, vector, callback_id);
                    return;
                }
                continue;
            }
            // The timeout bounds teardown latency. An IRQ racing between the
            // sample and waiter construction is noticed by the next sample.
            let _ = narf_interrupts::wait_for_irq_until(vector, narf_time::Deadline::after_ms(10))
                .await;
        }
    });
    0
}

/// Spawn one periodic task-context callback for a module-owned device. It
/// polls immediately, then roughly every 1 ms while the callback returns zero.
/// A non-zero return retires the poller.
pub fn module_spawn_poller(owner: u64, token: u64, callback: ModuleCallbackFn, cookie: u64) -> i32 {
    let callback_id = {
        let mut g = DEVICE_CTXS.lock();
        let Some(ctx) = g.iter_mut().find(|c| c.owner == owner && c.token == token) else {
            return -19;
        };
        if ctx.cap.invoke(DeviceOp(|| ())).is_err() {
            return -19;
        }
        if ctx.poller.is_some() {
            return -16;
        }
        let callback_id = ctx.next_callback_id;
        ctx.next_callback_id = ctx.next_callback_id.saturating_add(1);
        ctx.poller = Some(ModulePoller {
            callback,
            cookie,
            callback_id,
        });
        callback_id
    };

    narf_scheduler::spawn(async move {
        loop {
            if !poller_is_live(owner, token, callback, cookie, callback_id) {
                return;
            }
            let result = call_module_callback(owner, callback, cookie);
            record_callback_result(owner, token, result);
            if result != 0 {
                clear_poller(owner, token, callback_id);
                return;
            }
            narf_time::sleep_cycles(narf_time::ns_to_cycles(1_000_000)).await;
        }
    });
    0
}

fn module_net_tx_bridge(token: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    // The first module ABI advertises no offloads. Receiving non-plain metadata
    // would mean the net registry and module contract drifted.
    if meta != narf_net::TxMeta::plain() {
        return Err(());
    }
    let (owner, cap, callback) = {
        let g = DEVICE_CTXS.lock();
        let ctx = g.iter().find(|ctx| ctx.token == token).ok_or(())?;
        let iface = ctx.net_iface.as_ref().ok_or(())?;
        (ctx.owner, ctx.cap, iface.tx_callback)
    };
    if cap.invoke(DeviceOp(|| ())).is_err() {
        return Err(());
    }
    let result = call_module_tx(owner, callback, frame);
    if let Some(ctx) = DEVICE_CTXS
        .lock()
        .iter_mut()
        .find(|ctx| ctx.owner == owner && ctx.token == token)
    {
        ctx.net_tx_callbacks = ctx.net_tx_callbacks.saturating_add(1);
        if result != 0 {
            ctx.net_tx_failures = ctx.net_tx_failures.saturating_add(1);
        }
    }
    match result {
        0 => Ok(()),
        _ => Err(()),
    }
}

/// Register one copy-mode Ethernet interface for a module-owned device. The
/// permanent in-tree send trampoline carries `token` back to this context and
/// enters module text only through the lifecycle/domain gate.
pub fn module_netif_register(
    owner: u64,
    token: u64,
    mac: [u8; 6],
    tx_callback: ModuleTxFn,
) -> Result<u32, i32> {
    let cap = {
        let g = DEVICE_CTXS.lock();
        let Some(ctx) = g
            .iter()
            .find(|ctx| ctx.owner == owner && ctx.token == token)
        else {
            return Err(-19);
        };
        if ctx.net_iface.is_some() {
            return Err(-16);
        }
        ctx.cap
    };
    if cap.invoke(DeviceOp(|| ())).is_err() {
        return Err(-19);
    }

    let name = narf_net::iface::register_with_context("eth%d", mac, token, module_net_tx_bridge);
    let Some(ifindex) = narf_net::iface::ifindex_of(&name) else {
        let _ = narf_net::iface::unregister(&name);
        return Err(-5);
    };

    let mut g = DEVICE_CTXS.lock();
    let Some(ctx) = g
        .iter_mut()
        .find(|ctx| ctx.owner == owner && ctx.token == token)
    else {
        drop(g);
        let _ = narf_net::iface::unregister(&name);
        return Err(-19);
    };
    if ctx.net_iface.is_some() {
        drop(g);
        let _ = narf_net::iface::unregister(&name);
        return Err(-16);
    }
    ctx.net_iface = Some(ModuleNetIface {
        name,
        ifindex,
        tx_callback,
    });
    Ok(ifindex)
}

/// Deliver one copied receive frame from module memory into the kernel stack.
pub fn module_netif_rx(owner: u64, token: u64, ifindex: u32, frame: &mut [u8]) -> i32 {
    let (cap, name) = {
        let g = DEVICE_CTXS.lock();
        let Some(ctx) = g
            .iter()
            .find(|ctx| ctx.owner == owner && ctx.token == token)
        else {
            return -19;
        };
        let Some(iface) = ctx
            .net_iface
            .as_ref()
            .filter(|iface| iface.ifindex == ifindex)
        else {
            return -22;
        };
        (ctx.cap, iface.name.clone())
    };
    if cap.invoke(DeviceOp(|| ())).is_err() {
        return -19;
    }
    narf_net::iface::on_rx_frame_from(&name, frame);
    if let Some(ctx) = DEVICE_CTXS
        .lock()
        .iter_mut()
        .find(|ctx| ctx.owner == owner && ctx.token == token)
    {
        ctx.net_rx_frames = ctx.net_rx_frames.saturating_add(1);
    }
    0
}

/// The single `PciProbeFn` installed for every module-registered match.
/// Dispatches to the module's thunk by the discovered device's IDs.
fn module_probe_trampoline(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), ProbeError> {
    let (vid, did) = (device.id.vendor, device.id.device);
    let thunk = MODULE_THUNKS
        .lock()
        .iter()
        .find(|t| t.vendor == vid && t.device == did)
        .map(|t| (t.owner, t.thunk));
    let Some((owner, f)) = thunk else {
        return Err(ProbeError::NotForThisDriver);
    };
    // Install the datapath context (device + cap) so the module's probe can
    // drive the device through the datapath exports, then call the thunk.
    let token = addr_token(device.addr);
    install_device_ctx(owner, token, device, cap);
    // 0 => the module bound the device; keep the context (module owns it). A
    // negative errno => it declined; release the context + cap.
    match call_module_probe(owner, f, token, 0) {
        0 => Ok(()),
        _ => {
            remove_device_ctx(token);
            Err(ProbeError::Other("module probe declined"))
        }
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
    owner: u64,
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
        // and its owner rather than growing the table.
        let mut g = MODULE_THUNKS.lock();
        if let Some(pos) = g
            .iter()
            .position(|t| t.vendor == vendor && t.device == device)
        {
            if g[pos].owner != owner {
                return -16; // -EBUSY: another module owns this match.
            }
            g[pos].owner = owner;
            g[pos].name = name;
            g[pos].thunk = thunk;
        } else {
            g.push(ModuleThunk {
                owner,
                name,
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

/// Remove every PCI match, callback and device context owned by one loadable
/// module. The caller must run the module's exit hook first so it can quiesce
/// hardware while its resources are still reachable, and must call this
/// before unmapping module text.
pub fn unregister_module_pci_drivers(owner: u64) {
    let owned_matches = {
        let mut thunks = MODULE_THUNKS.lock();
        let mut owned = Vec::new();
        for thunk in thunks.iter().filter(|t| t.owner == owner) {
            owned.push((thunk.name, thunk.vendor, thunk.device));
        }
        thunks.retain(|t| t.owner != owner);
        owned
    };

    if !owned_matches.is_empty() {
        REGISTRY.lock().retain(|entry| {
            !owned_matches.iter().any(|(name, vendor, device)| {
                entry.name == *name
                    && entry.kind
                        == (MatchKind::VendorDevice {
                            vendor: *vendor,
                            device: *device,
                        })
                    && entry.probe as usize == module_probe_trampoline as usize
            })
        });
    }

    let contexts = {
        let mut all = DEVICE_CTXS.lock();
        let mut owned = Vec::new();
        let mut idx = 0;
        while idx < all.len() {
            if all[idx].owner == owner {
                owned.push(all.remove(idx));
            } else {
                idx += 1;
            }
        }
        owned
    };
    for ctx in contexts {
        teardown_device_ctx(ctx);
    }
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
pub fn __module_device_context_count_for_test(owner: u64) -> usize {
    DEVICE_CTXS
        .lock()
        .iter()
        .filter(|ctx| ctx.owner == owner)
        .count()
}

#[doc(hidden)]
pub fn __module_dma_buffer_count_for_test(owner: u64) -> usize {
    DEVICE_CTXS
        .lock()
        .iter()
        .filter(|ctx| ctx.owner == owner)
        .map(|ctx| ctx.dmabufs.iter().flatten().count())
        .sum()
}

#[doc(hidden)]
pub fn __module_callback_invocation_count_for_test(owner: u64) -> u64 {
    DEVICE_CTXS
        .lock()
        .iter()
        .filter(|ctx| ctx.owner == owner)
        .map(|ctx| ctx.callback_invocations)
        .sum()
}

#[doc(hidden)]
pub fn __module_callback_failure_count_for_test(owner: u64) -> u64 {
    DEVICE_CTXS
        .lock()
        .iter()
        .filter(|ctx| ctx.owner == owner)
        .map(|ctx| ctx.callback_failures)
        .sum()
}

#[doc(hidden)]
pub fn __module_irq_vector_count_for_test(owner: u64) -> usize {
    DEVICE_CTXS
        .lock()
        .iter()
        .filter(|ctx| ctx.owner == owner)
        .map(|ctx| ctx.irqs.len())
        .sum()
}

#[doc(hidden)]
pub fn __module_netif_count_for_test(owner: u64) -> usize {
    DEVICE_CTXS
        .lock()
        .iter()
        .filter(|ctx| ctx.owner == owner && ctx.net_iface.is_some())
        .count()
}

#[doc(hidden)]
pub fn __module_netif_stats_for_test(owner: u64) -> (u64, u64, u64) {
    let g = DEVICE_CTXS.lock();
    g.iter()
        .filter(|ctx| ctx.owner == owner)
        .fold((0, 0, 0), |(tx, tx_err, rx), ctx| {
            (
                tx.saturating_add(ctx.net_tx_callbacks),
                tx_err.saturating_add(ctx.net_tx_failures),
                rx.saturating_add(ctx.net_rx_frames),
            )
        })
}

#[doc(hidden)]
pub fn __module_netif_mac_for_test(owner: u64) -> Option<[u8; 6]> {
    let name = {
        let g = DEVICE_CTXS.lock();
        g.iter()
            .find(|ctx| ctx.owner == owner)
            .and_then(|ctx| ctx.net_iface.as_ref())
            .map(|iface| iface.name.clone())
    };
    narf_net::iface::lookup(&name?).map(|iface| iface.mac)
}

#[doc(hidden)]
pub fn __module_dma_read_for_test(owner: u64, handle: u64, offset: u64, dst: &mut [u8]) -> bool {
    let token = DEVICE_CTXS
        .lock()
        .iter()
        .find(|ctx| ctx.owner == owner)
        .map(|ctx| ctx.token);
    token.is_some_and(|token| module_dma_read(owner, token, handle, offset, dst) == 0)
}

#[doc(hidden)]
pub fn __module_dma_write_for_test(owner: u64, handle: u64, offset: u64, src: &[u8]) -> bool {
    let token = DEVICE_CTXS
        .lock()
        .iter()
        .find(|ctx| ctx.owner == owner)
        .map(|ctx| ctx.token);
    token.is_some_and(|token| module_dma_write(owner, token, handle, offset, src) == 0)
}

#[doc(hidden)]
pub fn __module_netif_send_for_test(owner: u64, frame: &[u8]) -> bool {
    let ifindex = {
        let g = DEVICE_CTXS.lock();
        g.iter()
            .find(|ctx| ctx.owner == owner)
            .and_then(|ctx| ctx.net_iface.as_ref())
            .map(|iface| iface.ifindex)
    };
    ifindex.is_some_and(|ifindex| narf_net::iface::send_on_ifindex(ifindex, frame).is_ok())
}

#[doc(hidden)]
/// Test-only: reset the registry between smokes. Keeps tests
/// hermetic without exposing a public clear path.
pub fn __reset_for_test() {
    let contexts = {
        let mut contexts = DEVICE_CTXS.lock();
        core::mem::take(&mut *contexts)
    };
    for ctx in contexts {
        teardown_device_ctx(ctx);
    }
    REGISTRY.lock().clear();
    MODULE_THUNKS.lock().clear();
    INTERNED_NAMES.lock().clear();
    REMOVE_FNS.lock().clear();
    BOUND.lock().clear();
}
