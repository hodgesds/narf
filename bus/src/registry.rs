//! Read-only device registry.
//!
//! Stage-2-side-track: a single `Vec<BusDevice>` behind an
//! `IrqSafeSpinLock<Option<...>>`, populated once by `init` and then
//! only read. Stage-3 Wave 2 rewires this on top of `rcu/` so
//! `devices()` is lock-free while hot-plug appends in parallel (spec
//! §3.2, §4 invariant: "registry is read-mostly and uses RCU for
//! lookups").
//!
//! The claim API is the cap-gated `Cap<BusRegistry, Claim>` →
//! `Cap<BusDevice, _>` flow per `bus/` §3.3. That whole surface depends
//! on the Wave-2 cap table, which isn't in this worktree. We expose a
//! placeholder `claim_device(BusAddr)` that returns a plain
//! `BusDeviceHandle` — structurally the right shape, missing the
//! capability typing. The main agent rewires this in Wave 2; see
//! `STAGE3.md` critical path "bus side track supplies claim".

use alloc::vec::Vec;
use core::fmt;

use narf_lib::sync::IrqSafeSpinLock;

use crate::addr::BusAddr;
use crate::device::BusDevice;

/// Registry error surface. Today only "no such device" is reachable;
/// cap-related errors arrive with the cap-table rewire in Wave 2
/// (`Revoked`, `RightsTooWeak`, etc. per `capabilities/` §3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClaimError {
    NotFound,
    NotInitialised,
}

/// Handle returned by `claim_device`. Wave-2 placeholder — once
/// `Cap<BusDevice, _>` exists, this becomes
/// `Cap<BusDevice, Map | Irq | Dma>` (spec §3.3 bundle). For now it
/// simply carries the `BusDevice` snapshot out by value.
#[derive(Copy, Clone)]
pub struct BusDeviceHandle {
    pub device: BusDevice,
}

impl fmt::Debug for BusDeviceHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BusDeviceHandle")
            .field("device", &self.device)
            .finish()
    }
}

static REGISTRY: IrqSafeSpinLock<Option<Vec<BusDevice>>> = IrqSafeSpinLock::new(None);

/// Install the registry from a vector of enumerated devices. The
/// canonical callers are `bus::x86_64::enumerate` and
/// `bus::aarch64::enumerate`; tests may call this directly with a
/// synthetic set. A second call replaces the registry — the intent
/// is that only `init` (called once by each arch backend) calls this,
/// but leaving it idempotent keeps per-arch tests independent.
pub fn install(devices: Vec<BusDevice>) {
    let mut g = REGISTRY.lock();
    *g = Some(devices);
}

/// Boot-time initialisation. Calls into the arch-appropriate enumerate
/// routine and installs its result. Safe to call multiple times — the
/// most recent call wins. Returns the number of devices discovered.
///
/// # Safety
/// - Bootloader handoff invariants hold (memory map parsed, allocator
///   online).
/// - On aarch64 the caller supplies the DTB physical address as handed
///   in via `RawBootInfo`. Passing a bogus pointer aborts the FDT walk
///   cleanly and yields an empty registry rather than UB.
pub unsafe fn init(
    #[cfg(target_arch = "x86_64")] ecam_base: narf_memory::PhysAddr,
    #[cfg(target_arch = "aarch64")] dtb: Option<narf_memory::PhysAddr>,
) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: caller-provided ECAM base; the enumerator only reads
        // 4-byte config-space words and rejects all-1s (unpopulated).
        let devs = unsafe { crate::x86_64::enumerate(ecam_base) };
        let n = devs.len();
        install(devs);
        n
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: FDT walker tolerates null / bad magic by returning
        // an empty Vec (same tolerance as `boot/src/aarch64` §parse_raw).
        let devs = unsafe { crate::aarch64::enumerate(dtb) };
        let n = devs.len();
        install(devs);
        n
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

/// Iterate every discovered device.
///
/// Returns an empty slice if `init` has not been called (Stage-2
/// flavour binaries may not call it; the kernel-test harness calls
/// into `init` from its per-arch test before asserting on the
/// results).
pub fn devices() -> Vec<BusDevice> {
    // We intentionally clone out of the lock: the Stage-2 backing store
    // is allocation-backed and Wave-2 will swap this for an RCU-protected
    // reader with no copy. Keeping the signature Vec-by-value lets that
    // rewire be a drop-in change for callers.
    let g = REGISTRY.lock();
    g.as_ref().cloned().unwrap_or_default()
}

/// Snapshot semantics per spec §3.2 — the boot-time-only view. Today
/// it's identical to `devices()` because hot-plug hasn't landed; once
/// it does, `snapshot` stays pinned at the Stage-2-end set and
/// `devices()` tracks hot-plug deltas.
pub fn snapshot() -> Vec<BusDevice> {
    devices()
}

/// Placeholder for the spec §3.3 claim API. Wave-2 rewires this to
/// take a `&Cap<BusRegistry, Claim>` and return `Cap<BusDevice, _>`.
///
/// The signature here is deliberately the non-cap variant; see the
/// report-back for the rewire contract.
pub fn claim_device(addr: BusAddr) -> Result<BusDeviceHandle, ClaimError> {
    let g = REGISTRY.lock();
    let list = match g.as_ref() {
        Some(v) => v,
        None    => return Err(ClaimError::NotInitialised),
    };
    for d in list.iter() {
        if d.addr == addr {
            return Ok(BusDeviceHandle { device: *d });
        }
    }
    Err(ClaimError::NotFound)
}
