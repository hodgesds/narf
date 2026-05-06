//! PCI Express extended capability list walker (offset 0x100..0xFFF).
//!
//! Spec: PCIe base 5.0 §7.6. The extended cap list is a separate
//! singly-linked list rooted at config offset 0x100. Each header is a
//! u32 layout:
//!   bits  0..=15 : extended cap id (16-bit, vs the 8-bit standard
//!                  cap id at offset 0x34)
//!   bits 16..=19 : cap version
//!   bits 20..=31 : next-cap pointer (12 bits; 0 → end of list)
//!
//! Extended caps NARF cares about today:
//!
//! | id     | name                       |
//! |--------|----------------------------|
//! | 0x0001 | Advanced Error Reporting   |
//! | 0x0002 | Virtual Channel            |
//! | 0x000D | Access Control Services    |
//! | 0x000F | Address Translation Services|
//! | 0x0010 | SR-IOV                     |
//! | 0x001D | Downstream Port Containment|

use core::sync::atomic::{compiler_fence, Ordering};

use narf_capabilities::{Cap, CapError, Read};
use narf_memory::PhysAddr;

use crate::device::{BusDevice, BusKind};
use crate::registry::BusDeviceCap;

/// Extended cap IDs.
pub mod id {
    pub const AER: u16 = 0x0001;
    pub const VC: u16 = 0x0002;
    pub const ACS: u16 = 0x000D;
    pub const ATS: u16 = 0x000F;
    pub const SR_IOV: u16 = 0x0010;
    pub const DPC: u16 = 0x001D;
}

/// Start of the extended cap list — fixed by spec.
pub const EXT_CAP_BASE: u64 = 0x100;
/// PCIe extended config space ends at 0x1000.
const EXT_CAP_LIMIT: u64 = 0x1000;
/// Bound the walker against malformed devices.
const MAX_HOPS: u32 = 256;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExtCapError {
    AuthorityRevoked,
    NotPcie,
}

impl From<CapError> for ExtCapError {
    fn from(_: CapError) -> Self {
        ExtCapError::AuthorityRevoked
    }
}

/// Decoded extended-cap header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExtCapHeader {
    pub id: u16,
    pub version: u8,
    pub offset: u64,
}

/// Iterate the extended cap list. ECAM / cfg-space access for offsets
/// 0x100..0xFFF requires the cfg window to be at least 4 KiB — true
/// for PCIe ECAM, false for legacy 256-byte PCI; the walker bails on
/// the first all-1s read so a device that doesn't expose extended
/// space cleanly returns an empty iterator.
///
/// Cap-gated.
pub fn iter(cap: &Cap<BusDeviceCap, Read>, device: &BusDevice) -> Result<ExtCapIter, ExtCapError> {
    cap.check_live()?;
    let cfg = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. } => return Err(ExtCapError::NotPcie),
    };
    Ok(ExtCapIter {
        cfg,
        next: EXT_CAP_BASE,
        hops: 0,
    })
}

/// Find the first extended capability with the given ID.
pub fn find_cap(
    cap: &Cap<BusDeviceCap, Read>,
    device: &BusDevice,
    id: u16,
) -> Result<Option<ExtCapHeader>, ExtCapError> {
    let it = iter(cap, device)?;
    for hdr in it {
        if hdr.id == id {
            return Ok(Some(hdr));
        }
    }
    Ok(None)
}

#[derive(Debug)]
pub struct ExtCapIter {
    cfg: PhysAddr,
    next: u64,
    hops: u32,
}

impl Iterator for ExtCapIter {
    type Item = ExtCapHeader;
    fn next(&mut self) -> Option<ExtCapHeader> {
        if self.next == 0
            || self.next < EXT_CAP_BASE
            || self.next >= EXT_CAP_LIMIT
            || self.hops >= MAX_HOPS
        {
            return None;
        }
        // SAFETY: extended-config window is identity-mapped; the
        // bounded `next` keeps us inside the 4 KiB cfg page.
        let hdr = unsafe { cfg_read32(self.cfg, self.next) };
        // All-zero or all-one header = end / unsupported.
        if hdr == 0 || hdr == 0xFFFF_FFFF {
            return None;
        }

        let id = (hdr & 0xFFFF) as u16;
        let version = ((hdr >> 16) & 0xF) as u8;
        let next = ((hdr >> 20) & 0xFFF) as u64;
        let here = self.next;
        self.next = next;
        self.hops += 1;
        Some(ExtCapHeader {
            id,
            version,
            offset: here,
        })
    }
}

// ── AER ─────────────────────────────────────────────────────────────

/// Decoded AER status snapshot. PCIe spec §7.8.4.
#[derive(Copy, Clone, Debug)]
pub struct AerStatus {
    /// Uncorrectable Error Status (RW1C, sticky).
    pub uncorrectable_status: u32,
    /// Uncorrectable Error Mask. Bits set = errors suppressed.
    pub uncorrectable_mask: u32,
    /// Uncorrectable Error Severity. Bits set = treat as fatal.
    pub uncorrectable_severity: u32,
    /// Correctable Error Status (RW1C, sticky).
    pub correctable_status: u32,
    /// Correctable Error Mask. Bits set = errors suppressed.
    pub correctable_mask: u32,
}

/// Read the device's AER status if the AER extended cap exists.
/// Returns `None` for devices without AER (e.g. QEMU NVMe by
/// default).
pub fn read_aer(
    cap: &Cap<BusDeviceCap, Read>,
    device: &BusDevice,
) -> Result<Option<AerStatus>, ExtCapError> {
    let hdr = find_cap(cap, device, id::AER)?;
    let Some(h) = hdr else {
        return Ok(None);
    };
    let cfg = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. } => return Err(ExtCapError::NotPcie),
    };
    // AER register layout (PCIe §7.8.4):
    //   +0x04 Uncorrectable Status
    //   +0x08 Uncorrectable Mask
    //   +0x0C Uncorrectable Severity
    //   +0x10 Correctable Status
    //   +0x14 Correctable Mask
    // SAFETY: 4 KiB cfg page; offsets stay in range.
    let s = unsafe {
        AerStatus {
            uncorrectable_status: cfg_read32(cfg, h.offset + 0x04),
            uncorrectable_mask: cfg_read32(cfg, h.offset + 0x08),
            uncorrectable_severity: cfg_read32(cfg, h.offset + 0x0C),
            correctable_status: cfg_read32(cfg, h.offset + 0x10),
            correctable_mask: cfg_read32(cfg, h.offset + 0x14),
        }
    };
    Ok(Some(s))
}

// ── AER event dispatch ──────────────────────────────────────────────
//
// AER status can be polled (today's path) or interrupt-driven (the
// root port's PCIe Capabilities Pointer points at an AER MSI vector
// the kernel programs at boot). Either way, the bus driver
// classifies the error word into `AerSeverity` and fires
// `dispatch_aer` to all registered listeners; drivers (or a global
// recovery coordinator) subscribe via `register_aer_listener`.
//
// This is the seam for: Fatal recovery (call `Driver::reset` on
// the bound driver), surface telemetry to userspace observability,
// and policy decisions like "isolate this device" or "panic". The
// dispatch table is intentionally separate from the hot-plug one
// so a global panic-on-fatal handler doesn't have to filter every
// hot-add event.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::addr::BusAddr;

/// Severity classification for an AER event. PCIe §7.8.2.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AerSeverity {
    /// Bit set in `correctable_status` — recovered transparently
    /// (replayed TLP, etc.). Telemetry only; no driver action.
    Correctable,
    /// Bit set in `uncorrectable_status` & ~severity — fatal-class
    /// uncorrectable but software can attempt recovery (FLR + bring
    /// up). Driver-level reset is the typical response.
    NonFatal,
    /// Bit set in `uncorrectable_status` & severity — link-level
    /// fatal; recovery requires segment / slot reset (the root
    /// port's downstream link is unusable). Today the policy is
    /// "log + isolate"; a future hot-replug arc may attempt full
    /// link retraining.
    Fatal,
}

/// One AER event. `status_word` is the raw `(un)correctable_status`
/// register value the bus driver decoded; `severity` is the
/// classification derived from it.
#[derive(Copy, Clone, Debug)]
pub struct AerEvent {
    pub addr: BusAddr,
    pub severity: AerSeverity,
    pub status_word: u32,
}

/// Subscriber interface. Listeners are `Send + Sync` so the AER
/// IRQ handler can fan out from the root-port interrupt directly.
pub trait AerListener: Send + Sync {
    fn on_aer(&self, ev: AerEvent);
}

static AER_LISTENERS: narf_lib::sync::IrqSafeSpinLock<Vec<Arc<dyn AerListener>>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());

/// Register an AER listener. Not cap-gated today — error
/// observation is considered system-wide telemetry rather than
/// a privileged operation; if that policy changes, the gate
/// becomes a `Cap<BusRegistryCap, Grant>` like hot-plug.
pub fn register_aer_listener(listener: Arc<dyn AerListener>) {
    AER_LISTENERS.lock().push(listener);
}

/// Fire an AER event to every registered listener. Called from
/// the bus driver after it has decoded the status word + cleared
/// the RW1C bits in the device's AER capability.
pub fn dispatch_aer(ev: AerEvent) {
    let list: Vec<Arc<dyn AerListener>> = {
        let g = AER_LISTENERS.lock();
        g.clone()
    };
    for l in list.iter() {
        l.on_aer(ev);
    }
}

/// Number of currently-registered AER listeners — useful for tests.
pub fn aer_listener_count() -> usize {
    AER_LISTENERS.lock().len()
}

#[doc(hidden)]
pub fn __clear_aer_listeners() {
    AER_LISTENERS.lock().clear();
}

/// Classify a raw AER status word + severity-mask pair into an
/// `AerSeverity`. Returns `None` if no error bits are set.
pub fn classify_aer(
    uncorr_status: u32,
    uncorr_severity: u32,
    corr_status: u32,
) -> Option<AerSeverity> {
    if corr_status != 0 {
        return Some(AerSeverity::Correctable);
    }
    if uncorr_status == 0 {
        return None;
    }
    if uncorr_status & uncorr_severity != 0 {
        Some(AerSeverity::Fatal)
    } else {
        Some(AerSeverity::NonFatal)
    }
}

// ── helpers ─────────────────────────────────────────────────────────

#[inline]
unsafe fn cfg_read32(cfg: PhysAddr, off: u64) -> u32 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is readable + 4-byte aligned.
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u32) };
    compiler_fence(Ordering::SeqCst);
    v
}
