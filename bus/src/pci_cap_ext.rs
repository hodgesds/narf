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
    /// PASID (Process Address Space ID) — PCIe Base §7.9.6.
    pub const PASID: u16 = 0x001B;
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
        // SAFETY: Valid memory or trusted environment
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

// ── AER bit definitions (PCIe §7.8.4.2 / §7.8.4.5) ────────────────

/// Uncorrectable Error Status / Mask / Severity bit definitions.
/// Same bit positions across all three registers (§7.8.4.2..§7.8.4.4).
pub mod aer_uncorrectable {
    /// Data Link Protocol Error.
    pub const DLP: u32 = 1 << 4;
    /// Surprise Down Error (link).
    pub const SURPRISE_DOWN: u32 = 1 << 5;
    /// Poisoned TLP Received.
    pub const POISONED_TLP: u32 = 1 << 12;
    /// Flow Control Protocol Error.
    pub const FLOW_CTRL_PROTO: u32 = 1 << 13;
    /// Completion Timeout.
    pub const COMPLETION_TIMEOUT: u32 = 1 << 14;
    /// Completer Abort.
    pub const COMPLETER_ABORT: u32 = 1 << 15;
    /// Unexpected Completion.
    pub const UNEXPECTED_COMPLETION: u32 = 1 << 16;
    /// Receiver Overflow.
    pub const RECEIVER_OVERFLOW: u32 = 1 << 17;
    /// Malformed TLP.
    pub const MALFORMED_TLP: u32 = 1 << 18;
    /// ECRC Error.
    pub const ECRC_ERROR: u32 = 1 << 19;
    /// Unsupported Request Error.
    pub const UNSUPPORTED_REQUEST: u32 = 1 << 20;
    /// ACS Violation.
    pub const ACS_VIOLATION: u32 = 1 << 21;
    /// Uncorrectable Internal Error.
    pub const INTERNAL_ERROR: u32 = 1 << 22;
    /// MC Blocked TLP.
    pub const MC_BLOCKED_TLP: u32 = 1 << 23;
    /// AtomicOp Egress Blocked.
    pub const ATOMIC_OP_EGRESS_BLOCKED: u32 = 1 << 24;
    /// TLP Prefix Blocked Error.
    pub const TLP_PREFIX_BLOCKED: u32 = 1 << 25;
}

/// Correctable Error Status / Mask bit definitions (§7.8.4.5/7.8.4.6).
pub mod aer_correctable {
    /// Receiver Error.
    pub const RECEIVER_ERROR: u32 = 1 << 0;
    /// Bad TLP.
    pub const BAD_TLP: u32 = 1 << 6;
    /// Bad DLLP.
    pub const BAD_DLLP: u32 = 1 << 7;
    /// REPLAY_NUM Rollover.
    pub const REPLAY_NUM_ROLLOVER: u32 = 1 << 8;
    /// Replay Timer Timeout.
    pub const REPLAY_TIMER_TIMEOUT: u32 = 1 << 12;
    /// Advisory Non-Fatal Error.
    pub const ADVISORY_NON_FATAL: u32 = 1 << 13;
    /// Corrected Internal Error.
    pub const CORRECTED_INTERNAL: u32 = 1 << 14;
    /// Header Log Overflow.
    pub const HEADER_LOG_OVERFLOW: u32 = 1 << 15;
}

/// AER register offsets within the extended capability.
pub mod aer_off {
    pub const UNCORR_STATUS: u64 = 0x04;
    pub const UNCORR_MASK: u64 = 0x08;
    pub const UNCORR_SEVERITY: u64 = 0x0C;
    pub const CORR_STATUS: u64 = 0x10;
    pub const CORR_MASK: u64 = 0x14;
    pub const CAPS_AND_CTRL: u64 = 0x18;
    pub const HEADER_LOG: u64 = 0x1C;
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

// ── AER mutating ops (status clear + mask program) ────────────────

/// Errors mutating AER state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AerWriteError {
    AuthorityRevoked,
    NotPcie,
    NoAer,
}

impl From<CapError> for AerWriteError {
    fn from(_: CapError) -> Self {
        AerWriteError::AuthorityRevoked
    }
}

/// Clear AER status bits by writing 1s to the `bits` mask
/// (RW1C semantics per PCIe §7.8.4.2 / §7.8.4.5). Caller picks
/// `correctable=true` to clear bits in CORR_STATUS, `false` for
/// UNCORR_STATUS.
///
/// Cap-gated on `Cap<BusDeviceCap, narf_capabilities::Write>` since
/// clearing sticky AER status is a privileged operation — only the
/// AER consumer (the global error coordinator or the bound driver)
/// should clear bits it has already observed.
pub fn clear_aer_status(
    cap: &Cap<BusDeviceCap, narf_capabilities::Write>,
    device: &BusDevice,
    correctable: bool,
    bits: u32,
) -> Result<(), AerWriteError> {
    cap.check_live()?;
    let cfg = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. } => return Err(AerWriteError::NotPcie),
    };
    let read_cap: Cap<BusDeviceCap, Read> = cap
        .derive::<Read>()
        .map_err(|_| AerWriteError::AuthorityRevoked)?;
    let hdr =
        match find_cap(&read_cap, device, id::AER).map_err(|_| AerWriteError::AuthorityRevoked)? {
            Some(h) => h,
            None => return Err(AerWriteError::NoAer),
        };
    let off = if correctable {
        aer_off::CORR_STATUS
    } else {
        aer_off::UNCORR_STATUS
    };
    // SAFETY: AER cap offset comes from the validated walker; cfg
    // page is identity-mapped.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        cfg_write32(cfg, hdr.offset + off, bits);
    }
    Ok(())
}

/// Program the AER mask register. Bits set = error class is
/// suppressed (won't surface in Status). Common policy: leave
/// Advisory Non-Fatal masked but keep everything else live.
pub fn set_aer_mask(
    cap: &Cap<BusDeviceCap, narf_capabilities::Write>,
    device: &BusDevice,
    correctable: bool,
    mask: u32,
) -> Result<(), AerWriteError> {
    cap.check_live()?;
    let cfg = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. } => return Err(AerWriteError::NotPcie),
    };
    let read_cap: Cap<BusDeviceCap, Read> = cap
        .derive::<Read>()
        .map_err(|_| AerWriteError::AuthorityRevoked)?;
    let hdr =
        match find_cap(&read_cap, device, id::AER).map_err(|_| AerWriteError::AuthorityRevoked)? {
            Some(h) => h,
            None => return Err(AerWriteError::NoAer),
        };
    let off = if correctable {
        aer_off::CORR_MASK
    } else {
        aer_off::UNCORR_MASK
    };
    // SAFETY: same as above.
    unsafe {
        cfg_write32(cfg, hdr.offset + off, mask);
    }
    Ok(())
}

/// Set the Uncorrectable Error Severity register. Bits set →
/// classified as Fatal; bits clear → NonFatal. PCIe §7.8.4.4.
pub fn set_aer_severity(
    cap: &Cap<BusDeviceCap, narf_capabilities::Write>,
    device: &BusDevice,
    severity: u32,
) -> Result<(), AerWriteError> {
    cap.check_live()?;
    let cfg = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. } => return Err(AerWriteError::NotPcie),
    };
    let read_cap: Cap<BusDeviceCap, Read> = cap
        .derive::<Read>()
        .map_err(|_| AerWriteError::AuthorityRevoked)?;
    let hdr =
        match find_cap(&read_cap, device, id::AER).map_err(|_| AerWriteError::AuthorityRevoked)? {
            Some(h) => h,
            None => return Err(AerWriteError::NoAer),
        };
    // SAFETY: same as above.
    unsafe {
        cfg_write32(cfg, hdr.offset + aer_off::UNCORR_SEVERITY, severity);
    }
    Ok(())
}

#[inline]
unsafe fn cfg_write32(cfg: PhysAddr, off: u64, value: u32) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is writable + 4-byte aligned.
    unsafe {
        if let Some(p) = crate::ecam::ptr_for(cfg, off) {
            core::ptr::write_volatile(p as *mut u32, value);
        };
    }
    compiler_fence(Ordering::SeqCst);
}

// ── helpers ─────────────────────────────────────────────────────────

#[inline]
unsafe fn cfg_read32(cfg: PhysAddr, off: u64) -> u32 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is readable + 4-byte aligned.
    let v = unsafe {
        match crate::ecam::ptr_for(cfg, off) {
            Some(p) => core::ptr::read_volatile(p as *const u32),
            None => u32::MAX,
        }
    };
    compiler_fence(Ordering::SeqCst);
    v
}

// ── DPC (Downstream Port Containment) — PCIe Base §7.9.14 ──────────
//
// DPC is a per-downstream-port containment mechanism: when an
// uncorrectable error happens on a link below a DPC-capable
// switch port, the port automatically blocks all subsequent
// transactions to/from that link, captures the first error, and
// signals the host. Pairs with AER — AER reports the error;
// DPC stops the bleed.
//
// Register layout (offsets relative to the DPC ext-cap header):
//
//   +0x00  Extended Cap Header                  (32-bit, generic)
//   +0x04  DPC Capability                       (16-bit)
//   +0x06  DPC Control                          (16-bit)
//   +0x08  DPC Status                           (16-bit)
//   +0x0A  DPC Error Source ID                  (16-bit)
//   +0x0C  RP PIO Status                        (32-bit, RPEXT only)
//   +0x10  RP PIO Mask                          (32-bit, RPEXT only)
//   +0x14  RP PIO Severity                      (32-bit, RPEXT only)
//   +0x18  RP PIO SysError                      (32-bit, RPEXT only)
//   +0x1C  RP PIO Exception                     (32-bit, RPEXT only)
//   +0x20  RP PIO Header Log                    (16 bytes, RPEXT only)

/// DPC register offsets within the extended capability.
pub mod dpc_off {
    pub const CAP: u64 = 0x04;
    pub const CTRL: u64 = 0x06;
    pub const STATUS: u64 = 0x08;
    pub const ERR_SOURCE_ID: u64 = 0x0A;
    pub const RP_PIO_STATUS: u64 = 0x0C;
    pub const RP_PIO_MASK: u64 = 0x10;
    pub const RP_PIO_SEVERITY: u64 = 0x14;
}

/// DPC Capability bits (PCIe §7.9.14.2).
pub mod dpc_cap {
    /// DPC Interrupt Message Number (bits[4:0]).
    pub const INT_MSG_NUM_MASK: u16 = 0x001F;
    /// RP Extensions for DPC supported (bit 5).
    pub const RP_EXTENSIONS: u16 = 1 << 5;
    /// Poisoned TLP Egress Blocking supported (bit 6).
    pub const POISONED_TLP_EGRESS_BLOCKING: u16 = 1 << 6;
    /// DPC Software Triggering supported (bit 7).
    pub const SW_TRIGGERING: u16 = 1 << 7;
    /// RP PIO Log Size (bits[11:8]) — number of dwords.
    pub const RP_PIO_LOG_SIZE_SHIFT: u32 = 8;
    pub const RP_PIO_LOG_SIZE_MASK: u16 = 0xF << 8;
    /// DL_Active ERR_COR Signaling supported (bit 12).
    pub const DL_ACTIVE_ERR_COR: u16 = 1 << 12;
}

/// DPC Control bits (PCIe §7.9.14.3).
pub mod dpc_ctrl {
    /// DPC Trigger Enable (bits[1:0]): 00=disabled, 01=enabled
    /// for ERR_NONFATAL/ERR_FATAL, 10=enabled for ERR_FATAL only.
    pub const TRIGGER_EN_MASK: u16 = 0x0003;
    pub const TRIGGER_EN_DISABLED: u16 = 0b00;
    pub const TRIGGER_EN_NONFATAL_FATAL: u16 = 0b01;
    pub const TRIGGER_EN_FATAL_ONLY: u16 = 0b10;
    /// DPC Completion Control (bit 2).
    pub const COMPLETION_CTRL: u16 = 1 << 2;
    /// DPC Interrupt Enable (bit 3).
    pub const INT_ENABLE: u16 = 1 << 3;
    /// DPC ERR_COR Enable (bit 4).
    pub const ERR_COR_ENABLE: u16 = 1 << 4;
    /// Poisoned TLP Egress Blocking Enable (bit 5).
    pub const POISONED_TLP_EGRESS_BLOCKING_EN: u16 = 1 << 5;
    /// DPC Software Trigger (write-only, bit 6).
    pub const SW_TRIGGER: u16 = 1 << 6;
    /// DL_Active ERR_COR Enable (bit 7).
    pub const DL_ACTIVE_ERR_COR_EN: u16 = 1 << 7;
}

/// DPC Status bits (PCIe §7.9.14.4).
pub mod dpc_status {
    /// DPC Trigger Status (RW1C, bit 0) — set when DPC has
    /// triggered.
    pub const TRIGGER_STATUS: u16 = 1 << 0;
    /// DPC Trigger Reason (bits[2:1]): 00=ERR_NONFATAL,
    /// 01=ERR_FATAL, 10=RP PIO, 11=software trigger.
    pub const TRIGGER_REASON_MASK: u16 = 0x0006;
    pub const TRIGGER_REASON_NONFATAL: u16 = 0b00 << 1;
    pub const TRIGGER_REASON_FATAL: u16 = 0b01 << 1;
    pub const TRIGGER_REASON_RP_PIO: u16 = 0b10 << 1;
    pub const TRIGGER_REASON_SW: u16 = 0b11 << 1;
    /// DPC Interrupt Status (RW1C, bit 3).
    pub const INT_STATUS: u16 = 1 << 3;
    /// DPC RP Busy (bit 4) — port is still draining.
    pub const RP_BUSY: u16 = 1 << 4;
    /// DPC Trigger Reason Extension (bits[6:5]): 00=undefined,
    /// 01=memory request received with ATC entry,
    /// 10..11=reserved.
    pub const TRIGGER_REASON_EXT_MASK: u16 = 0x0060;
}

/// Decoded DPC snapshot. PCIe §7.9.14.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpcStatus {
    /// `DPC Capability` (RO) — features the port advertises.
    pub capability: u16,
    /// `DPC Control` (RW) — currently-programmed knobs.
    pub control: u16,
    /// `DPC Status` (mixed RW1C/RO) — current trigger state.
    pub status: u16,
    /// `DPC Error Source ID` — Requester ID of the device that
    /// caused the trigger; meaningful only after a trigger.
    pub error_source_id: u16,
}

impl DpcStatus {
    /// `true` when DPC has triggered and not yet been cleared.
    pub fn triggered(&self) -> bool {
        self.status & dpc_status::TRIGGER_STATUS != 0
    }
    /// The 2-bit Trigger Reason field, masked & shifted.
    pub fn trigger_reason(&self) -> u16 {
        (self.status & dpc_status::TRIGGER_REASON_MASK) >> 1
    }
}

/// Read the device's DPC status if the DPC extended cap exists.
pub fn read_dpc(
    cap: &Cap<BusDeviceCap, Read>,
    device: &BusDevice,
) -> Result<Option<DpcStatus>, ExtCapError> {
    let Some(h) = find_cap(cap, device, id::DPC)? else {
        return Ok(None);
    };
    let cfg = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. } => return Err(ExtCapError::NotPcie),
    };
    // CAP+CTRL share a 32-bit dword, as do STATUS+ERR_SOURCE_ID.
    // SAFETY: cfg page is identity-mapped; offsets in range.
    let (capability, control, status, esid) = unsafe {
        let cap_ctrl = cfg_read32(cfg, h.offset + dpc_off::CAP);
        let stat_esid = cfg_read32(cfg, h.offset + dpc_off::STATUS);
        (
            (cap_ctrl & 0xFFFF) as u16,
            (cap_ctrl >> 16) as u16,
            (stat_esid & 0xFFFF) as u16,
            (stat_esid >> 16) as u16,
        )
    };
    Ok(Some(DpcStatus {
        capability,
        control,
        status,
        error_source_id: esid,
    }))
}

// ── ATS (Address Translation Services) — PCIe Base §7.9.4 ──────────
//
// ATS lets an endpoint cache IOMMU translations. The host driver
// is interested in:
//
//   - "Smallest Translation Unit" — the granularity of cached
//     translations the endpoint supports, in units of pages.
//   - "Invalidate Queue Depth" — how many in-flight invalidate
//     requests the endpoint can absorb.
//   - "Enable" / "Cache Disable" — runtime control.
//
// Register layout:
//
//   +0x00 Extended Cap Header
//   +0x04 ATS Capability    (16-bit)
//   +0x06 ATS Control       (16-bit)

/// ATS register offsets.
pub mod ats_off {
    pub const CAP: u64 = 0x04;
    pub const CTRL: u64 = 0x06;
}

/// ATS Capability bits (PCIe §7.9.4.2).
pub mod ats_cap {
    /// Invalidate Queue Depth (bits[4:0]). 0 = no queue.
    pub const INVALIDATE_QUEUE_DEPTH_MASK: u16 = 0x001F;
    /// Page Aligned Request supported (bit 5).
    pub const PAGE_ALIGNED_REQUEST: u16 = 1 << 5;
    /// Global Invalidate supported (bit 6).
    pub const GLOBAL_INVALIDATE: u16 = 1 << 6;
    /// Relaxed Ordering supported (bit 7).
    pub const RELAXED_ORDERING: u16 = 1 << 7;
}

/// ATS Control bits (PCIe §7.9.4.3).
pub mod ats_ctrl {
    /// Smallest Translation Unit (bits[4:0]) — log2(pages) the
    /// endpoint will translate as one unit. 0 = single page.
    pub const STU_MASK: u16 = 0x001F;
    /// Enable (bit 15).
    pub const ENABLE: u16 = 1 << 15;
}

/// Decoded ATS snapshot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AtsStatus {
    pub capability: u16,
    pub control: u16,
}

impl AtsStatus {
    pub fn invalidate_queue_depth(&self) -> u8 {
        (self.capability & ats_cap::INVALIDATE_QUEUE_DEPTH_MASK) as u8
    }
    pub fn smallest_translation_unit_log2(&self) -> u8 {
        (self.control & ats_ctrl::STU_MASK) as u8
    }
    pub fn enabled(&self) -> bool {
        self.control & ats_ctrl::ENABLE != 0
    }
}

/// Read the device's ATS status if the ATS extended cap exists.
pub fn read_ats(
    cap: &Cap<BusDeviceCap, Read>,
    device: &BusDevice,
) -> Result<Option<AtsStatus>, ExtCapError> {
    let Some(h) = find_cap(cap, device, id::ATS)? else {
        return Ok(None);
    };
    let cfg = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. } => return Err(ExtCapError::NotPcie),
    };
    // CAP+CTRL share a 32-bit dword.
    // SAFETY: cfg page is identity-mapped.
    let dword = unsafe { cfg_read32(cfg, h.offset + ats_off::CAP) };
    Ok(Some(AtsStatus {
        capability: (dword & 0xFFFF) as u16,
        control: (dword >> 16) as u16,
    }))
}

// ── ACS (Access Control Services) — PCIe Base §7.9.5 ──────────────
//
// ACS is the IOMMU-side guarantee that peer-to-peer transactions
// are routed through the root complex (so the IOMMU sees them).
// Without ACS, two devices behind the same switch port can
// DMA-talk to each other invisibly to the IOMMU — a serious
// isolation hole for VFIO-style passthrough.
//
// Register layout:
//
//   +0x00 Extended Cap Header
//   +0x04 ACS Capability   (16-bit)
//   +0x06 ACS Control      (16-bit)
//   +0x08 Egress Control Vector  (variable, ECV-bit-set only)

/// ACS register offsets.
pub mod acs_off {
    pub const CAP: u64 = 0x04;
    pub const CTRL: u64 = 0x06;
    pub const EGRESS_CTRL_VECTOR: u64 = 0x08;
}

/// ACS Capability bits (PCIe §7.9.5.2). Each bit indicates
/// whether the corresponding feature is *supported*.
pub mod acs_cap {
    /// ACS Source Validation (bit 0).
    pub const SOURCE_VALIDATION: u16 = 1 << 0;
    /// ACS Translation Blocking (bit 1).
    pub const TRANSLATION_BLOCKING: u16 = 1 << 1;
    /// ACS P2P Request Redirect (bit 2) — the load-bearing bit
    /// for IOMMU isolation.
    pub const P2P_REQUEST_REDIRECT: u16 = 1 << 2;
    /// ACS P2P Completion Redirect (bit 3).
    pub const P2P_COMPLETION_REDIRECT: u16 = 1 << 3;
    /// ACS Upstream Forwarding (bit 4).
    pub const UPSTREAM_FORWARDING: u16 = 1 << 4;
    /// ACS P2P Egress Control (bit 5).
    pub const P2P_EGRESS_CONTROL: u16 = 1 << 5;
    /// ACS Direct Translated P2P (bit 6).
    pub const DIRECT_TRANSLATED_P2P: u16 = 1 << 6;
    /// Egress Control Vector Size (bits[15:8]).
    pub const ECV_SIZE_SHIFT: u32 = 8;
    pub const ECV_SIZE_MASK: u16 = 0xFF << 8;
}

/// ACS Control bits (PCIe §7.9.5.3). Same bit positions as
/// `acs_cap`, but here each bit *enables* the corresponding
/// feature.
pub mod acs_ctrl {
    pub const SOURCE_VALIDATION_EN: u16 = 1 << 0;
    pub const TRANSLATION_BLOCKING_EN: u16 = 1 << 1;
    pub const P2P_REQUEST_REDIRECT_EN: u16 = 1 << 2;
    pub const P2P_COMPLETION_REDIRECT_EN: u16 = 1 << 3;
    pub const UPSTREAM_FORWARDING_EN: u16 = 1 << 4;
    pub const P2P_EGRESS_CONTROL_EN: u16 = 1 << 5;
    pub const DIRECT_TRANSLATED_P2P_EN: u16 = 1 << 6;
}

/// Decoded ACS snapshot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AcsStatus {
    pub capability: u16,
    pub control: u16,
}

impl AcsStatus {
    /// `true` when the port enforces P2P request redirection —
    /// the canonical "ACS is doing its job" check used by VFIO.
    pub fn p2p_isolation_enabled(&self) -> bool {
        self.control & acs_ctrl::P2P_REQUEST_REDIRECT_EN != 0
    }
    /// Egress Control Vector size (number of valid bits in the
    /// downstream Egress Control Vector that follows).
    pub fn egress_control_vector_size(&self) -> u8 {
        ((self.capability & acs_cap::ECV_SIZE_MASK) >> acs_cap::ECV_SIZE_SHIFT) as u8
    }
}

/// Read the device's ACS status if the ACS extended cap exists.
pub fn read_acs(
    cap: &Cap<BusDeviceCap, Read>,
    device: &BusDevice,
) -> Result<Option<AcsStatus>, ExtCapError> {
    let Some(h) = find_cap(cap, device, id::ACS)? else {
        return Ok(None);
    };
    let cfg = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. } => return Err(ExtCapError::NotPcie),
    };
    // SAFETY: cfg page is identity-mapped.
    let dword = unsafe { cfg_read32(cfg, h.offset + acs_off::CAP) };
    Ok(Some(AcsStatus {
        capability: (dword & 0xFFFF) as u16,
        control: (dword >> 16) as u16,
    }))
}

// ── PASID (Process Address Space ID) — PCIe Base §7.9.6 ───────────
//
// PASID lets an endpoint tag its DMA requests with a process-
// space identifier so the IOMMU walks the right page table per-
// process. Supports SVM (Shared Virtual Memory) for accelerators
// (GPUs, NPUs).
//
// Register layout:
//
//   +0x00 Extended Cap Header
//   +0x04 PASID Capability   (16-bit)
//   +0x06 PASID Control      (16-bit)

/// PASID register offsets.
pub mod pasid_off {
    pub const CAP: u64 = 0x04;
    pub const CTRL: u64 = 0x06;
}

/// PASID Capability bits (PCIe §7.9.6.2).
pub mod pasid_cap {
    /// Execute Permission Supported (bit 1).
    pub const EXECUTE_SUPPORTED: u16 = 1 << 1;
    /// Privileged Mode Supported (bit 2).
    pub const PRIVILEGED_SUPPORTED: u16 = 1 << 2;
    /// Max PASID Width (bits[12:8]) — log2 of max PASID values.
    pub const MAX_PASID_WIDTH_SHIFT: u32 = 8;
    pub const MAX_PASID_WIDTH_MASK: u16 = 0x1F << 8;
}

/// PASID Control bits (PCIe §7.9.6.3).
pub mod pasid_ctrl {
    /// PASID Enable (bit 0).
    pub const ENABLE: u16 = 1 << 0;
    /// Execute Permission Enable (bit 1).
    pub const EXECUTE_ENABLE: u16 = 1 << 1;
    /// Privileged Mode Enable (bit 2).
    pub const PRIVILEGED_ENABLE: u16 = 1 << 2;
}

/// Decoded PASID snapshot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PasidStatus {
    pub capability: u16,
    pub control: u16,
}

impl PasidStatus {
    pub fn max_pasid_width(&self) -> u8 {
        ((self.capability & pasid_cap::MAX_PASID_WIDTH_MASK) >> pasid_cap::MAX_PASID_WIDTH_SHIFT)
            as u8
    }
    pub fn enabled(&self) -> bool {
        self.control & pasid_ctrl::ENABLE != 0
    }
}

/// Read the device's PASID status if the PASID extended cap exists.
pub fn read_pasid(
    cap: &Cap<BusDeviceCap, Read>,
    device: &BusDevice,
) -> Result<Option<PasidStatus>, ExtCapError> {
    let Some(h) = find_cap(cap, device, id::PASID)? else {
        return Ok(None);
    };
    let cfg = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. } => return Err(ExtCapError::NotPcie),
    };
    // SAFETY: cfg page is identity-mapped.
    let dword = unsafe { cfg_read32(cfg, h.offset + pasid_off::CAP) };
    Ok(Some(PasidStatus {
        capability: (dword & 0xFFFF) as u16,
        control: (dword >> 16) as u16,
    }))
}

#[cfg(any(test, feature = "kernel-test"))]
mod ext_cap_codec_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_dpc_status_field_decode() -> TestResult {
        let s = DpcStatus {
            capability: dpc_cap::SW_TRIGGERING | dpc_cap::POISONED_TLP_EGRESS_BLOCKING,
            control: dpc_ctrl::INT_ENABLE | dpc_ctrl::TRIGGER_EN_NONFATAL_FATAL,
            status: dpc_status::TRIGGER_STATUS | dpc_status::TRIGGER_REASON_FATAL,
            error_source_id: 0xABCD,
        };
        if !s.triggered() {
            return TestResult::Fail("triggered() should be true");
        }
        if s.trigger_reason() != 0b01 {
            return TestResult::Fail("trigger_reason should be Fatal (0b01)");
        }
        TestResult::Pass
    }
    kernel_test_in!("bus/pci_cap_ext", smoke_dpc_status_field_decode);

    fn smoke_ats_field_decode() -> TestResult {
        let s = AtsStatus {
            capability: 0x0008,                 // Invalidate Queue Depth = 8
            control: ats_ctrl::ENABLE | 0x0004, // STU=4, enabled
        };
        if s.invalidate_queue_depth() != 8 {
            return TestResult::Fail("queue depth wrong");
        }
        if s.smallest_translation_unit_log2() != 4 {
            return TestResult::Fail("STU wrong");
        }
        if !s.enabled() {
            return TestResult::Fail("enabled bit lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("bus/pci_cap_ext", smoke_ats_field_decode);

    fn smoke_acs_field_decode() -> TestResult {
        let cap_word = acs_cap::P2P_REQUEST_REDIRECT
            | acs_cap::P2P_COMPLETION_REDIRECT
            | (4u16 << acs_cap::ECV_SIZE_SHIFT);
        let s = AcsStatus {
            capability: cap_word,
            control: acs_ctrl::P2P_REQUEST_REDIRECT_EN | acs_ctrl::P2P_COMPLETION_REDIRECT_EN,
        };
        if !s.p2p_isolation_enabled() {
            return TestResult::Fail("P2P isolation should be enabled");
        }
        if s.egress_control_vector_size() != 4 {
            return TestResult::Fail("ECV size wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("bus/pci_cap_ext", smoke_acs_field_decode);

    fn smoke_pasid_field_decode() -> TestResult {
        let cap_word = pasid_cap::EXECUTE_SUPPORTED
            | pasid_cap::PRIVILEGED_SUPPORTED
            | (20u16 << pasid_cap::MAX_PASID_WIDTH_SHIFT); // 1M PASIDs
        let s = PasidStatus {
            capability: cap_word,
            control: pasid_ctrl::ENABLE | pasid_ctrl::EXECUTE_ENABLE,
        };
        if s.max_pasid_width() != 20 {
            return TestResult::Fail("max PASID width wrong");
        }
        if !s.enabled() {
            return TestResult::Fail("enable bit lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("bus/pci_cap_ext", smoke_pasid_field_decode);
}
