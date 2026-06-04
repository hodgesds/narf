//! PCIe Downstream Port Containment (DPC) actuation.
//!
//! DPC freezes the link below a Root Port / Switch Downstream Port
//! the moment a fatal error message comes through, preventing the
//! error from propagating upstream and corrupting more state. The
//! port hardware does this automatically; software's job is to (a)
//! detect that DPC fired, (b) clear the latched state, and (c) run
//! the per-driver recovery callbacks so the link can come back.
//!
//! ## Sources
//!
//! - **PCIe Base Specification, Revision 6.0**, PCI-SIG —
//!   §7.9.14 (Downstream Port Containment Capability), §6.2.10
//!   (Containment-by-DPC interaction with AER).
//!   <https://pcisig.com/specifications>
//! - **Linux**, `drivers/pci/pcie/dpc.c` (DPC service driver,
//!   `dpc_handler` / `dpc_process_error` / `dpc_reset_link`),
//!   GPL-2.0. We mirror its register layout + actuation order.

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

use crate::pcie_aer::DPC_CAP_ID;

/// DPC register offsets within the DPC Extended Capability block.
///
/// Layout per PCIe 6.0 §7.9.14 Table 7-205. Offsets are relative
/// to the cap header (the one carrying `cap_id = 0x001D`).
pub mod regs {
    /// Extended Cap Header — `[15:0] cap_id, [19:16] cap_version,
    /// [31:20] next_ptr`. Same shape as every other extended cap.
    pub const HEADER: u16 = 0x00;
    /// DPC Capability — 16-bit. Feature bits + IRQ vector number.
    pub const CAPABILITY: u16 = 0x04;
    /// DPC Control — 16-bit. Enable bits + interrupt enable.
    pub const CONTROL: u16 = 0x06;
    /// DPC Status — 16-bit. TRIGGERED / TRIGGER REASON / Interrupt
    /// Status / RP Busy. RW1C semantics on TRIGGERED + INTERRUPT.
    pub const STATUS: u16 = 0x08;
    /// Error Source ID — 16-bit. BDF of the device whose error
    /// caused DPC to fire.
    pub const SOURCE_ID: u16 = 0x0A;
    // Root-Port-extensions-only registers — RP PIO error tracking.
    // We define the offsets for completeness; full RP PIO handling
    // is deferred.
    pub const RP_PIO_STATUS: u16 = 0x0C;
    pub const RP_PIO_MASK: u16 = 0x10;
    pub const RP_PIO_SEVERITY: u16 = 0x14;
}

/// DPC Capability bits (16-bit field at +0x04). PCIe 6.0 §7.9.14.2.
pub mod cap {
    /// `Interrupt Message Number` — bits[4:0]. Identifies which
    /// MSI / MSI-X vector DPC raises on.
    pub const IRQ_MASK: u16 = 0x001F;
    /// `RP Extensions for DPC Supported` — bit 5. If clear, the
    /// RP PIO error-tracking sub-block is RAZ.
    pub const RP_EXTENSIONS: u16 = 1 << 5;
    /// `Poisoned TLP Egress Blocking Supported` — bit 6.
    pub const POISONED_TLP: u16 = 1 << 6;
    /// `DPC Software Triggering Supported` — bit 7.
    pub const SW_TRIGGER: u16 = 1 << 7;
    /// `RP PIO Log Size` — bits[11:8]. Number of TLP-prefix words
    /// the RP PIO log can carry.
    pub const RP_PIO_LOG_SIZE_MASK: u16 = 0x0F00;
    /// `DL_Active ERR_COR Signaling Supported` — bit 12.
    pub const DL_ACTIVE_ERR_COR: u16 = 1 << 12;
}

/// DPC Control bits (16-bit at +0x06). PCIe 6.0 §7.9.14.3.
pub mod ctrl {
    /// `DPC Trigger Enable` — bits[1:0]. Controls which AER classes
    /// fire DPC: 0 = disabled, 1 = on Fatal, 2 = on Non-Fatal or
    /// Fatal. We program 1 (Fatal only) to mirror Linux's default.
    pub const TRIGGER_MASK: u16 = 0x0003;
    /// Enable DPC on ERR_FATAL messages.
    pub const EN_FATAL: u16 = 0x0001;
    /// Enable DPC on ERR_NONFATAL messages (additionally to fatal).
    pub const EN_NONFATAL: u16 = 0x0002;
    /// `DPC Interrupt Enable` — bit 3.
    pub const INT_EN: u16 = 1 << 3;
    /// `DPC ERR_COR Enable` — bit 4. Generate ERR_COR upstream when
    /// DPC fires (for diagnostic visibility on RPs that aren't the
    /// platform-default error sink).
    pub const ERR_COR_EN: u16 = 1 << 4;
    /// `DPC Software Trigger` — bit 6 (RW; SW triggers DPC).
    pub const SW_TRIGGER: u16 = 1 << 6;
}

/// DPC Status bits (16-bit at +0x08). PCIe 6.0 §7.9.14.4.
pub mod sts {
    /// `DPC Trigger Status` — bit 0. RW1C; set when DPC has fired
    /// on this port.
    pub const TRIGGERED: u16 = 1 << 0;
    /// `DPC Trigger Reason` — bits[2:1]. Encoded reason for the
    /// containment event.
    pub const REASON_MASK: u16 = 0x0006;
    /// Reason = 0: unmasked uncorrectable error.
    pub const REASON_UNCOR: u16 = 0x0000;
    /// Reason = 1: ERR_NONFATAL message received.
    pub const REASON_NFE: u16 = 0x0002;
    /// Reason = 2: ERR_FATAL message received.
    pub const REASON_FE: u16 = 0x0004;
    /// Reason = 3: reason in the extension field (DL Protocol Error
    /// or RP PIO error).
    pub const REASON_EXT: u16 = 0x0006;
    /// `DPC Interrupt Status` — bit 3. RW1C.
    pub const INTERRUPT: u16 = 1 << 3;
    /// `DPC RP Busy` — bit 4. Cleared once the port has fully
    /// quiesced internal state after DPC.
    pub const RP_BUSY: u16 = 1 << 4;
    /// `DPC Trigger Reason Extension` — bits[6:5]. Only meaningful
    /// when `REASON_MASK == REASON_EXT`.
    pub const REASON_EXT_MASK: u16 = 0x0060;
    /// Extension = 0: RP PIO error.
    pub const REASON_EXT_RP_PIO: u16 = 0x0000;
    /// Extension = 1: software triggered DPC.
    pub const REASON_EXT_SW: u16 = 0x0020;
}

/// Decoded DPC Status word.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpcStatus {
    /// Raw 16-bit register value.
    pub raw: u16,
    /// `TRIGGERED` bit — DPC fired since last clear.
    pub triggered: bool,
    /// `INTERRUPT` bit — DPC raised an MSI.
    pub interrupt: bool,
    /// `RP_BUSY` bit — root port is still draining internal state.
    pub rp_busy: bool,
    /// Decoded trigger reason.
    pub reason: DpcReason,
}

/// Why DPC fired.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DpcReason {
    /// Unmasked uncorrectable error detected by this port. Look at
    /// AER UE Status for the bit.
    Uncorrectable,
    /// ERR_NONFATAL message arrived from downstream.
    NonFatal,
    /// ERR_FATAL message arrived from downstream.
    Fatal,
    /// RP PIO error — root port's outbound configuration / IO /
    /// memory request got an UR or CA completion. Driver hint:
    /// link corruption suspected, log + leave down.
    RpPioError,
    /// Software triggered DPC via the SW Trigger bit.
    SoftwareTrigger,
    /// Spec-reserved encoding; we still surface it so unexpected
    /// hardware values don't silently disappear.
    Reserved,
}

impl DpcReason {
    /// Decode the 2-bit Reason + 2-bit Reason Extension.
    pub fn decode(status: u16) -> Self {
        match status & sts::REASON_MASK {
            sts::REASON_UNCOR => DpcReason::Uncorrectable,
            sts::REASON_NFE => DpcReason::NonFatal,
            sts::REASON_FE => DpcReason::Fatal,
            sts::REASON_EXT => match status & sts::REASON_EXT_MASK {
                sts::REASON_EXT_RP_PIO => DpcReason::RpPioError,
                sts::REASON_EXT_SW => DpcReason::SoftwareTrigger,
                _ => DpcReason::Reserved,
            },
            _ => DpcReason::Reserved,
        }
    }
}

impl DpcStatus {
    pub fn decode(raw: u16) -> Self {
        Self {
            raw,
            triggered: raw & sts::TRIGGERED != 0,
            interrupt: raw & sts::INTERRUPT != 0,
            rp_busy: raw & sts::RP_BUSY != 0,
            reason: DpcReason::decode(raw),
        }
    }

    /// `true` if the reason indicates DL Protocol corruption — caller
    /// should leave the link down rather than running recovery, per
    /// PCIe 6.0 §6.2.10.
    pub fn is_dl_protocol_error(&self) -> bool {
        self.reason == DpcReason::RpPioError
    }
}

// ── Diagnostic counters ───────────────────────────────────────────

/// Bumped by `dpc_isr` each time a DPC event is processed. Exposed
/// for tests and `/proc`-style observability paths.
pub static DPC_TRIGGER_COUNT: AtomicU64 = AtomicU64::new(0);

/// Bumped when DPC fires for a reason we leave the link down on
/// (e.g. RP PIO / DL protocol errors).
pub static DPC_LINK_DOWN_COUNT: AtomicU64 = AtomicU64::new(0);

// ── Capability walk ───────────────────────────────────────────────

/// Walk the extended-cap list and return the byte-offset of the DPC
/// capability, or `None` if the port doesn't carry one.
///
/// # Safety
/// `cfg_phys` must point at a live, 4-KiB PCIe config page; the walk
/// only issues volatile reads.
pub unsafe fn find_dpc_cap_offset(cfg_phys: u64) -> Option<u16> {
    let mut off: u16 = 0x100;
    for _ in 0..256 {
        if off == 0 || off < 0x100 || off >= 0x1000 {
            return None;
        }
        // SAFETY: caller-asserted live config; offset bounded above.
        let hdr = unsafe { core::ptr::read_volatile((cfg_phys + off as u64) as *const u32) };
        if hdr == 0 || hdr == u32::MAX {
            return None;
        }
        let cap_id = (hdr & 0xFFFF) as u16;
        let next = ((hdr >> 20) & 0xFFF) as u16;
        if cap_id == DPC_CAP_ID {
            return Some(off);
        }
        if next == 0 {
            return None;
        }
        off = next;
    }
    None
}

// ── Status read + RW1C clear ──────────────────────────────────────

/// Read DPC Status, return the decoded snapshot, and clear the
/// RW1C bits (TRIGGERED + INTERRUPT).
///
/// Mirrors the head of Linux's `dpc_irq()`.
///
/// # Safety
/// `cfg_phys` live PCIe config; `dpc_off` from `find_dpc_cap_offset`.
pub unsafe fn read_and_clear_status(cfg_phys: u64, dpc_off: u16) -> DpcStatus {
    let ptr = (cfg_phys + dpc_off as u64 + regs::STATUS as u64) as *mut u16;
    // SAFETY: caller-asserted.
    let raw = unsafe { core::ptr::read_volatile(ptr as *const u16) };
    let snap = DpcStatus::decode(raw);
    // RW1C: write back the latched TRIGGERED / INTERRUPT bits to clear
    // them. RP_BUSY is RO and won't clear from a write.
    let rw1c = raw & (sts::TRIGGERED | sts::INTERRUPT);
    if rw1c != 0 {
        // SAFETY: same.
        unsafe { core::ptr::write_volatile(ptr, rw1c) };
    }
    snap
}

/// Read the Error Source ID (BDF of the offending device) latched
/// when DPC fired.
///
/// # Safety
/// Same as `read_and_clear_status`.
pub unsafe fn read_source_id(cfg_phys: u64, dpc_off: u16) -> u16 {
    // SAFETY: caller-asserted.
    unsafe {
        core::ptr::read_volatile((cfg_phys + dpc_off as u64 + regs::SOURCE_ID as u64) as *const u16)
    }
}

// ── DPC configuration ─────────────────────────────────────────────

/// Configure DPC on a Root Port / Downstream Port:
///   - Clear any pending Interrupt Status from a prior event.
///   - Enable trigger on ERR_FATAL (default).
///   - Enable DPC interrupt.
///
/// Mirrors Linux's `dpc_enable()` in `drivers/pci/pcie/dpc.c`.
///
/// # Safety
/// `cfg_phys` live PCIe config; `dpc_off` from walker.
pub unsafe fn configure_dpc(cfg_phys: u64, dpc_off: u16) {
    // SAFETY: caller-asserted.
    unsafe {
        // Clear pending INTERRUPT so a stale state doesn't fire as
        // soon as we enable the IRQ. TRIGGERED is left to RW1C
        // semantics — if it was set we still want the handler to see
        // it once we enable interrupts.
        core::ptr::write_volatile(
            (cfg_phys + dpc_off as u64 + regs::STATUS as u64) as *mut u16,
            sts::INTERRUPT,
        );
        // Read-modify-write CTL: clear TRIGGER mask, then OR in EN_FATAL
        // + INT_EN.
        let ctl_ptr = (cfg_phys + dpc_off as u64 + regs::CONTROL as u64) as *mut u16;
        let mut ctl = core::ptr::read_volatile(ctl_ptr as *const u16);
        ctl &= !ctrl::TRIGGER_MASK;
        ctl |= ctrl::EN_FATAL | ctrl::INT_EN;
        core::ptr::write_volatile(ctl_ptr, ctl);
    }
}

/// Disable DPC triggering + interrupts. Mirrors Linux's
/// `dpc_disable()`.
///
/// # Safety
/// Same as `configure_dpc`.
pub unsafe fn disable_dpc(cfg_phys: u64, dpc_off: u16) {
    // SAFETY: caller-asserted.
    unsafe {
        let ctl_ptr = (cfg_phys + dpc_off as u64 + regs::CONTROL as u64) as *mut u16;
        let mut ctl = core::ptr::read_volatile(ctl_ptr as *const u16);
        ctl &= !(ctrl::EN_FATAL | ctrl::EN_NONFATAL | ctrl::INT_EN);
        core::ptr::write_volatile(ctl_ptr, ctl);
    }
}

/// Clear TRIGGERED via RW1C — used after the recovery sequence has
/// completed and the link is back up. Mirrors the final step of
/// Linux's `dpc_reset_link()`.
///
/// # Safety
/// Same as `configure_dpc`.
pub unsafe fn clear_triggered(cfg_phys: u64, dpc_off: u16) {
    // SAFETY: caller-asserted.
    unsafe {
        core::ptr::write_volatile(
            (cfg_phys + dpc_off as u64 + regs::STATUS as u64) as *mut u16,
            sts::TRIGGERED,
        );
    }
}

// ── DPC ISR ───────────────────────────────────────────────────────

/// What the ISR observed. Returned to the caller so it can drive the
/// recovery state machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpcEvent {
    /// Per-port DPC status at the time of the IRQ.
    pub status: DpcStatus,
    /// BDF of the requester whose error caused DPC.
    pub source_id: u16,
    /// `true` if the caller should drive recovery; `false` if the
    /// reason was DL Protocol / RP PIO (link is gone, leave it down).
    pub run_recovery: bool,
}

/// DPC ISR — read the per-port status, clear RW1C bits, bump the
/// counters, and return the decoded event. Caller routes the
/// recovery via `pcie_recovery::do_recovery` with the link-reset
/// callback at [`reset_link`].
///
/// Mirrors Linux's `dpc_handler()` head; the heavy lifting (running
/// recovery for the affected subtree) is the caller's job here so the
/// bus crate stays free of driver-table assumptions.
///
/// # Safety
/// `cfg_phys` live PCIe config; `dpc_off` from `find_dpc_cap_offset`.
pub unsafe fn dpc_isr(cfg_phys: u64, dpc_off: u16) -> Option<DpcEvent> {
    // SAFETY: caller-asserted.
    let status = unsafe { read_and_clear_status(cfg_phys, dpc_off) };
    if !status.triggered {
        return None;
    }
    DPC_TRIGGER_COUNT.fetch_add(1, Ordering::Relaxed);
    // SAFETY: same.
    let source_id = unsafe { read_source_id(cfg_phys, dpc_off) };
    let run_recovery = !status.is_dl_protocol_error();
    if !run_recovery {
        DPC_LINK_DOWN_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    Some(DpcEvent {
        status,
        source_id,
        run_recovery,
    })
}

/// Drive the actual link-reset half of DPC recovery: clear TRIGGERED
/// (RW1C) so the port leaves DPC, then re-program the control word
/// to keep DPC armed for future events.
///
/// Mirrors Linux's `dpc_reset_link()` body (with `dpc_wait_rp_inactive`
/// + `pci_bridge_wait_for_secondary_bus` deferred to caller policy).
///
/// # Safety
/// Same as `configure_dpc`.
pub unsafe fn reset_link(cfg_phys: u64, dpc_off: u16) {
    // SAFETY: caller-asserted.
    unsafe {
        clear_triggered(cfg_phys, dpc_off);
        // Re-arm DPC so the next fatal event still fires it. Linux's
        // dpc_enable runs in the resume hook; for narf we keep DPC
        // continuously armed.
        configure_dpc(cfg_phys, dpc_off);
    }
}
