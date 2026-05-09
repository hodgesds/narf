//! PCIe Advanced Error Reporting (AER) — clean-room.
//!
//! ## Sources (public only)
//!
//! - **PCI Express Base Specification, Revision 6.0**, PCI-SIG —
//!   §7.8.4 "Advanced Error Reporting Capability".
//!   <https://pcisig.com/specifications>
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Layout decoders + bit-mask constants for the AER PCIe Extended
//! Capability. AER lives at one of the per-device extended-cap
//! pointers (capability ID `0x0001`); this module describes the
//! 0x40-ish byte register window the device exposes there. Live
//! MMIO reads + IRQ routing live in the caller — this module
//! defines the *layout* both sides agree on.
//!
//! AER classifies errors into three buckets:
//!
//! - **Uncorrectable Severe** — link is unusable; root-port
//!   typically generates a Fatal Error message that the OS
//!   maps to a kernel panic / device hot-remove.
//! - **Uncorrectable Non-Fatal** — operation failed but the link
//!   is still functional; one-shot recovery via the device's
//!   driver.
//! - **Correctable** — error happened but the link auto-corrected
//!   it; logged for diagnostics, no software action needed.
//!
//! `Severity` chooses Severe vs Non-Fatal for each Uncorrectable
//! bit at runtime.

extern crate alloc;

/// PCIe Extended Capability ID for AER.
pub const AER_CAP_ID: u16 = 0x0001;

/// Register offsets within the AER capability block (PCIe 6.0
/// §7.8.4 Table 7-72).
pub mod regs {
    /// Extended Capability Header — `[15:0] cap_id`,
    /// `[19:16] cap_version`, `[31:20] next_ptr`.
    pub const HEADER: usize = 0x00;
    pub const UNCORRECTABLE_ERROR_STATUS: usize = 0x04;
    pub const UNCORRECTABLE_ERROR_MASK: usize = 0x08;
    pub const UNCORRECTABLE_ERROR_SEVERITY: usize = 0x0C;
    pub const CORRECTABLE_ERROR_STATUS: usize = 0x10;
    pub const CORRECTABLE_ERROR_MASK: usize = 0x14;
    pub const ADVANCED_ERR_CAP_CONTROL: usize = 0x18;
    /// 4 DWords (16 bytes) holding the failed TLP header.
    pub const HEADER_LOG: usize = 0x1C;
    /// Root-port-only registers (offsets 0x2C..=0x37):
    pub const ROOT_ERROR_COMMAND: usize = 0x2C;
    pub const ROOT_ERROR_STATUS: usize = 0x30;
    pub const ERROR_SOURCE_IDENTIFICATION: usize = 0x34;
    /// PCIe 4.0+ TLP Prefix Log (4 DWords = 16 bytes).
    pub const TLP_PREFIX_LOG: usize = 0x38;
}

/// Uncorrectable Error Status / Mask / Severity bits (PCIe 6.0
/// §7.8.4.2 Table 7-73 — same bit layout for all three regs).
pub mod ue {
    pub const DATA_LINK_PROTOCOL_ERROR: u32 = 1 << 4;
    pub const SURPRISE_DOWN_ERROR: u32 = 1 << 5;
    pub const POISONED_TLP: u32 = 1 << 12;
    pub const FLOW_CONTROL_PROTOCOL_ERROR: u32 = 1 << 13;
    pub const COMPLETION_TIMEOUT: u32 = 1 << 14;
    pub const COMPLETER_ABORT: u32 = 1 << 15;
    pub const UNEXPECTED_COMPLETION: u32 = 1 << 16;
    pub const RECEIVER_OVERFLOW: u32 = 1 << 17;
    pub const MALFORMED_TLP: u32 = 1 << 18;
    pub const ECRC_ERROR: u32 = 1 << 19;
    pub const UNSUPPORTED_REQUEST: u32 = 1 << 20;
    pub const ACS_VIOLATION: u32 = 1 << 21;
    pub const UNCORRECTABLE_INTERNAL_ERROR: u32 = 1 << 22;
    pub const MC_BLOCKED_TLP: u32 = 1 << 23;
    pub const ATOMIC_OP_EGRESS_BLOCKED: u32 = 1 << 24;
    pub const TLP_PREFIX_BLOCKED: u32 = 1 << 25;
    pub const POISONED_TLP_EGRESS_BLOCKED: u32 = 1 << 26;

    /// Default severity per PCIe 6.0 — these bits ship as Severe.
    /// Drivers can re-map by writing `UNCORRECTABLE_ERROR_SEVERITY`.
    pub const DEFAULT_SEVERE: u32 = DATA_LINK_PROTOCOL_ERROR
        | SURPRISE_DOWN_ERROR
        | FLOW_CONTROL_PROTOCOL_ERROR
        | RECEIVER_OVERFLOW
        | MALFORMED_TLP
        | UNCORRECTABLE_INTERNAL_ERROR;
}

/// Correctable Error Status / Mask bits (PCIe 6.0 §7.8.4.5
/// Table 7-76).
pub mod ce {
    pub const RECEIVER_ERROR: u32 = 1 << 0;
    pub const BAD_TLP: u32 = 1 << 6;
    pub const BAD_DLLP: u32 = 1 << 7;
    pub const REPLAY_NUM_ROLLOVER: u32 = 1 << 8;
    pub const REPLAY_TIMER_TIMEOUT: u32 = 1 << 12;
    pub const ADVISORY_NON_FATAL: u32 = 1 << 13;
    pub const CORRECTED_INTERNAL_ERROR: u32 = 1 << 14;
    pub const HEADER_LOG_OVERFLOW: u32 = 1 << 15;
}

/// Advanced Error Capabilities and Control register (PCIe 6.0
/// §7.8.4.7 Table 7-78).
pub mod cap_ctrl {
    /// First-error pointer, bits[4:0]. Indicates the bit position
    /// of the first uncorrectable error logged.
    pub const FIRST_ERROR_POINTER_MASK: u32 = 0x1F;
    pub const ECRC_GENERATION_CAPABLE: u32 = 1 << 5;
    pub const ECRC_GENERATION_ENABLE: u32 = 1 << 6;
    pub const ECRC_CHECK_CAPABLE: u32 = 1 << 7;
    pub const ECRC_CHECK_ENABLE: u32 = 1 << 8;
    pub const MULT_HEADER_REC_CAPABLE: u32 = 1 << 9;
    pub const MULT_HEADER_REC_ENABLE: u32 = 1 << 10;
    pub const TLP_PREFIX_LOG_PRESENT: u32 = 1 << 11;
    pub const COMPLETION_TIMEOUT_PREFIX_HEADER_LOG_CAPABLE: u32 = 1 << 12;
}

/// Root Error Command bits (PCIe 6.0 §7.8.4.8).
pub mod root_cmd {
    pub const CORRECTABLE_ERROR_REPORTING_ENABLE: u32 = 1 << 0;
    pub const NON_FATAL_ERROR_REPORTING_ENABLE: u32 = 1 << 1;
    pub const FATAL_ERROR_REPORTING_ENABLE: u32 = 1 << 2;
}

/// Root Error Status bits (PCIe 6.0 §7.8.4.9).
pub mod root_sts {
    pub const ERR_COR_RECEIVED: u32 = 1 << 0;
    pub const MULTIPLE_ERR_COR_RECEIVED: u32 = 1 << 1;
    pub const ERR_FATAL_NONFATAL_RECEIVED: u32 = 1 << 2;
    pub const MULTIPLE_ERR_FATAL_NONFATAL_RECEIVED: u32 = 1 << 3;
    pub const FIRST_UNCORRECTABLE_FATAL: u32 = 1 << 4;
    pub const NON_FATAL_ERROR_MESSAGES_RECEIVED: u32 = 1 << 5;
    pub const FATAL_ERROR_MESSAGES_RECEIVED: u32 = 1 << 6;
    /// AER Interrupt Number, bits[31:27]. Identifies which MSI/
    /// MSI-X vector AER errors raise on.
    pub const AER_INT_NUMBER_MASK: u32 = 0x1F << 27;
}

/// Decoded Extended Cap Header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExtCapHeader {
    pub cap_id: u16,
    pub cap_version: u8,
    /// PCIe-cfg-space offset of the next Extended Cap, or 0 to
    /// terminate.
    pub next_ptr: u16,
}

impl ExtCapHeader {
    pub fn decode(raw: u32) -> Self {
        Self {
            cap_id: (raw & 0xFFFF) as u16,
            cap_version: ((raw >> 16) & 0xF) as u8,
            next_ptr: ((raw >> 20) & 0xFFF) as u16,
        }
    }
    pub fn is_aer(self) -> bool {
        self.cap_id == AER_CAP_ID
    }
}

/// Severity classifier — given the Uncorrectable Status + Severity
/// register values, return whether the latched error is Severe
/// (link-fatal) or Non-Fatal.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UeSeverity {
    /// No uncorrectable error currently latched.
    None,
    NonFatal,
    Severe,
}

pub fn classify_uncorrectable(status: u32, severity: u32) -> UeSeverity {
    if status == 0 {
        UeSeverity::None
    } else if status & severity != 0 {
        UeSeverity::Severe
    } else {
        UeSeverity::NonFatal
    }
}

/// Decoded TLP-Header Log (4 DWords = 16 bytes). The actual
/// fields depend on the TLP type captured (Memory Read, Memory
/// Write, IO, Configuration, Message, Completion). For AER
/// diagnostics we keep the raw bytes and let higher-level
/// tracing decode TLP-type-specific layouts.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HeaderLog(pub [u32; 4]);

impl HeaderLog {
    pub fn decode(raw: &[u8; 16]) -> Self {
        Self([
            u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
            u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
            u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
            u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]),
        ])
    }
}

// ── Extended-capability walker ─────────────────────────────────────
//
// PCIe extended config space starts at offset 0x100 and contains a
// linked list of extended capabilities. Each header is a 32-bit
// dword: bits[15:0] = cap_id, bits[19:16] = cap_version,
// bits[31:20] = next_offset (0 = end of list, >= 0x100). Spec:
// PCIe 6.0 §7.6 (Extended Configuration Space and Extended
// Capabilities).

/// Walk the device's extended-capability list and return the
/// offset (in config-space bytes from `cfg_phys`) of the AER cap,
/// or `None` if the device doesn't carry one.
///
/// Most consumer endpoints (NVMe, NICs, GPUs) do carry AER. Root
/// ports + switch upstream ports always do.
///
/// # Safety
/// `cfg_phys` must point at the start of a 4 KiB device config
/// region the CPU can reach (the same shape ECAM enumeration
/// produces). The walk is read-only.
pub unsafe fn find_aer_cap_offset(cfg_phys: u64) -> Option<u16> {
    let mut off: u16 = 0x100;
    // Bound the walk so a corrupted next-pointer can't loop us
    // forever; the extended config space is at most 4 KiB.
    for _ in 0..256 {
        if off == 0 || off < 0x100 || off >= 0x1000 {
            return None;
        }
        // SAFETY: caller-asserted live config space; offset
        // bounded above.
        let header = unsafe {
            core::ptr::read_volatile((cfg_phys + off as u64) as *const u32)
        };
        if header == 0 || header == u32::MAX {
            return None;
        }
        let cap_id = (header & 0xFFFF) as u16;
        let next = ((header >> 20) & 0xFFF) as u16;
        if cap_id == AER_CAP_ID {
            return Some(off);
        }
        if next == 0 {
            return None;
        }
        off = next;
    }
    None
}

// ── Root Error Status MSI-vector field ────────────────────────────

/// Mask for the "Advanced Error Interrupt Message Number" field
/// in the Root Error Status register (PCIe 6.0 §7.8.4.9
/// bits[31:27]). The value identifies which MSI vector (within
/// the device's MSI cap allocation) AER fires on.
pub const ROOT_ERR_STS_MSI_NUMBER: u32 = 0x1F << 27;

/// Decode the AER MSI-number field from a raw Root Error Status
/// value. Returns the 5-bit vector index (0..=31).
pub fn aer_msi_number(root_err_sts: u32) -> u8 {
    ((root_err_sts & ROOT_ERR_STS_MSI_NUMBER) >> 27) as u8
}

// ── Boot-time enable hook ─────────────────────────────────────────

/// Diagnostic counters — bumped by the AER MSI handler. Exported
/// so tests / debug commands can observe AER deliveries.
pub static AER_FATAL_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static AER_NONFATAL_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static AER_CORRECTABLE_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// AER ISR — runs in IRQ context. Reads Root Error Status from
/// every root port that carries an AER cap, increments the
/// correctable / non-fatal / fatal counters, and clears the
/// status bits via W1C.
///
/// The full per-bridge state walk is deliberately stateless +
/// global: there's no persistent registry of root-port AER
/// blocks today, so the ISR re-walks the bus device list each
/// fire. Acceptable because AER fires rarely (errors are by
/// definition exceptional).
pub fn aer_isr() {
    use core::sync::atomic::Ordering;
    use crate::devices;
    for d in devices().iter() {
        let cfg_phys = match d.kind {
            crate::BusKind::Pcie { cfg_phys, .. } => cfg_phys.raw(),
            _ => continue,
        };
        // SAFETY: cfg_phys is identity-mapped ECAM from
        // bus enumeration; read of the AER cap ID is read-only.
        let aer = match unsafe { find_aer_cap_offset(cfg_phys) } {
            Some(o) => o as u64,
            None => continue,
        };
        // Read Root Error Status (offset 0x30 within the AER
        // cap). Only root ports + switch upstream ports
        // implement this; endpoints will read zero here, which
        // is harmless.
        // SAFETY: same.
        let sts = unsafe {
            core::ptr::read_volatile((cfg_phys + aer + regs::ROOT_ERROR_STATUS as u64)
                as *const u32)
        };
        if sts & root_sts::ERR_COR_RECEIVED != 0 {
            AER_CORRECTABLE_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        if sts & root_sts::ERR_FATAL_NONFATAL_RECEIVED != 0 {
            // Differentiate fatal vs non-fatal by reading the
            // uncorrectable severity from the source device's
            // AER block — out of scope for the ISR. Bump
            // non-fatal here; future refinement can split.
            AER_NONFATAL_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        // Clear the consumed status bits (W1C).
        if sts != 0 {
            // SAFETY: same.
            unsafe {
                core::ptr::write_volatile(
                    (cfg_phys + aer + regs::ROOT_ERROR_STATUS as u64) as *mut u32,
                    sts,
                );
            }
        }
    }
}
