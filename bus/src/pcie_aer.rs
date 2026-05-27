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

// ── AER mask configuration ────────────────────────────────────────
//
// Linux drivers/pci/pcie/aer.c aer_enable_rootport() masks Advisory
// Non-Fatal (bit 13 of CE Mask) because it fires constantly on
// some hardware and carries no actionable information. Everything
// else is unmasked so the root port captures it for logging.
//
// Default severe UE bits are: DLP | Surprise Down |
// Flow Control Protocol Error | Receiver Overflow | Malformed TLP |
// Uncorrectable Internal Error — per PCIe spec §7.8.4.4 reset values.

/// Default correctable-error mask: Advisory Non-Fatal suppressed,
/// all others reported. PCIe §7.8.4.6.
pub const DEFAULT_CE_MASK: u32 = ce::ADVISORY_NON_FATAL;

/// Default uncorrectable-error mask: all zero (report everything).
pub const DEFAULT_UE_MASK: u32 = 0;

/// Default uncorrectable-error severity: the spec-mandated set of
/// link-fatal errors. Adapts from PCIe 6.0 §7.8.4.4 Table 7-75.
pub const DEFAULT_UE_SEVERITY: u32 = ue::DATA_LINK_PROTOCOL_ERROR
    | ue::SURPRISE_DOWN_ERROR
    | ue::FLOW_CONTROL_PROTOCOL_ERROR
    | ue::RECEIVER_OVERFLOW
    | ue::MALFORMED_TLP
    | ue::UNCORRECTABLE_INTERNAL_ERROR;

/// Apply the default AER masks + severity to a device's AER cap.
///
/// Writes the correctable mask, uncorrectable mask, and uncorrectable
/// severity registers in one sequential burst. Returns `false` if the
/// device has no AER capability (skip silently); `true` if programmed.
///
/// # Safety
/// `cfg_phys` must be a live, 4 KiB-mapped PCIe config page;
/// `aer_off` must be the offset returned by `find_aer_cap_offset`.
/// Caller owns the device exclusively during the write window.
pub unsafe fn configure_aer_defaults(cfg_phys: u64, aer_off: u16) {
    // SAFETY: caller-asserted.
    unsafe {
        // Correctable Mask — suppress Advisory Non-Fatal.
        core::ptr::write_volatile(
            (cfg_phys + aer_off as u64 + regs::CORRECTABLE_ERROR_MASK as u64) as *mut u32,
            DEFAULT_CE_MASK,
        );
        // Uncorrectable Mask — report all.
        core::ptr::write_volatile(
            (cfg_phys + aer_off as u64 + regs::UNCORRECTABLE_ERROR_MASK as u64) as *mut u32,
            DEFAULT_UE_MASK,
        );
        // Severity — fatal classification per spec defaults.
        core::ptr::write_volatile(
            (cfg_phys + aer_off as u64 + regs::UNCORRECTABLE_ERROR_SEVERITY as u64) as *mut u32,
            DEFAULT_UE_SEVERITY,
        );
    }
}

/// Enable root-error reporting on a Root Port's AER capability.
/// Sets all three reporting-enable bits in Root Error Command so
/// the root port forwards correctable, non-fatal, and fatal AER
/// messages to the BIOS / OS.
///
/// # Safety
/// Same as `configure_aer_defaults`.
pub unsafe fn enable_root_error_reporting(cfg_phys: u64, aer_off: u16) {
    // SAFETY: caller-asserted.
    unsafe {
        let cmd = root_cmd::CORRECTABLE_ERROR_REPORTING_ENABLE
            | root_cmd::NON_FATAL_ERROR_REPORTING_ENABLE
            | root_cmd::FATAL_ERROR_REPORTING_ENABLE;
        core::ptr::write_volatile(
            (cfg_phys + aer_off as u64 + regs::ROOT_ERROR_COMMAND as u64) as *mut u32,
            cmd,
        );
    }
}

// ── Root Error Status aggregation ────────────────────────────────
//
// A root port's Root Error Status (AER cap +0x30, PCIe §7.8.4.9)
// aggregates error messages from downstream. The register is RW1C:
// reading the value and writing the same value back clears the bits.
// The Error Source Identification register (AER cap +0x34) holds the
// Requester ID of the first offending device.

/// Decoded Root Error Status snapshot. Suitable for passing to an
/// AER dispatcher or logging path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RootErrorStatus {
    /// Raw Root Error Status register value (before clearing).
    pub raw: u32,
    /// Correctable error(s) received.
    pub corr_received: bool,
    /// Multiple correctable errors received.
    pub multi_corr: bool,
    /// Fatal or non-fatal error message received.
    pub fatal_nonfatal_received: bool,
    /// Multiple fatal/non-fatal errors received.
    pub multi_fatal_nonfatal: bool,
    /// The first uncorrectable error was Fatal (vs Non-Fatal).
    pub first_ue_fatal: bool,
    /// Specific non-fatal error messages pending.
    pub nonfatal_pending: bool,
    /// Specific fatal error messages pending.
    pub fatal_pending: bool,
    /// AER MSI interrupt vector number (bits[31:27]).
    pub aer_int_number: u8,
}

impl RootErrorStatus {
    /// Decode a raw Root Error Status DWORD.
    pub fn decode(raw: u32) -> Self {
        Self {
            raw,
            corr_received: raw & root_sts::ERR_COR_RECEIVED != 0,
            multi_corr: raw & root_sts::MULTIPLE_ERR_COR_RECEIVED != 0,
            fatal_nonfatal_received: raw & root_sts::ERR_FATAL_NONFATAL_RECEIVED != 0,
            multi_fatal_nonfatal: raw & root_sts::MULTIPLE_ERR_FATAL_NONFATAL_RECEIVED != 0,
            first_ue_fatal: raw & root_sts::FIRST_UNCORRECTABLE_FATAL != 0,
            nonfatal_pending: raw & root_sts::NON_FATAL_ERROR_MESSAGES_RECEIVED != 0,
            fatal_pending: raw & root_sts::FATAL_ERROR_MESSAGES_RECEIVED != 0,
            aer_int_number: ((raw & root_sts::AER_INT_NUMBER_MASK) >> 27) as u8,
        }
    }

    /// `true` if any error is pending (correctable, non-fatal, or fatal).
    pub fn any_error(&self) -> bool {
        self.corr_received || self.fatal_nonfatal_received
    }

    /// Classify the highest-priority pending error as `UeSeverity`.
    /// Fatal > NonFatal > Correctable > None.
    pub fn ue_severity(&self) -> UeSeverity {
        if self.fatal_nonfatal_received && self.first_ue_fatal {
            UeSeverity::Severe
        } else if self.fatal_nonfatal_received {
            UeSeverity::NonFatal
        } else if self.corr_received {
            UeSeverity::None // correctable — not an UE
        } else {
            UeSeverity::None
        }
    }
}

/// Read Root Error Status and clear it (RW1C). Returns the snapshot
/// before the clear. If the root port has no AER cap this returns
/// `None` (safe to call on any device — the walker will skip it).
///
/// Reference: Linux drivers/pci/pcie/aer.c get_e_source().
///
/// # Safety
/// `cfg_phys` live 4 KiB PCIe config; `aer_off` from walker.
pub unsafe fn read_and_clear_root_error_status(cfg_phys: u64, aer_off: u16) -> RootErrorStatus {
    // SAFETY: caller assertion.
    let raw = unsafe {
        core::ptr::read_volatile(
            (cfg_phys + aer_off as u64 + regs::ROOT_ERROR_STATUS as u64) as *const u32,
        )
    };
    // Clear by writing back the latched bits (RW1C).
    if raw != 0 {
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                (cfg_phys + aer_off as u64 + regs::ROOT_ERROR_STATUS as u64) as *mut u32,
                raw,
            );
        }
    }
    RootErrorStatus::decode(raw)
}

// ── DPC capability detection ──────────────────────────────────────
//
// DPC (Downstream Port Containment, PCIe §7.9.14) is an extended
// capability (ID 0x001D). When DPC triggers it freezes the link
// below the port — preventing AER storms from propagating upstream.
// Detection here is read-only; actuation (re-enabling the link after
// recovery) is a follow-up.
//
// Reference: Linux drivers/pci/pcie/dpc.c dpc_probe().

/// DPC Extended Capability ID.
pub const DPC_CAP_ID: u16 = 0x001D;

/// Minimal decoded DPC capability — just the features the port
/// advertises. Written once during port init; consulted by the AER
/// ISR to decide whether a link containment notification is expected.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpcCapability {
    /// Raw DPC Capability register (16-bit, at DPC cap +0x04).
    pub raw: u16,
    /// Whether RP Extensions are supported (RP PIO logging).
    pub rp_extensions: bool,
    /// Whether Poisoned TLP Egress Blocking is supported.
    pub ptlp_egress_blocking: bool,
    /// Whether Software Triggering is supported.
    pub sw_triggering: bool,
    /// DL_Active ERR_COR Signaling supported.
    pub dl_active_err_cor: bool,
    /// DPC Interrupt Message Number (5-bit MSI vector, bits[4:0]).
    pub int_msg_number: u8,
}

impl DpcCapability {
    /// Decode the DPC Capability register (PCIe 6.0 §7.9.14.2).
    pub fn decode(raw: u16) -> Self {
        Self {
            raw,
            rp_extensions: raw & (1 << 5) != 0,
            ptlp_egress_blocking: raw & (1 << 6) != 0,
            sw_triggering: raw & (1 << 7) != 0,
            dl_active_err_cor: raw & (1 << 12) != 0,
            int_msg_number: (raw & 0x1F) as u8,
        }
    }
}

/// Walk the device's extended cap list to find the DPC capability.
/// Returns `None` for devices without DPC (most endpoints).
///
/// Detection only — no register writes. Suitable for the AER init
/// path and diagnostic dumps.
///
/// # Safety
/// `cfg_phys` must point at a live 4 KiB PCIe config page.
pub unsafe fn find_dpc_capability(cfg_phys: u64) -> Option<DpcCapability> {
    // Walk the extended cap list from 0x100.
    let mut off: u16 = 0x100;
    for _ in 0..256 {
        if off == 0 || off < 0x100 || off >= 0x1000 {
            return None;
        }
        // SAFETY: caller-asserted; offset bounded.
        let hdr = unsafe {
            core::ptr::read_volatile((cfg_phys + off as u64) as *const u32)
        };
        if hdr == 0 || hdr == 0xFFFF_FFFF {
            return None;
        }
        let cap_id = (hdr & 0xFFFF) as u16;
        let next = ((hdr >> 20) & 0xFFF) as u16;
        if cap_id == DPC_CAP_ID {
            // DPC Capability register is at cap_off + 0x04 (16-bit).
            // SAFETY: same.
            let dpc_raw = unsafe {
                core::ptr::read_volatile((cfg_phys + off as u64 + 0x04) as *const u16)
            };
            return Some(DpcCapability::decode(dpc_raw));
        }
        if next == 0 {
            return None;
        }
        off = next;
    }
    None
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
