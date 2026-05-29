//! xHCI 1.2 Operational Register definitions (§5.4).
//!
//! Operational registers sit at `BAR0 + CAPLENGTH`. They are the
//! mutable controller-state surface: USBCMD/USBSTS, PAGESIZE, CRCR,
//! DCBAAP, CONFIG, and the per-port register set starting at
//! offset 0x400.
//!
//! This file factors out *decode helpers* for the bitfields. The
//! register-read calls themselves live in `super` (xhci/mod.rs) so
//! the MMIO unsafety stays local to the bring-up + ISR paths.

#![allow(dead_code)]

/// Operational-register byte offsets, relative to op_base = BAR0 + CAPLENGTH.
pub const OP_USBCMD: u64 = 0x00;
pub const OP_USBSTS: u64 = 0x04;
pub const OP_PAGESIZE: u64 = 0x08;
pub const OP_DNCTRL: u64 = 0x14;
pub const OP_CRCR: u64 = 0x18;
pub const OP_DCBAAP: u64 = 0x30;
pub const OP_CONFIG: u64 = 0x38;
/// Port Register Set base offset (§5.4.8). One 16-byte block per port.
pub const OP_PORTSC_BASE: u64 = 0x400;
pub const PORT_REGS_STRIDE: u64 = 0x10;

// USBCMD bits (§5.4.1).
pub const USBCMD_RS: u32 = 1 << 0; // Run/Stop
pub const USBCMD_HCRST: u32 = 1 << 1; // Host Controller Reset
pub const USBCMD_INTE: u32 = 1 << 2; // Interrupter Enable
pub const USBCMD_HSEE: u32 = 1 << 3; // Host System Error Enable
pub const USBCMD_LHCRST: u32 = 1 << 7; // Light Host Controller Reset
pub const USBCMD_CSS: u32 = 1 << 8; // Controller Save State
pub const USBCMD_CRS: u32 = 1 << 9; // Controller Restore State
pub const USBCMD_EWE: u32 = 1 << 10; // Enable Wrap Event

// USBSTS bits (§5.4.2).
pub const USBSTS_HCH: u32 = 1 << 0; // Host Controller Halted
pub const USBSTS_HSE: u32 = 1 << 2; // Host System Error
pub const USBSTS_EINT: u32 = 1 << 3; // Event Interrupt
pub const USBSTS_PCD: u32 = 1 << 4; // Port Change Detect
pub const USBSTS_SSS: u32 = 1 << 8; // Save State Status
pub const USBSTS_RSS: u32 = 1 << 9; // Restore State Status
pub const USBSTS_SRE: u32 = 1 << 10; // Save/Restore Error
pub const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready
pub const USBSTS_HCE: u32 = 1 << 12; // Host Controller Error

// PORTSC bits (§5.4.8).
pub const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status (RO)
pub const PORTSC_PED: u32 = 1 << 1; // Port Enabled / Disabled (RW1C)
pub const PORTSC_OCA: u32 = 1 << 3; // Over-current Active
pub const PORTSC_PR: u32 = 1 << 4; // Port Reset (RWS)
/// PLS — Port Link State, bits[8:5].
pub const PORTSC_PLS_SHIFT: u32 = 5;
pub const PORTSC_PLS_MASK: u32 = 0xF << PORTSC_PLS_SHIFT;
pub const PORTSC_PP: u32 = 1 << 9; // Port Power
/// Port Speed, bits[13:10].
pub const PORTSC_SPEED_SHIFT: u32 = 10;
pub const PORTSC_SPEED_MASK: u32 = 0xF << PORTSC_SPEED_SHIFT;
pub const PORTSC_LWS: u32 = 1 << 16; // Port Link State Write Strobe
pub const PORTSC_CSC: u32 = 1 << 17; // Connect Status Change (RW1C)
pub const PORTSC_PEC: u32 = 1 << 18; // Port Enable Change (RW1C)
pub const PORTSC_WRC: u32 = 1 << 19; // Warm Port Reset Change (RW1C)
pub const PORTSC_OCC: u32 = 1 << 20; // Over-current Change (RW1C)
pub const PORTSC_PRC: u32 = 1 << 21; // Port Reset Change (RW1C)
pub const PORTSC_PLC: u32 = 1 << 22; // Port Link State Change (RW1C)
pub const PORTSC_CEC: u32 = 1 << 23; // Port Config Error Change (RW1C)
/// Aggregate of all RW1C change bits in PORTSC[23:17].
pub const PORTSC_CHG_MASK: u32 = 0x00FE_0000;

/// PORTSC.PLS encoding (§5.4.8 Table 5-27).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortLinkState {
    U0 = 0,
    U1 = 1,
    U2 = 2,
    U3Suspended = 3,
    Disabled = 4,
    RxDetect = 5,
    Inactive = 6,
    Polling = 7,
    Recovery = 8,
    HotReset = 9,
    ComplianceMode = 10,
    TestMode = 11,
    Resume = 15,
}

impl PortLinkState {
    pub fn from_portsc(v: u32) -> Option<Self> {
        let pls = (v >> PORTSC_PLS_SHIFT) & 0xF;
        Some(match pls {
            0 => Self::U0,
            1 => Self::U1,
            2 => Self::U2,
            3 => Self::U3Suspended,
            4 => Self::Disabled,
            5 => Self::RxDetect,
            6 => Self::Inactive,
            7 => Self::Polling,
            8 => Self::Recovery,
            9 => Self::HotReset,
            10 => Self::ComplianceMode,
            11 => Self::TestMode,
            15 => Self::Resume,
            _ => return None,
        })
    }
}

/// Decoded PORTSC view useful for tests + diagnostics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortStatus {
    pub connected: bool,
    pub enabled: bool,
    pub powered: bool,
    pub reset_in_progress: bool,
    pub over_current: bool,
    pub link_state: Option<PortLinkState>,
    pub speed_code: u8,
    pub csc: bool,
    pub prc: bool,
}

impl PortStatus {
    pub fn decode(v: u32) -> Self {
        Self {
            connected: (v & PORTSC_CCS) != 0,
            enabled: (v & PORTSC_PED) != 0,
            powered: (v & PORTSC_PP) != 0,
            reset_in_progress: (v & PORTSC_PR) != 0,
            over_current: (v & PORTSC_OCA) != 0,
            link_state: PortLinkState::from_portsc(v),
            speed_code: ((v & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT) as u8,
            csc: (v & PORTSC_CSC) != 0,
            prc: (v & PORTSC_PRC) != 0,
        }
    }

    /// Compose a safe RW1C writeback that preserves RO/RWS state while
    /// clearing the requested change bits. xHCI requires you NOT touch
    /// the PR bit while clearing changes, otherwise you accidentally
    /// re-trigger reset on some controllers.
    pub fn clear_changes_value(orig: u32, clear: u32) -> u32 {
        // Strip all change-bits from the live value, then OR back only
        // the bits the caller wants to clear (RW1C).
        let preserved = orig & !(PORTSC_CHG_MASK | PORTSC_PED | PORTSC_PR);
        preserved | (clear & PORTSC_CHG_MASK)
    }
}
