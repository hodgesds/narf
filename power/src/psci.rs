//! ARM PSCI (Power State Coordination Interface) — clean-room.
//!
//! ## Sources (public only)
//!
//! - **ARM, "Power State Coordination Interface (PSCI) System
//!   Software on ARM Systems"**, version 1.3 (DEN0022F),
//!   April 2023. Public.
//!   <https://developer.arm.com/documentation/den0022/latest>
//! - **Arm Architecture Reference Manual** for the SMC / HVC
//!   calling-convention details (ARM ARM §K22 SMC Calling
//!   Convention).
//!   <https://developer.arm.com/documentation/ddi0487/latest/>
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Function-ID + return-code constants for the PSCI standard
//! services that every ARM kernel uses to power CPUs on/off,
//! suspend the system, and reboot. The actual SMC/HVC instruction
//! that crosses into firmware is in `arch/aarch64`; this module
//! defines the calling-convention values both sides agree on.

extern crate alloc;

/// PSCI Function IDs (PSCI 1.3 §5.1 Table 5-1).
///
/// 32-bit form has bit 30 clear (`0x84??_????`), 64-bit has bit
/// 30 set (`0xC4??_????`). Both ABIs deliver the same semantics;
/// 64-bit lets the caller pass / receive 64-bit context-id and
/// power-state arguments.
pub mod fn_id {
    pub const PSCI_VERSION: u32 = 0x8400_0000;
    pub const CPU_SUSPEND_32: u32 = 0x8400_0001;
    pub const CPU_SUSPEND_64: u32 = 0xC400_0001;
    pub const CPU_OFF: u32 = 0x8400_0002;
    pub const CPU_ON_32: u32 = 0x8400_0003;
    pub const CPU_ON_64: u32 = 0xC400_0003;
    pub const AFFINITY_INFO_32: u32 = 0x8400_0004;
    pub const AFFINITY_INFO_64: u32 = 0xC400_0004;
    pub const MIGRATE_32: u32 = 0x8400_0005;
    pub const MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
    pub const MIGRATE_INFO_UP_CPU_64: u32 = 0xC400_0007;
    pub const SYSTEM_OFF: u32 = 0x8400_0008;
    pub const SYSTEM_RESET: u32 = 0x8400_0009;
    pub const PSCI_FEATURES: u32 = 0x8400_000A;
    pub const CPU_FREEZE: u32 = 0x8400_000B;
    pub const CPU_DEFAULT_SUSPEND_64: u32 = 0xC400_000C;
    pub const NODE_HW_STATE_64: u32 = 0xC400_000D;
    pub const SYSTEM_SUSPEND_64: u32 = 0xC400_000E;
    pub const PSCI_SET_SUSPEND_MODE: u32 = 0x8400_000F;
    pub const PSCI_STAT_RESIDENCY_64: u32 = 0xC400_0010;
    pub const PSCI_STAT_COUNT_64: u32 = 0xC400_0011;
    pub const SYSTEM_RESET2_64: u32 = 0xC400_0012;
    pub const MEM_PROTECT: u32 = 0x8400_0013;
    pub const MEM_PROTECT_CHECK_RANGE_64: u32 = 0xC400_0014;
}

/// Return codes (PSCI 1.3 §5.2.2 Table 5-3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Status {
    Success = 0,
    NotSupported = -1,
    InvalidParameters = -2,
    Denied = -3,
    AlreadyOn = -4,
    OnPending = -5,
    InternalFailure = -6,
    NotPresent = -7,
    Disabled = -8,
    InvalidAddress = -9,
}

impl Status {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Success,
            -1 => Self::NotSupported,
            -2 => Self::InvalidParameters,
            -3 => Self::Denied,
            -4 => Self::AlreadyOn,
            -5 => Self::OnPending,
            -6 => Self::InternalFailure,
            -7 => Self::NotPresent,
            -8 => Self::Disabled,
            -9 => Self::InvalidAddress,
            _ => Self::InternalFailure,
        }
    }
}

/// PSCI version (PSCI 1.3 §5.4.1) — the value `PSCI_VERSION`
/// returns: bits[31:16] = major, bits[15:0] = minor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Version(pub u32);

impl Version {
    pub fn major(self) -> u16 {
        (self.0 >> 16) as u16
    }
    pub fn minor(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }
}

/// Power-state encoding for `CPU_SUSPEND` (PSCI 1.3 §5.4.2 +
/// Annex A.1 Original Format).
///
/// Original format (32-bit):
/// ```text
///   bits[15:0]   StateID — IMPLEMENTATION DEFINED
///   bit  16      StateType — 0 = standby, 1 = power-down
///   bits[26:24]  Affinity Level (0 = CPU, 1 = cluster, 2 = system)
/// ```
pub fn encode_power_state(state_id: u16, power_down: bool, affinity_level: u8) -> u32 {
    let mut v = state_id as u32;
    if power_down {
        v |= 1 << 16;
    }
    v |= ((affinity_level as u32) & 0x7) << 24;
    v
}

/// Affinity-level types passed to `AFFINITY_INFO`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AffinityState {
    On = 0,
    Off = 1,
    OnPending = 2,
}

impl AffinityState {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::On,
            1 => Self::Off,
            2 => Self::OnPending,
            _ => return None,
        })
    }
}

/// `SYSTEM_RESET2` reset types (PSCI 1.3 §5.4.20).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SystemReset2Type {
    Architectural = 0,
    /// Vendor-defined; the upper 31 bits of the function-arg word
    /// pick the specific vendor reset, with bit 31 set (0x8000_0000).
    Vendor = 0x8000_0000,
}
