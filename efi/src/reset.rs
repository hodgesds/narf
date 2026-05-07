//! `ResetSystem()` parameters — UEFI 2.10 §8.5.1.

/// `EFI_RESET_TYPE` (UEFI 2.10 §8.5.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EfiResetType {
    /// Cold reset — clears volatile + most non-volatile state, then
    /// re-runs POST.
    Cold = 0,
    /// Warm reset — re-runs POST without clearing CMOS / RAM where
    /// the platform supports it.
    Warm = 1,
    /// Power-off (S5).
    Shutdown = 2,
    /// Platform-specific reset; `ResetData` carries a GUID + payload.
    PlatformSpecific = 3,
}

impl EfiResetType {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::Cold,
            1 => Self::Warm,
            2 => Self::Shutdown,
            3 => Self::PlatformSpecific,
            _ => return None,
        })
    }
}

/// EFI_STATUS values commonly seen in `ResetSystem` `ResetStatus`
/// arguments (UEFI 2.10 Appendix D). These are EFI's high-bit-set
/// error codes; the kernel typically passes `EFI_SUCCESS = 0` for
/// a clean reboot.
pub mod status {
    pub const SUCCESS: u64 = 0;
    /// High bit (1 << 63 on 64-bit, 1 << 31 on 32-bit) set indicates
    /// "error". The constants below are 64-bit form.
    pub const LOAD_ERROR: u64 = (1 << 63) | 1;
    pub const INVALID_PARAMETER: u64 = (1 << 63) | 2;
    pub const UNSUPPORTED: u64 = (1 << 63) | 3;
    pub const BAD_BUFFER_SIZE: u64 = (1 << 63) | 4;
    pub const BUFFER_TOO_SMALL: u64 = (1 << 63) | 5;
    pub const NOT_READY: u64 = (1 << 63) | 6;
    pub const DEVICE_ERROR: u64 = (1 << 63) | 7;
    pub const WRITE_PROTECTED: u64 = (1 << 63) | 8;
    pub const OUT_OF_RESOURCES: u64 = (1 << 63) | 9;
    pub const NOT_FOUND: u64 = (1 << 63) | 14;
    pub const SECURITY_VIOLATION: u64 = (1 << 63) | 26;
}
