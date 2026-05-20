//! ACPI AC Adapter state.
//!
//! ACPI 6.5 §10.3.1: every AC adapter device implements `_PSR`
//! ("Power Source") returning a single Integer: 0 = offline
//! (battery), 1 = online (mains).
//!
//! Per Appendix E, the recommended `_Qxx` event for AC adapter
//! plug-state changes is `_Q42` on most laptop ECs, but vendors
//! sometimes pick a different index. The platform's DSDT/SSDT
//! resolves which `_Qxx` actually calls `Notify(\_SB.ACAD, 0x80)`
//! (the spec event code for AC state change), and the AML
//! interpreter routes the notify into this driver.
//!
//! Reference: ACPI 6.5 §10.3 (Power Source).

extern crate alloc;

/// AC adapter state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcAdapterState {
    /// Running on battery — wall power not connected.
    Offline,
    /// Running on AC — wall power is connected.
    Online,
}

/// Errors decoding the `_PSR` return value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PsrError {
    /// `_PSR` returned a value other than 0 or 1.
    BadValue(u32),
}

/// Decode a `_PSR` integer return value into typed state.
pub fn decode_psr(value: u32) -> Result<AcAdapterState, PsrError> {
    match value {
        0 => Ok(AcAdapterState::Offline),
        1 => Ok(AcAdapterState::Online),
        other => Err(PsrError::BadValue(other)),
    }
}

/// Spec-defined Notify code for "AC adapter state change". The
/// AML interpreter's Notify handler routes this to the AC adapter
/// driver, which re-evaluates `_PSR` and updates state.
pub const NOTIFY_AC_ADAPTER_STATE_CHANGED: u8 = 0x80;

/// Recommended `_Qxx` index for AC adapter events on most laptop
/// ECs (per ACPI 6.5 Appendix E §E.5). Vendors may renumber;
/// the DSDT is the authority — this is a hint for the boot path.
pub const RECOMMENDED_QXX_AC_ADAPTER: u8 = 0x42;
