//! ACPI laptop lid switch.
//!
//! ACPI 6.5 §9.5.1: laptop lid devices implement `_LID` returning
//! an Integer: 0 = closed, non-zero = open. When the EC observes
//! a lid state transition it fires a `_Qxx` event that calls
//! `Notify(\_SB.LID0, 0x80)`; the AML interpreter routes the
//! notify into the lid driver which re-evaluates `_LID`.
//!
//! The lid policy (suspend on close, ignore, etc.) is decided by
//! the host OS; this module only owns the state model.

/// Lid state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LidState {
    /// Lid is closed — typically triggers screen-off / suspend.
    Closed,
    /// Lid is open.
    Open,
}

/// Decode a `_LID` integer return value into typed state. Per spec
/// 0 = closed, non-zero = open (any nonzero value is "open").
pub fn decode_lid(value: u32) -> LidState {
    if value == 0 {
        LidState::Closed
    } else {
        LidState::Open
    }
}

/// Spec-defined Notify code for "lid state changed" (ACPI 6.5
/// §9.5.1).
pub const NOTIFY_LID_STATE_CHANGED: u8 = 0x80;
