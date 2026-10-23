//! Firmware identity and the retired synchronous-loader boundary.
//!
//! Runtime loading lives in `firmware_transport`: the retained async owner
//! validates the full chip-bound image and uses vendor-control EP0 writes.
//! Bulk-OUT endpoints carry packet traffic, not firmware pages.

use super::regs::ChipFamily;

pub const fn firmware_name(chip: ChipFamily) -> Option<&'static str> {
    chip.firmware_name()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FwDlError {
    /// A stripped payload and synchronous packet transport cannot represent
    /// authenticated image validation or the async control-pipe lifecycle.
    UseAsyncOwner,
}

/// The former planner uploaded firmware as bulk packets and overwrote
/// unrelated SYS/MCU state. Require the actual async firmware owner instead.
pub fn upload_firmware_blob<T: super::usb::Rtl8xxxuTransport>(
    _transport: &T,
    _stripped_payload: &[u8],
) -> Result<usize, FwDlError> {
    Err(FwDlError::UseAsyncOwner)
}
