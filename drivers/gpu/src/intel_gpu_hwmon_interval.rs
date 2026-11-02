//! PL1/PL2 time windows, exercised by the retained DG2/BMG control owners.
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad xe_hwmon.c
//! xe_hwmon_power_max_interval_{show,store}, regs/xe_mchbar_regs.h.

use narf_filesystem::FsError;

pub(super) const MASK: u32 = 0x7f << 17;

/// `shift` is the source's four-bit PKG_TIME_UNIT or BMG TIME_UNIT=10.
pub(super) fn decode(bits: u32, shift: u8) -> u64 {
    let x = (bits >> 22) & 3;
    let y = (bits >> 17) & 31;
    (((4 | u64::from(x)) << y) * 1000) >> (shift + 2)
}
pub(super) fn maximum(shift: u8) -> u64 {
    // Xe uses x=0,y=18 because existing dGPU SKU MAX_WIN is unreliable.
    // 256 seconds applies only when the time-unit shift is10.
    decode(18 << 17, shift)
}
pub(super) fn minimum(shift: u8) -> u64 {
    (1000u64 >> shift).max(1)
}
pub(super) fn encode(milliseconds: u64, shift: u8) -> Result<u32, FsError> {
    if milliseconds == 0 || milliseconds > maximum(shift) {
        return Err(FsError::InvalidData);
    }
    // Exact Xe algorithm: nearest hardware units plus one, then 1.x*2^y
    // with two fractional bits. NARF refuses a zero represented interval.
    let units = milliseconds
        .checked_shl(u32::from(shift))
        .and_then(|v| v.checked_add(500))
        .map(|v| v / 1000)
        .and_then(|v| v.checked_add(1))
        .ok_or(FsError::InvalidData)?;
    let y = units.ilog2();
    let x = ((units - (1u64 << y)) << 2) >> y;
    let bits = (x as u32) << 22 | y << 17;
    if decode(bits, shift) == 0 || decode(bits, shift) > maximum(shift) {
        return Err(FsError::InvalidData);
    }
    Ok(bits)
}
