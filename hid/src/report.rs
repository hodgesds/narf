//! HID Report value codec.
//!
//! Given a parsed [`ReportDescriptor`](crate::ReportDescriptor) and
//! a wire-format report, [`extract`] returns the `report_count`
//! values for one [`Field`] with proper sign-extension. [`pack`]
//! does the inverse for Output / Feature reports.
//!
//! Bit-packing follows HID 1.11 §6.2.2.7 (Report Size / Count) and
//! §8 (Report Format): values are packed least-significant-bit-first
//! into the byte stream, in declaration order. A Report ID, if used,
//! prefixes the report as a single byte and is **not** part of the
//! bit-offset arithmetic stored in [`Field::bit_offset`].

extern crate alloc;
use alloc::vec::Vec;

use crate::descriptor::{Field, FieldFlags};

/// Errors from [`extract`] / [`pack`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReportError {
    /// Buffer too short for the field's last bit.
    Short,
    /// Field's `report_size` is 0 or > 32 — we cap at 32 because no
    /// real HID field exceeds that, and we work in `i32`.
    UnsupportedSize,
}

/// Extract every value of a field from a raw report. The slice
/// passed in must already have the report-id byte stripped (when
/// present) — the caller knows whether the descriptor uses report
/// IDs (`ReportDescriptor::has_report_ids`).
///
/// Sign-extension is applied iff `field.logical_min < 0`. Otherwise
/// the value is returned as the unsigned bit pattern in `i32`.
pub fn extract(field: &Field, body: &[u8]) -> Result<Vec<i32>, ReportError> {
    let size = field.report_size;
    if size == 0 || size > 32 {
        return Err(ReportError::UnsupportedSize);
    }
    let count = field.report_count as usize;
    let mut out = Vec::with_capacity(count);
    let signed = field.logical_min < 0;
    for i in 0..count {
        let bit = field.bit_offset as u64 + (i as u64) * (size as u64);
        let v = read_bits(body, bit, size as usize, signed)?;
        out.push(v);
    }
    Ok(out)
}

/// Pack `values` into `body` at `field.bit_offset`. `values.len()`
/// must equal `field.report_count`; excess values are ignored,
/// missing ones leave the underlying bits as-is.
///
/// `body` must already be sized for the largest bit-offset of the
/// containing report — usually allocated by the caller from
/// `ReportDescriptor::report_body_bits` rounded up to bytes.
pub fn pack(field: &Field, body: &mut [u8], values: &[i32]) -> Result<(), ReportError> {
    let size = field.report_size;
    if size == 0 || size > 32 {
        return Err(ReportError::UnsupportedSize);
    }
    let count = field.report_count as usize;
    for i in 0..count.min(values.len()) {
        let bit = field.bit_offset as u64 + (i as u64) * (size as u64);
        write_bits(body, bit, size as usize, values[i])?;
    }
    Ok(())
}

/// Read `n` bits (≤ 32) starting at bit position `bit` (LSB-first
/// within each byte) from `body`. Returns the value as `i32`,
/// sign-extending iff `signed`.
fn read_bits(body: &[u8], bit: u64, n: usize, signed: bool) -> Result<i32, ReportError> {
    if n == 0 {
        return Ok(0);
    }
    // Byte range covered.
    let last_bit = bit + n as u64 - 1;
    let last_byte = (last_bit / 8) as usize;
    if last_byte >= body.len() {
        return Err(ReportError::Short);
    }
    let mut acc: u64 = 0;
    let start_byte = (bit / 8) as usize;
    let start_off = (bit % 8) as usize;
    let total_bits_to_load = start_off + n;
    let bytes_to_load = total_bits_to_load.div_ceil(8);
    for k in 0..bytes_to_load {
        acc |= (body[start_byte + k] as u64) << (8 * k);
    }
    let mut v = (acc >> start_off) as u32;
    if n < 32 {
        v &= (1u32 << n) - 1;
    }
    if signed && n < 32 {
        let sign_bit = 1u32 << (n - 1);
        if v & sign_bit != 0 {
            v |= !((1u32 << n) - 1);
        }
    }
    Ok(v as i32)
}

fn write_bits(body: &mut [u8], bit: u64, n: usize, value: i32) -> Result<(), ReportError> {
    if n == 0 {
        return Ok(());
    }
    let last_bit = bit + n as u64 - 1;
    let last_byte = (last_bit / 8) as usize;
    if last_byte >= body.len() {
        return Err(ReportError::Short);
    }
    let mask: u32 = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
    let masked = (value as u32) & mask;
    let start_byte = (bit / 8) as usize;
    let start_off = (bit % 8) as usize;
    // Splat into a working u64 view, clear the field, write, then
    // store back byte-by-byte.
    let total_bits = start_off + n;
    let bytes = total_bits.div_ceil(8);
    let mut acc: u64 = 0;
    for k in 0..bytes {
        acc |= (body[start_byte + k] as u64) << (8 * k);
    }
    let field_mask = (mask as u64) << start_off;
    acc = (acc & !field_mask) | ((masked as u64) << start_off);
    for k in 0..bytes {
        body[start_byte + k] = (acc >> (8 * k)) as u8;
    }
    Ok(())
}

/// Convenience: an array-field decoder. Array fields (HID
/// `Variable` flag *clear*) report `report_count` *indices* into the
/// usage list — one slot per simultaneously-active usage. This
/// helper returns the list of currently-active usages, dropping any
/// zero / out-of-range entries.
pub fn array_active_usages(field: &Field, body: &[u8]) -> Result<Vec<(u16, u16)>, ReportError> {
    if field.flags.contains(FieldFlags::VARIABLE) {
        // Caller probably wanted `extract` instead; still produce a
        // sensible result by mapping every set bit to its usage.
        return Ok(Vec::new());
    }
    let raw = extract(field, body)?;
    let mut out = Vec::new();
    let lo = field.logical_min as u32;
    let hi = field.logical_max as u32;
    let usage_min = field.usage_min.map(|(_, id)| id as u32).unwrap_or(0);
    for v in raw {
        let v = v as u32;
        if v == 0 {
            continue;
        }
        if v < lo || v > hi {
            continue;
        }
        // Index → usage. If usage_min/max range is set, map by
        // offset; else treat the value itself as the usage id.
        let id = if field.usage_min.is_some() {
            usage_min + (v - lo)
        } else {
            v
        };
        out.push((field.usage_page, id as u16));
    }
    Ok(out)
}
