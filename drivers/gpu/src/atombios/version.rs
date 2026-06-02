//! VBIOS version string extraction.
//!
//! The version string is a NUL-terminated ASCII sequence located at
//! `AtomRomHeader::bios_bootup_message_offset` within the VBIOS image.
//! Real AMD strings look like:
//!
//! ```text
//! "BK-AMD ATOMBIOSBK-AMD VER015.040.000.000.014546\0"
//! ```
//!
//! ## Linux references
//!
//! - `linux/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c` lines 73-100
//!   (`amdgpu_atombios_get_bios_version`): reads the NUL-terminated string
//!   from `bios_bootup_message_offset`, trims trailing whitespace, and
//!   returns it as the vbios_version sysfs attribute.

extern crate alloc;

use alloc::string::String;

use super::header::AtomRomHeader;

/// Extract the NUL-terminated VBIOS version string from the bootup
/// message offset recorded in `header`.
///
/// Returns `None` when:
/// - `bios_bootup_message_offset` is 0.
/// - The offset falls past the end of the image.
/// - The string contains non-UTF-8 bytes (or is longer than the image).
///
/// Handles missing NUL terminator gracefully: if no NUL is found
/// within the remaining image bytes, uses the whole trailing slice.
///
/// Linux ref: `amdgpu_atombios_get_bios_version`
/// (amdgpu/amdgpu_atombios.c, lines 73-100).
pub fn extract_version(image: &[u8], header: &AtomRomHeader) -> Option<String> {
    let off = header.bios_bootup_message_offset as usize;
    if off == 0 || off >= image.len() {
        return None;
    }
    let tail = &image[off..];
    // Find NUL terminator; fall back to entire tail if absent.
    let len = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    let bytes = &tail[..len];
    // Treat a zero-length string as absent.
    if bytes.is_empty() {
        return None;
    }
    // Validate UTF-8 (real VBIOSes are ASCII, but we accept any valid UTF-8).
    core::str::from_utf8(bytes).ok().map(String::from)
}
