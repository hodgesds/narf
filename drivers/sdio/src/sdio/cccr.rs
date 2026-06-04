// SPDX-License-Identifier: GPL-2.0-or-later
//! SDIO Card Common Control Registers (CCCR) and Function Basic
//! Registers (FBR) layout.
//!
//! References:
//! - SDIO Simplified Specification v3.00 §6.9 (CCCR map).
//! - SDIO Simplified Specification v3.00 §6.10 (FBR map).
//! - Linux `include/linux/mmc/sdio.h` (GPL-2.0-or-later, adapted).

#![allow(dead_code)]

// ── CCCR register addresses (function 0, 17-bit address space) ────────
/// CCCR/SDIO Revision (R).
pub const CCCR_SDIO_REVISION: u32 = 0x00;
/// SD Specification Revision (R).
pub const CCCR_SD_SPEC_REVISION: u32 = 0x01;
/// I/O Enable register — bit N enables function N (R/W).
pub const CCCR_IO_ENABLE: u32 = 0x02;
/// I/O Ready register — bit N = function N ready (R).
pub const CCCR_IO_READY: u32 = 0x03;
/// Interrupt Enable — bit 0 = master enable; bit N = function N (R/W).
pub const CCCR_INT_ENABLE: u32 = 0x04;
/// Interrupt Pending (R).
pub const CCCR_INT_PENDING: u32 = 0x05;
/// I/O Abort (R/W).
pub const CCCR_IO_ABORT: u32 = 0x06;
/// Bus Interface Control — bus-width, CD disable, … (R/W).
pub const CCCR_BUS_IFACE: u32 = 0x07;
/// Card Capability (R).
pub const CCCR_CARD_CAPABILITY: u32 = 0x08;
/// Common CIS pointer, byte 0 (R). Full pointer = bytes [0x09..0x0B].
pub const CCCR_CIS_PTR_0: u32 = 0x09;
pub const CCCR_CIS_PTR_1: u32 = 0x0A;
pub const CCCR_CIS_PTR_2: u32 = 0x0B;
/// Bus Suspend (R/W).
pub const CCCR_BUS_SUSPEND: u32 = 0x0C;
/// Function Select (R/W).
pub const CCCR_FUNC_SELECT: u32 = 0x0D;
/// Exec Flags (R).
pub const CCCR_EXEC_FLAGS: u32 = 0x0E;
/// Ready Flags (R).
pub const CCCR_READY_FLAGS: u32 = 0x0F;
/// Function 0 block size, byte 0 (R/W).
pub const CCCR_FN0_BLKSZ_0: u32 = 0x10;
pub const CCCR_FN0_BLKSZ_1: u32 = 0x11;
/// Power Control (R/W).
pub const CCCR_POWER_CTRL: u32 = 0x12;
/// High-Speed register (R/W).
pub const CCCR_HIGH_SPEED: u32 = 0x13;
/// UHS-I Support (R).
pub const CCCR_UHS_I_SUPPORT: u32 = 0x14;
/// Driver Strength (R/W).
pub const CCCR_DRIVER_STRENGTH: u32 = 0x15;
/// Interrupt Extension (R/W).
pub const CCCR_INT_EXT: u32 = 0x16;

// CCCR_BUS_IFACE bits
pub const BUS_IFACE_BW_MASK: u8 = 0x03;
pub const BUS_IFACE_BW_1BIT: u8 = 0x00;
pub const BUS_IFACE_BW_4BIT: u8 = 0x02;
pub const BUS_IFACE_CD_DISABLE: u8 = 0x80;

// CCCR_HIGH_SPEED bits
pub const HIGH_SPEED_SHS: u8 = 0x01; // support high speed
pub const HIGH_SPEED_EHS: u8 = 0x02; // enable high speed

// CCCR SDIO-revision field (bits [3:0] of CCCR_SDIO_REVISION)
pub const SDIO_REV_MASK: u8 = 0x0F;
pub const SDIO_REV_1_00: u8 = 0x00;
pub const SDIO_REV_1_10: u8 = 0x01;
pub const SDIO_REV_1_20: u8 = 0x02;
pub const SDIO_REV_2_00: u8 = 0x03;
pub const SDIO_REV_3_00: u8 = 0x04;

// ── FBR (Function Basic Registers) ────────────────────────────────────
//
// Each function n (1–7) has its FBR block at base address 0x100 × n.
// Offsets within the FBR block:

/// FBR base address for function n.
#[inline]
pub const fn fbr_base(func: u8) -> u32 {
    0x100 * (func as u32)
}

/// FBR offset: Standard SDIO Function Interface Code (R).
pub const FBR_STD_IF: u32 = 0x00;
/// FBR offset: Extended Standard SDIO Function Interface Code (R).
pub const FBR_STD_IF_EXT: u32 = 0x01;
/// FBR offset: Power Selection (R/W).
pub const FBR_POWER_SEL: u32 = 0x02;
/// FBR offset: CIS Pointer byte 0 (R). Full = [0x09..0x0B] relative to FBR base.
pub const FBR_CIS_PTR_0: u32 = 0x09;
pub const FBR_CIS_PTR_1: u32 = 0x0A;
pub const FBR_CIS_PTR_2: u32 = 0x0B;
/// FBR offset: CSA Pointer byte 0 (R/W if CSA supported).
pub const FBR_CSA_PTR_0: u32 = 0x0C;
/// FBR offset: function block size byte 0 (R/W).
pub const FBR_BLKSZ_0: u32 = 0x10;
pub const FBR_BLKSZ_1: u32 = 0x11;

// FBR_STD_IF class values of interest
pub const SDIO_CLASS_NONE: u8 = 0x00;
pub const SDIO_CLASS_UART: u8 = 0x01;
pub const SDIO_CLASS_BLUETOOTH: u8 = 0x02;
pub const SDIO_CLASS_GPS: u8 = 0x04;
pub const SDIO_CLASS_CAMERA: u8 = 0x06;
pub const SDIO_CLASS_WLAN: u8 = 0x07;

// ── CIS tuple codes ────────────────────────────────────────────────────
/// Null tuple — no link field, ignored.
pub const CISTPL_NULL: u8 = 0x00;
/// CISTPL_VERS_1 — product info strings.
pub const CISTPL_VERS_1: u8 = 0x15;
/// CISTPL_MANFID — manufacturer ID (4 bytes: vendor[2] + device[2]).
pub const CISTPL_MANFID: u8 = 0x20;
/// CISTPL_FUNCID — function class (2 bytes).
pub const CISTPL_FUNCID: u8 = 0x21;
/// CISTPL_FUNCE — function extension (variable).
pub const CISTPL_FUNCE: u8 = 0x22;
/// End-of-chain sentinel.
pub const CISTPL_END: u8 = 0xFF;

/// Minimum tuple body sizes (bytes after code + link).
pub const CISTPL_MANFID_MIN: u8 = 4;
pub const CISTPL_FUNCID_MIN: u8 = 2;

/// Decode a CISTPL_MANFID body (4 bytes) into (vendor, device).
///
/// Byte order: vendor[0..1] little-endian, device[2..3] little-endian.
#[inline]
pub fn cistpl_manfid_decode(body: &[u8]) -> Option<(u16, u16)> {
    if body.len() < 4 {
        return None;
    }
    let vendor = u16::from_le_bytes([body[0], body[1]]);
    let device = u16::from_le_bytes([body[2], body[3]]);
    Some((vendor, device))
}

/// Decode a CISTPL_FUNCID body (2 bytes) into (function_class, sysinit).
#[inline]
pub fn cistpl_funcid_decode(body: &[u8]) -> Option<(u8, u8)> {
    if body.len() < 2 {
        return None;
    }
    Some((body[0], body[1]))
}

/// Decode the TPLFE_MAX_BLK_SIZE from a CISTPL_FUNCE body for a
/// per-function tuple (type 0x01, bytes[12..13]).
#[inline]
pub fn cistpl_funce_max_blksz(body: &[u8]) -> Option<u16> {
    if body.len() < 14 {
        return None;
    }
    Some(u16::from_le_bytes([body[12], body[13]]))
}

/// Parse the CIS pointer from three successive CCCR/FBR bytes.
#[inline]
pub fn cis_ptr_from_bytes(b0: u8, b1: u8, b2: u8) -> u32 {
    (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16)
}

/// Compact snapshot of parsed CCCR fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CccrInfo {
    /// SDIO spec revision (4-bit field from offset 0x00).
    pub sdio_rev: u8,
    /// Number of I/O functions (1–7).
    pub func_count: u8,
    /// True if the memory function (SDIO/SD combo) is present.
    pub mem_present: bool,
    /// High-speed capable.
    pub supports_hs: bool,
    /// Common CIS pointer (24-bit).
    pub cis_ptr: u32,
    /// Function 0 block size.
    pub fn0_blksz: u16,
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_cccr_layout_fn0() -> TestResult {
        // CCCR lives at function-0 base (address 0x0000).
        // Key register addresses per SDIO Simplified Spec §6.9 Table 6-1.
        let checks: &[(u32, u32)] = &[
            (CCCR_SDIO_REVISION, 0x00),
            (CCCR_IO_ENABLE, 0x02),
            (CCCR_IO_READY, 0x03),
            (CCCR_INT_ENABLE, 0x04),
            (CCCR_CIS_PTR_0, 0x09),
            (CCCR_HIGH_SPEED, 0x13),
        ];
        for &(got, want) in checks {
            if got != want {
                return TestResult::Fail("CCCR register address mismatch");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/cccr", smoke_cccr_layout_fn0);

    fn smoke_fbr_layout_fn1() -> TestResult {
        // FBR for function 1 starts at 0x100.
        let base = fbr_base(1);
        if base != 0x100 {
            return TestResult::Fail("FBR base for fn1 should be 0x100");
        }
        // FBR for function 7 starts at 0x700.
        if fbr_base(7) != 0x700 {
            return TestResult::Fail("FBR base for fn7 should be 0x700");
        }
        // CIS pointer offset within FBR.
        if FBR_CIS_PTR_0 != 0x09 {
            return TestResult::Fail("FBR_CIS_PTR_0 should be 0x09");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/cccr", smoke_fbr_layout_fn1);

    fn smoke_cistpl_manfid_decode() -> TestResult {
        // MANFID for CYW43439: vendor=0x02D0, device=0xA9A6.
        let body: [u8; 4] = [0xD0, 0x02, 0xA6, 0xA9];
        match cistpl_manfid_decode(&body) {
            Some((0x02D0, 0xA9A6)) => {}
            _ => return TestResult::Fail("MANFID decode mismatch"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/cccr", smoke_cistpl_manfid_decode);

    fn smoke_cistpl_funcid_decode() -> TestResult {
        // WLAN = 0x0C per CISTPL_FUNCID standard.
        let body: [u8; 2] = [0x0C, 0x00];
        match cistpl_funcid_decode(&body) {
            Some((0x0C, 0x00)) => {}
            _ => return TestResult::Fail("FUNCID decode mismatch"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/cccr", smoke_cistpl_funcid_decode);

    fn smoke_cistpl_funce_max_blksz() -> TestResult {
        // Construct a fake 14-byte FUNCE body where bytes[12..13] = 0x0040 (64).
        let mut body = [0u8; 14];
        body[12] = 0x40;
        body[13] = 0x00;
        match cistpl_funce_max_blksz(&body) {
            Some(64) => {}
            _ => return TestResult::Fail("FUNCE blksz decode mismatch"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/cccr", smoke_cistpl_funce_max_blksz);

    fn smoke_cis_ptr_construction() -> TestResult {
        // Three-byte CIS pointer: 0x12, 0x34, 0x56 → 0x56_34_12.
        let p = cis_ptr_from_bytes(0x12, 0x34, 0x56);
        if p != 0x0056_3412 {
            return TestResult::Fail("CIS pointer byte order wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/cccr", smoke_cis_ptr_construction);
}
