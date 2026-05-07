//! CYW43439 backplane access — window paging codec.
//!
//! Reference: **CYW43439 datasheet Rev. 03 §6.5 ("Backplane access
//! through F1")**. The chip's internal SoC bus ("the backplane") is
//! 32-bit byte-addressed but the F1 window into it is only 32 KiB
//! wide. The host walks the backplane by programming the upper bits
//! of the target address into the three F1 SBADDRLOW/MID/HIGH
//! registers, then issuing F1 reads/writes within the resulting
//! window. This module is pure codec — no I/O.
//!
//! Permissively-licensed cross-checks: `soypat/cyw43439` (MIT) and
//! Embassy `cyw43` (Apache-2.0 / MIT). **No GPL `brcmfmac` /
//! `bcmdhd` source consulted.**

use super::sdio::{F1_SBADDRHIGH, F1_SBADDRLOW, F1_SBADDRMID};

/// Size of the F1 backplane window (datasheet §6.5).
pub const WINDOW_SIZE: u32 = 0x8000;
/// Mask of the in-window address bits (low 15 bits).
pub const WINDOW_OFFSET_MASK: u32 = WINDOW_SIZE - 1;
/// Mask of the address bits that select the window itself.
pub const WINDOW_BASE_MASK: u32 = !WINDOW_OFFSET_MASK;

/// Compute the F1 window base + in-window offset for a backplane
/// target address.
///
/// Returns `(window_base, window_offset)` where:
/// - `window_base` is the value to install in
///   `SBADDRLOW/MID/HIGH` (low 15 bits cleared).
/// - `window_offset` is the byte offset to use as the F1 address for
///   the access (always within `[0, WINDOW_SIZE)`).
pub fn split(addr: u32) -> (u32, u32) {
    (addr & WINDOW_BASE_MASK, addr & WINDOW_OFFSET_MASK)
}

/// Three-byte little-endian decomposition of the window base, in the
/// order the host writes them to F1 (low → mid → high). The low
/// 15 bits of `base` are dropped because they live inside the window
/// itself.
pub fn window_bytes(base: u32) -> [u8; 3] {
    let masked = base & WINDOW_BASE_MASK;
    [
        ((masked >> 8) & 0xFF) as u8,
        ((masked >> 16) & 0xFF) as u8,
        ((masked >> 24) & 0xFF) as u8,
    ]
}

/// One programmed-window step: which F1 register to write next, and
/// the byte to put there. Yielded in low → mid → high order so a
/// caller can issue three CMD52 writes without further bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowWrite {
    pub address: u32,
    pub data: u8,
}

/// Iterator over the three F1 register writes that establish the
/// window for `base`.
pub fn window_writes(base: u32) -> [WindowWrite; 3] {
    let bytes = window_bytes(base);
    [
        WindowWrite {
            address: F1_SBADDRLOW,
            data: bytes[0],
        },
        WindowWrite {
            address: F1_SBADDRMID,
            data: bytes[1],
        },
        WindowWrite {
            address: F1_SBADDRHIGH,
            data: bytes[2],
        },
    ]
}

// ── Backplane core ids (datasheet §6.5 Table 6-8) ─────────────────

/// The WLAN ARM ("D11") core — runs the WiFi MAC firmware.
pub const CORE_ID_WLAN_ARM: u16 = 0x829;
/// The on-chip RAM core — the staging area for firmware before the
/// ARM core is taken out of reset.
pub const CORE_ID_SOC_RAM: u16 = 0x80E;
/// The chip-common core — top-level chip control.
pub const CORE_ID_CHIPCOMMON: u16 = 0x800;

/// CYW43439 backplane core control / reset register offsets, taken
/// from the published `ARM Cortex-M3` core wrapper layout
/// (datasheet §6.5 Table 6-9). Each address is **relative to the
/// core's wrapper base** — the absolute backplane address is
/// `core_wrapper_base + offset`.
///
/// `IOCTRL` (clock / endian) — `0x408`.
pub const CORE_OFFSET_IOCTRL: u32 = 0x408;
/// `RESETCTRL` (drive RESET) — `0x800`.
pub const CORE_OFFSET_RESETCTRL: u32 = 0x800;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_window_split_aligned() -> TestResult {
        // Address 0x1234_5678 lives in window 0x1234_0000 at offset 0x5678.
        let (base, off) = split(0x1234_5678);
        if base != 0x1234_0000 {
            return TestResult::Fail("window base mis-computed");
        }
        if off != 0x5678 {
            return TestResult::Fail("window offset mis-computed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/backplane",
        smoke_window_split_aligned
    );

    fn smoke_window_writes_low_mid_high_order() -> TestResult {
        // Window for backplane address 0x1880_0000:
        //   bytes  = (0x00, 0x80, 0x18)
        //   F1 regs = SBADDRLOW, SBADDRMID, SBADDRHIGH
        let writes = window_writes(0x1880_0000);
        if writes[0].address != F1_SBADDRLOW || writes[0].data != 0x00 {
            return TestResult::Fail("low-byte write mismatch");
        }
        if writes[1].address != F1_SBADDRMID || writes[1].data != 0x80 {
            return TestResult::Fail("mid-byte write mismatch");
        }
        if writes[2].address != F1_SBADDRHIGH || writes[2].data != 0x18 {
            return TestResult::Fail("high-byte write mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/backplane",
        smoke_window_writes_low_mid_high_order
    );

    fn smoke_window_offset_mask_is_full_window() -> TestResult {
        // Bottom of one window + top of the next must land in
        // adjacent windows.
        let (lo_base, lo_off) = split(WINDOW_SIZE - 1);
        let (hi_base, hi_off) = split(WINDOW_SIZE);
        if lo_base != 0 || lo_off != WINDOW_SIZE - 1 {
            return TestResult::Fail("low-window edge mis-computed");
        }
        if hi_base != WINDOW_SIZE || hi_off != 0 {
            return TestResult::Fail("high-window edge mis-computed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/backplane",
        smoke_window_offset_mask_is_full_window
    );
}
