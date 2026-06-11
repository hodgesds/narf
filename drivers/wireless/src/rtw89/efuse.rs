//! RTW89 EFUSE read.
//!
//! Mirrors the per-byte access pattern Linux uses for the 8852/8851
//! parts. The Wi-Fi-6 silicon moved the address mask one nibble left
//! (`B_AX_EF_ADDR_MASK = GENMASK(26, 16)` versus `[25:8]` on rtw88)
//! and inverted the polarity of the "done" bit (`B_AX_EF_RDY` is set
//! when the byte is ready, versus `EFUSE_CTRL_VALID` going low on the
//! 8821C / 8822C family).
//!
//! ## References (GPL-2.0)
//!
//! - Linux `drivers/net/wireless/realtek/rtw89/efuse.c` (v6.6)
//!   — `rtw89_dump_physical_efuse_map_ddv` (~L113..L138). The
//!   per-byte arming loop here is a direct port: write address →
//!   clear `B_AX_EF_RDY` → `read_poll_timeout_atomic` on the bit
//!   coming back high → fetch the low 8 bits as the data byte.
//! - Linux `drivers/net/wireless/realtek/rtw89/efuse.c` (v6.6)
//!   — `rtw89_switch_efuse_bank` (~L40..L65). We don't switch banks
//!   at Stage 0 because Realtek docs the Wi-Fi bank as the POR
//!   default and the AX parts auto-restore on warm-reset.
//! - Linux `drivers/net/wireless/realtek/rtw89/rtw8852a.h` —
//!   `struct rtw8852ae_efuse::mac_addr` lives at offset 0x000 of the
//!   PCIe variant's logical map.

#![allow(dead_code)]

use narf_bus::MmioRegion;
use narf_time::Deadline;

use super::mac::{
    B_AX_EF_ADDR_MASK, B_AX_EF_ADDR_SHIFT, B_AX_EF_DATA_MASK, B_AX_EF_MODE_SEL_MASK, B_AX_EF_RDY,
    R_AX_EFUSE_CTRL,
};

/// Per-byte wall-clock budget. Linux's loop uses
/// `read_poll_timeout_atomic(..., 1, 1000000, ...)` — 1 µs poll, 1 s
/// budget. We default to 50 ms since the kernel-side test harness
/// has tighter overall budgets; the byte read itself completes in
/// tens of µs on real silicon.
const EFUSE_POLL_MS: u32 = 50;

/// MAC-address byte count.
pub const MAC_ADDR_LEN: usize = 6;

/// Baseline EFUSE logical-map offset for the factory MAC on the
/// PCIe variant of the 8852A/B/C and 8851B parts. Per
/// `rtw89/rtw8852a.h::rtw8852ae_efuse` the `mac_addr[ETH_ALEN]` field
/// sits at offset 0x000 of the PCIe efuse struct. The 8922A
/// reshuffles this (see `rtw8922a_read_efuse_mac_addr` ~L587) — we
/// keep the AX offset as the default and the follow-up will branch on
/// `ChipId`.
pub const EFUSE_MAC_OFFSET: u32 = 0x0000;

/// Errors raised by the EFUSE path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EfuseError {
    /// One per-byte read never asserted `B_AX_EF_RDY`. Either the PMU
    /// isn't actually in the post-PWR state (run the power-on
    /// prologue first) or the EFUSE LDO isn't powered. Linux returns
    /// `-EBUSY` from the same spot.
    Timeout,
    /// The MAC bytes read back as the all-FF / all-00 sentinels that
    /// mean "uninitialized EFUSE." Real factory-programmed silicon
    /// never lands here; QEMU / un-fused parts do.
    MacUninitialized,
}

/// Read `count` bytes starting at logical EFUSE offset `addr` into
/// `out`. Loops byte-by-byte, polling `B_AX_EF_RDY` between writes.
/// `out.len()` must be ≥ `count`.
///
/// # Safety
/// Caller owns the BAR2 MMIO exclusively and the power-on sequence
/// has been run — the EFUSE LDO needs the PMU in the post-PWR state
/// to present data, otherwise the polling loop wedges and times out.
pub unsafe fn read_efuse_bytes(
    mmio: &MmioRegion,
    addr: u32,
    out: &mut [u8],
    count: usize,
) -> Result<(), EfuseError> {
    assert!(
        out.len() >= count,
        "rtw89: read_efuse_bytes out buffer smaller than count"
    );

    for (i, out_byte) in out.iter_mut().enumerate().take(count) {
        let byte_addr = addr.saturating_add(i as u32);

        // Build the EFUSE_CTRL value: address goes into B_AX_EF_ADDR_MASK
        // (bits[26:16]); leave the mode-select field untouched (Linux
        // calls this implicitly via `u32_encode_bits(addr,
        // B_AX_EF_ADDR_MASK)` which preserves bits outside the mask of
        // a *fresh* value, then we OR with the existing reg below).
        let addr_field = (byte_addr << B_AX_EF_ADDR_SHIFT) & B_AX_EF_ADDR_MASK;

        // SAFETY: identity-mapped MMIO; caller asserts BAR2 ownership.
        unsafe {
            let cur = mmio.read32(R_AX_EFUSE_CTRL);
            // Preserve mode-select; replace address field; clear RDY so
            // the hardware re-issues the read. Linux writes
            // `efuse_ctl & ~B_AX_EF_RDY` after setting the address.
            let new = (cur & B_AX_EF_MODE_SEL_MASK) | addr_field;
            mmio.write32(R_AX_EFUSE_CTRL, new);
        }

        // Poll for RDY. Linux: `read_poll_timeout_atomic(rtw89_read32,
        // efuse_ctl, efuse_ctl & B_AX_EF_RDY, 1, 1000000, true,
        // rtwdev, R_AX_EFUSE_CTRL)`.
        let mut last: u32 = 0;
        let done = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: identity-mapped MMIO.
                last = unsafe { mmio.read32(R_AX_EFUSE_CTRL) };
                last & B_AX_EF_RDY != 0
            },
            Deadline::after_ms(EFUSE_POLL_MS as u64),
        );
        if !done {
            return Err(EfuseError::Timeout);
        }

        // Linux stores `(u8)(efuse_ctl & 0xff)` — the data field is
        // `B_AX_EF_DATA_MASK = GENMASK(15, 0)` but only the low byte is
        // valid per single-byte read; the upper byte holds the next
        // sequential byte when burst-mode is enabled (we don't enable
        // burst at Stage 0).
        *out_byte = (last & B_AX_EF_DATA_MASK & 0xFF) as u8;
    }

    Ok(())
}

/// Read the 6-byte MAC address from `EFUSE_MAC_OFFSET`. Fails on
/// timeout OR when the MAC reads back as an all-zero / all-FF
/// sentinel.
///
/// # Safety
/// As for [`read_efuse_bytes`].
pub unsafe fn read_mac(mmio: &MmioRegion) -> Result<[u8; MAC_ADDR_LEN], EfuseError> {
    let mut mac = [0u8; MAC_ADDR_LEN];
    // SAFETY: forwarded.
    unsafe { read_efuse_bytes(mmio, EFUSE_MAC_OFFSET, &mut mac, MAC_ADDR_LEN) }?;
    if mac == [0u8; MAC_ADDR_LEN] || mac == [0xFFu8; MAC_ADDR_LEN] {
        return Err(EfuseError::MacUninitialized);
    }
    Ok(mac)
}

/// `true` if the 6 bytes look like a real MAC (not the all-00 / all-FF
/// sentinels EFUSE returns when unfused).
pub fn mac_is_valid(mac: [u8; MAC_ADDR_LEN]) -> bool {
    mac != [0u8; MAC_ADDR_LEN] && mac != [0xFFu8; MAC_ADDR_LEN]
}
