//! RTW88 EFUSE read.
//!
//! Mirrors the per-byte EFUSE access pattern Linux uses for the
//! 8821C / 8822B / 8822C parts:
//!
//! - `drivers/net/wireless/realtek/rtw88/efuse.c::rtw_efuse_read`
//!   (Linux v6.6 lines ~50..~120) — the byte-loop that:
//!     1. asserts `LDOE25_EN` in `REG_LDO_EFUSE_CTRL` once,
//!     2. for each byte:
//!        a. writes `(addr << 8)` to `REG_EFUSE_CTRL` (data/addr field),
//!        b. clears bit 31 (`EFUSE_CTRL_VALID`) — this is the *write*
//!        shape that arms the read once we re-assert it,
//!        c. sets bit 31 to trigger,
//!        d. polls bit 31 — when the hardware finishes the read, it
//!        flips bit 31 back to 0 and presents the data byte in
//!        bits[7:0],
//!     3. clears `LDOE25_EN`.
//!
//! NARF is GPL-2.0-or-later, so this direct port is in-policy.
//!
//! The baseline only reads the 6 bytes the MAC lives in, but the
//! `read_efuse_bytes` helper is generic over count so a follow-up can
//! pull the full ~512-byte logical map.

#![allow(dead_code)]

use narf_bus::MmioRegion;
use narf_time::Deadline;

use super::regs::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EfuseError {
    /// A single byte read didn't complete within the wall-clock
    /// budget. Either the LDO isn't actually powered (PWR-seq
    /// incomplete) or the chip is in PMU power-down.
    Timeout,
    /// The MAC bytes read back as the all-FF / all-00 sentinels
    /// that mean "uninitialized EFUSE." Real factory-programmed
    /// silicon never lands here; QEMU / un-fused parts do.
    MacUninitialized,
}

/// Per-byte wall-clock budget. Linux uses a 100-iter poll loop with a
/// 1 µs udelay between iters — so ~100 µs typical, ~few ms worst. 5 ms
/// gives plenty of headroom.
const EFUSE_POLL_MS: u32 = 5;

/// Read `count` bytes starting at logical EFUSE offset `addr` into
/// `out`. Asserts the EFUSE LDO once, loops byte-by-byte, then
/// de-asserts. `out.len()` must be ≥ `count`.
///
/// # Safety
/// Caller owns the BAR0 MMIO exclusively and the power-on sequence
/// has been run — the EFUSE LDO needs the PMU in the post-PWR state
/// to actually present data, otherwise the polling loop wedges and
/// times out.
pub unsafe fn read_efuse_bytes(
    mmio: &MmioRegion,
    addr: u32,
    out: &mut [u8],
    count: usize,
) -> Result<(), EfuseError> {
    assert!(
        out.len() >= count,
        "rtw88: read_efuse_bytes out buffer smaller than count"
    );

    // Power the EFUSE LDO. Per `rtw88/efuse.c::rtw_efuse_read`, this
    // is a write-1-to-set on bit 31 of REG_LDO_EFUSE_CTRL.
    // SAFETY: identity-mapped MMIO; caller asserts BAR0 ownership.
    let ldo = unsafe { mmio.read32(REG_LDO_EFUSE_CTRL) };
    // SAFETY: same.
    unsafe {
        mmio.write32(REG_LDO_EFUSE_CTRL, ldo | LDO_EFUSE_EN);
    }

    for (i, out_byte) in out.iter_mut().enumerate().take(count) {
        let byte_addr = addr.saturating_add(i as u32) & EFUSE_CTRL_ADDR_MASK;

        // Arm the read: write the address into bits[25:8] and clear
        // VALID (bit 31). The hardware re-asserts VALID once we set
        // it; clearing first matches the Linux shape and avoids a
        // false "already done" detection if a prior read left VALID
        // set.
        let arm = (byte_addr & EFUSE_CTRL_ADDR_MASK) << EFUSE_CTRL_ADDR_SHIFT;
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_EFUSE_CTRL, arm);
            // Trigger.
            mmio.write32(REG_EFUSE_CTRL, arm | EFUSE_CTRL_VALID);
        }

        // Poll. Bit 31 reads back as 0 once the byte is presented in
        // bits[7:0]. responsive_spin_until ticks sleep_pumps so the
        // FB cursor / serial drain stay alive while we wait.
        let mut last: u32 = 0;
        let done = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: identity-mapped MMIO.
                last = unsafe { mmio.read32(REG_EFUSE_CTRL) };
                last & EFUSE_CTRL_VALID == 0
            },
            Deadline::after_ms(EFUSE_POLL_MS as u64),
        );
        if !done {
            // De-assert the LDO before returning so we don't leave it
            // powered on the failure path.
            // SAFETY: same.
            unsafe {
                let v = mmio.read32(REG_LDO_EFUSE_CTRL);
                mmio.write32(REG_LDO_EFUSE_CTRL, v & !LDO_EFUSE_EN);
            }
            return Err(EfuseError::Timeout);
        }
        *out_byte = (last & EFUSE_CTRL_DATA_MASK) as u8;
    }

    // De-assert the LDO. Linux clears the bit at the end of
    // `rtw_efuse_read` to leave the chip in the low-power state.
    // SAFETY: same.
    unsafe {
        let v = mmio.read32(REG_LDO_EFUSE_CTRL);
        mmio.write32(REG_LDO_EFUSE_CTRL, v & !LDO_EFUSE_EN);
    }

    Ok(())
}

/// Read the 6-byte MAC address from the conventional logical EFUSE
/// offset (`EFUSE_MAC_OFFSET`). Fails if the read times out OR if the
/// MAC reads back as an all-zero / all-FF sentinel (which means EFUSE
/// is unfused — caller's concern, but we surface it as an explicit
/// error so probe can fall back to a derived MAC if it wants).
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
