//! rtlwifi EFUSE access — logical-map read via the SPI-like register protocol.
//!
//! The rtlwifi family uses a slightly different EFUSE power-switch path than
//! rtw88: instead of a dedicated `REG_LDO_EFUSE_CTRL`, the voltage is brought
//! up by writing `VOLTAGE_V25 << LDOE25_SHIFT` into the upper bits of
//! `REG_EFUSE_TEST` (0x0034).  The per-byte read protocol is otherwise
//! identical.
//!
//! ## Protocol (per byte at logical address `addr`)
//!
//! 1. Assert `EFUSE_TEST_LDOE25_EN` in `REG_EFUSE_TEST`.
//! 2. Write `(addr << EFUSE_CTRL_ADDR_SHIFT)` to `REG_EFUSE_CTRL` (arm).
//! 3. Write same value **with** `EFUSE_CTRL_VALID` set (trigger).
//! 4. Poll `REG_EFUSE_CTRL` until bit 31 reads back as 0.
//! 5. Extract `REG_EFUSE_CTRL & EFUSE_CTRL_DATA_MASK` as the data byte.
//! 6. After all bytes: de-assert `EFUSE_TEST_LDOE25_EN`.
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/efuse.c::read_efuse_byte` — per-byte access protocol
//! - `rtlwifi/efuse.c::efuse_power_switch` — LDO voltage switch
//! - `rtlwifi/efuse.h` — `VOLTAGE_V25`, `LDOE25_SHIFT` constants

#![allow(dead_code)]

use narf_bus::MmioRegion;
use narf_time::Deadline;

use super::regs::*;

/// Errors from the EFUSE read path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EfuseError {
    /// A single byte read didn't complete within the wall-clock budget.
    /// Typically means power-on is incomplete or the LDO didn't come up.
    Timeout,
    /// MAC bytes read back as the all-zero or all-FF sentinel that means
    /// the EFUSE is unfused (engineering sample or blank chip).
    MacUninitialized,
}

/// Per-byte poll budget.  Linux loops up to 10000 iterations with 10 µs
/// between each; 100 ms is comfortably over that.
const EFUSE_POLL_MS: u64 = 100;

/// Read `count` bytes starting at logical EFUSE offset `addr` into `out`.
///
/// Asserts the LDOE25 voltage once, performs the per-byte protocol for each
/// requested byte, then de-asserts the voltage.
///
/// # Safety
/// Caller must own `mmio` (BAR0) exclusively and must have run the
/// chip power-on sequence so the EFUSE LDO can actually respond.
pub unsafe fn read_efuse_bytes(
    mmio: &MmioRegion,
    addr: u32,
    out: &mut [u8],
    count: usize,
) -> Result<(), EfuseError> {
    assert!(
        out.len() >= count,
        "rtlwifi: read_efuse_bytes: output buffer smaller than count"
    );

    // Assert LDOE25.  Linux `efuse_power_switch(hw, 0 /*read*/, 1 /*on*/)`.
    // SAFETY: caller-asserted MMIO ownership.
    unsafe {
        let cur = mmio.read32(REG_EFUSE_TEST);
        mmio.write32(REG_EFUSE_TEST, (cur & !0xF000_0000) | EFUSE_TEST_LDOE25_EN);
    }

    for i in 0..count {
        let byte_addr = (addr.saturating_add(i as u32)) & EFUSE_CTRL_ADDR_MASK;
        let arm = byte_addr << EFUSE_CTRL_ADDR_SHIFT;

        // Arm then trigger.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_EFUSE_CTRL, arm);
            mmio.write32(REG_EFUSE_CTRL, arm | EFUSE_CTRL_VALID);
        }

        // Poll until bit 31 clears (hardware presents data byte).
        let mut last: u32 = EFUSE_CTRL_VALID;
        let done = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: same.
                last = unsafe { mmio.read32(REG_EFUSE_CTRL) };
                last & EFUSE_CTRL_VALID == 0
            },
            Deadline::after_ms(EFUSE_POLL_MS),
        );
        if !done {
            // De-assert LDO before returning.
            // SAFETY: same.
            unsafe {
                let cur = mmio.read32(REG_EFUSE_TEST);
                mmio.write32(REG_EFUSE_TEST, cur & !EFUSE_TEST_LDOE25_EN);
            }
            return Err(EfuseError::Timeout);
        }
        out[i] = (last & EFUSE_CTRL_DATA_MASK) as u8;
    }

    // De-assert LDOE25.
    // SAFETY: same.
    unsafe {
        let cur = mmio.read32(REG_EFUSE_TEST);
        mmio.write32(REG_EFUSE_TEST, cur & !EFUSE_TEST_LDOE25_EN);
    }

    Ok(())
}

/// Read the 6-byte MAC address from the conventional EFUSE offset.
///
/// Returns `Err(EfuseError::MacUninitialized)` if the result is all-00 or
/// all-FF (sentinel values for "EFUSE not programmed").
///
/// # Safety
/// As for [`read_efuse_bytes`].
pub unsafe fn read_mac(mmio: &MmioRegion) -> Result<[u8; MAC_ADDR_LEN], EfuseError> {
    let mut mac = [0u8; MAC_ADDR_LEN];
    // SAFETY: forwarded.
    unsafe { read_efuse_bytes(mmio, EFUSE_MAC_OFFSET, &mut mac, MAC_ADDR_LEN) }?;
    if mac == [0u8; MAC_ADDR_LEN] || mac == [0xFF; MAC_ADDR_LEN] {
        return Err(EfuseError::MacUninitialized);
    }
    Ok(mac)
}

/// True if `mac` is neither the all-zero nor all-FF sentinel.
pub fn mac_is_valid(mac: [u8; MAC_ADDR_LEN]) -> bool {
    mac != [0u8; MAC_ADDR_LEN] && mac != [0xFF; MAC_ADDR_LEN]
}
