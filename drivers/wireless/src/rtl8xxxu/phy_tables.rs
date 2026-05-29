//! Shared PHY/RF/MAC register-init table representation used by every
//! per-chip integration module.
//!
//! Linux defines three table-row structs in `rtl8xxxu.h`:
//!
//! ```c
//! struct rtl8xxxu_reg8val  { u16 reg; u8  val; };  // MAC init
//! struct rtl8xxxu_reg32val { u16 reg; u32 val; };  // PHY/BB + AGC init
//! struct rtl8xxxu_rfregval { u8  reg; u32 val; };  // RF (LSSI) init
//! ```
//!
//! All three terminate with a sentinel row whose `reg` field is 0xFF or
//! 0xFFFF and whose `val` field is all-ones. The Rust ports use the same
//! convention via the `is_sentinel` predicate so the apply-loop logic is
//! identical across chips.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu.h` lines ~1100–1140
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c::rtl8xxxu_init_mac`
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c::rtl8xxxu_init_phy_regs`
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c::rtl8xxxu_init_phy_rf`

#![allow(dead_code)]

use super::phy::Reg32Val;

/// 8-bit MAC table row.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MacRow {
    pub reg: u16,
    pub val: u8,
}

impl MacRow {
    /// Sentinel terminating row — Linux uses `{0xFFFF, 0xFF}`.
    pub const SENTINEL: Self = Self { reg: 0xFFFF, val: 0xFF };

    pub const fn is_sentinel(&self) -> bool {
        self.reg == 0xFFFF
    }
}

/// 5-bit-RF-address × 20-bit-data row used by RF init tables.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RfRow {
    /// RF register address (5 bits, but stored as u8).
    pub reg: u8,
    /// 20-bit data field; high bits 0.
    pub val: u32,
}

impl RfRow {
    /// Sentinel — Linux uses `{0xFF, 0xFFFFFFFF}`.
    pub const SENTINEL: Self = Self { reg: 0xFF, val: 0xFFFFFFFF };

    pub const fn is_sentinel(&self) -> bool {
        self.reg == 0xFF
    }
}

/// Re-export the `Reg32Val` row from `phy.rs` so callers can keep a
/// single table-row vocabulary.
pub type PhyRow = Reg32Val;

/// Count rows in a table up to (but not including) the sentinel.
pub fn live_rows_mac(table: &[MacRow]) -> usize {
    table.iter().take_while(|r| !r.is_sentinel()).count()
}

/// Count rows in a PHY/BB/AGC table up to the sentinel.
pub fn live_rows_phy(table: &[PhyRow]) -> usize {
    table.iter().take_while(|r| **r != PhyRow::SENTINEL).count()
}

/// Count rows in an RF table up to the sentinel.
pub fn live_rows_rf(table: &[RfRow]) -> usize {
    table.iter().take_while(|r| !r.is_sentinel()).count()
}

/// Apply a MAC table by invoking `write8(reg, val)` for each non-sentinel
/// row.
///
/// Source: `core.c::rtl8xxxu_init_mac` ~L2187..L2230. The Linux loop:
///
/// ```c
/// for (i = 0; ; i++) {
///     if (array[i].reg == 0xffff && array[i].val == 0xff)
///         break;
///     rtl8xxxu_write8(priv, array[i].reg, array[i].val);
/// }
/// ```
pub fn apply_mac_table<W: FnMut(u16, u8)>(table: &[MacRow], mut write8: W) -> usize {
    let mut n = 0;
    for row in table {
        if row.is_sentinel() {
            break;
        }
        write8(row.reg, row.val);
        n += 1;
    }
    n
}

/// Apply a PHY/BB or AGC table by invoking `write32(reg, val)`.
///
/// Source: `core.c::rtl8xxxu_init_phy_regs` ~L2230.
pub fn apply_phy_table<W: FnMut(u16, u32)>(table: &[PhyRow], mut write32: W) -> usize {
    let mut n = 0;
    for row in table {
        if *row == PhyRow::SENTINEL {
            break;
        }
        write32(row.reg, row.val);
        n += 1;
    }
    n
}

/// Apply an RF table by invoking `write_rfreg(path, reg, val)`.
///
/// Source: `core.c::rtl8xxxu_init_phy_rf` ~L2310. The RF path is
/// determined by the caller (`RF_A` or `RF_B`).
pub fn apply_rf_table<W: FnMut(u8, u32)>(table: &[RfRow], mut write_rfreg: W) -> usize {
    let mut n = 0;
    for row in table {
        if row.is_sentinel() {
            break;
        }
        write_rfreg(row.reg, row.val);
        n += 1;
    }
    n
}
