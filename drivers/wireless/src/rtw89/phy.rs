//! RTW89 PHY parameter table loader — Stage-1 stub.
//!
//! Realtek's Wi-Fi 6 silicon doesn't ship BB/RF init values in the
//! firmware blob — those live in per-chip `*_phy_table.c` source files
//! that the Linux driver compiles in. Each table is a long list of
//! `(register, value, mask, delay)` writes:
//!
//!   - `rtw89/rtw8852a_table.c` — 8852A BB + RF + AGC + RFK tables.
//!   - `rtw89/rtw8852b_table.c` — same for 8852B.
//!   - `rtw89/rtw8852c_table.c` — same for 8852C (Wi-Fi 6E).
//!   - `rtw89/rtw8851b_table.c` — 8851B.
//!   - `rtw89/rtw8922a_table.c` — 8922A (Wi-Fi 7).
//!
//! Each is ~20–50k lines of generated table data. Porting them is
//! mechanical but volumetric — out of scope for Stage 0/1. The stub
//! exists so the probe path has a stable call site.
//!
//! ## References (GPL-2.0)
//!
//! - Linux `rtw89/phy.c::rtw89_phy_init_bb_reg` (~L300..L450) —
//!   the table walker.
//! - Linux `rtw89/phy.c::rtw89_phy_load_txpwr_byrate` (~L500..L700)
//!   — TX-power-by-rate calibration.
//! - Linux `rtw89/phy.h` — `struct rtw89_phy_table` shape we'll
//!   replicate in Stage 2.

#![allow(dead_code)]

use narf_bus::MmioRegion;

/// Stage-1 stub. Returns `Ok(0)` — "no tables loaded, but the caller
/// should continue." Stage 2 will fill this in.
///
/// # Safety
/// Caller owns BAR2 + power-on completed. Future implementation will
/// issue thousands of MMIO writes via the table walker.
pub unsafe fn load_param_tables_stub(_mmio: &MmioRegion) -> Result<usize, PhyError> {
    // Stage-1 returns count=0; Stage 2 will:
    //   1. resolve `(chip_id, cv)` → BB/RF/AGC table set,
    //   2. walk each `(reg, val, mask)` tuple, issuing
    //      `rtw89_write32_mask(rtwdev, reg, mask, val)` equivalents,
    //   3. honor delay slots between sections (typically AFE-PLL lock
    //      settling).
    Ok(0)
}

/// Errors raised by the PHY-table loader. Stage-1 stub never returns
/// any of these — they're here so the Stage-2 drop-in is mechanical.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PhyError {
    /// No table set known for the (chip-id, cv) pair.
    UnknownChip,
    /// A `(reg, val, mask, delay)` entry's polling slot didn't settle
    /// within the wall-clock budget. Usually an AFE-PLL lock failure.
    SettleTimeout,
}
