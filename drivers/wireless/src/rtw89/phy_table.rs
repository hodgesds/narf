//! RTW89 PHY/BB/RF parameter-table walker — Stage-8.
//!
//! The Linux driver compiles in per-chip BB / AGC / RF init tables as
//! C arrays of `(register, value, mask, delay)` quadruples. Walking
//! one is a uniform "write or poll" loop: each entry either issues
//! `write32_mask(reg, mask, val)` or, when the bits-flagged delay slot
//! says so, spins on a polling condition until a settle time.
//!
//! This module ships the **walker** + entry types. The actual table
//! arrays are too volumetric to land in one stage (8852A alone has
//! ~30k entries across BB + AGC + RF); we keep this scaffold so the
//! per-chip tables drop in mechanically when they land.
//!
//! ## References (all GPL-2.0)
//!
//! - Linux `rtw89/phy.c::rtw89_phy_init_bb_reg` (~L300..L450) — the
//!   walker.
//! - Linux `rtw89/phy.h::struct rtw89_phy_table` — table shape.
//! - Linux `rtw89/rtw8852a_table.c` — concrete table example.

#![allow(dead_code)]

use narf_bus::MmioRegion;
use narf_time::Deadline;

use super::phy::PhyError;

/// One entry in a PHY/BB/AGC table. Mirrors the (register, val, mask,
/// delay) quad Linux uses. We represent the "polling" rows as
/// `Op::Poll`; data rows are `Op::Write`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PhyEntry {
    /// BAR-relative offset to touch.
    pub reg: u64,
    /// Value or polling target.
    pub val: u32,
    /// Bit mask. For Write entries, only bits in mask are updated.
    /// For Poll entries, only those bits are compared.
    pub mask: u32,
    /// Operation kind.
    pub op: PhyOp,
    /// Per-entry delay in microseconds applied after the op.
    pub delay_us: u32,
}

/// Per-entry operation kind.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PhyOp {
    /// Write `val` masked by `mask` into `reg`.
    Write,
    /// Poll `reg` until `(reg_val & mask) == val`. Fail with
    /// `PhyError::SettleTimeout` if budget exceeds 5 ms.
    Poll,
    /// Sleep for `delay_us` micros (no register touch).
    Delay,
}

/// One table is a slice of entries. Mirrors `struct rtw89_phy_table`'s
/// `regs` array.
pub type PhyTable = &'static [PhyEntry];

/// Helper: build a write entry.
pub const fn pw(reg: u64, val: u32, mask: u32) -> PhyEntry {
    PhyEntry {
        reg,
        val,
        mask,
        op: PhyOp::Write,
        delay_us: 0,
    }
}

/// Helper: build a polled-wait entry.
pub const fn pp(reg: u64, val: u32, mask: u32) -> PhyEntry {
    PhyEntry {
        reg,
        val,
        mask,
        op: PhyOp::Poll,
        delay_us: 0,
    }
}

/// Helper: build a delay-only entry.
pub const fn pd(delay_us: u32) -> PhyEntry {
    PhyEntry {
        reg: 0,
        val: 0,
        mask: 0,
        op: PhyOp::Delay,
        delay_us,
    }
}

/// Apply `table` against `mmio`. Returns the number of entries applied
/// on success, or `PhyError::SettleTimeout` on the first failed
/// polling row.
///
/// # Safety
/// Caller owns the BAR2 MMIO exclusively.
pub unsafe fn apply_table(mmio: &MmioRegion, table: PhyTable) -> Result<usize, PhyError> {
    for (i, entry) in table.iter().enumerate() {
        match entry.op {
            PhyOp::Write => {
                // SAFETY: identity-mapped MMIO.
                let cur = unsafe { mmio.read32(entry.reg) };
                let new = (cur & !entry.mask) | (entry.val & entry.mask);
                // SAFETY: identity-mapped MMIO.
                unsafe { mmio.write32(entry.reg, new); }
            }
            PhyOp::Poll => {
                let mut last: u32 = 0;
                let done = narf_scheduler::responsive_spin_until(
                    || {
                        // SAFETY: identity-mapped MMIO.
                        last = unsafe { mmio.read32(entry.reg) };
                        (last & entry.mask) == (entry.val & entry.mask)
                    },
                    Deadline::after_us(5_000),
                );
                if !done {
                    let _ = i;
                    return Err(PhyError::SettleTimeout);
                }
            }
            PhyOp::Delay => {
                let _ = narf_scheduler::responsive_spin_until(
                    || false,
                    Deadline::after_us(entry.delay_us as u64),
                );
            }
        }
        if entry.delay_us > 0 && entry.op != PhyOp::Delay {
            let _ = narf_scheduler::responsive_spin_until(
                || false,
                Deadline::after_us(entry.delay_us as u64),
            );
        }
    }
    Ok(table.len())
}

// ── Pre-baked tiny tables ───────────────────────────────────────────
//
// Real per-chip tables are too volumetric to land in this stage. We
// ship a minimal "BB pre-init" snippet derived from
// `rtw89_mac_enable_bb_rf` (mac.c:4172) — that captures the canonical
// "set the bits / poll the ready" idiom every per-chip table extends.

use super::mac_init::{
    PHYREG_SET_ALL_CYCLE, R_AX_PHYREG_SET, R_AX_WLRF_CTRL, WLRF_ENABLE_MASK,
};

/// Bootstrap BB / RF enable as one PHY-table walk. Functionally
/// identical to `mac_init::enable_bb_rf` but drives the walker so the
/// path the per-chip tables will hit is exercised.
pub const BB_RF_BOOTSTRAP_TABLE: &[PhyEntry] = &[
    // WLRF_CTRL: set all four enable bits.
    pw(R_AX_WLRF_CTRL, WLRF_ENABLE_MASK, WLRF_ENABLE_MASK),
    // PHYREG_SET: pulse ALL_CYCLE.
    pw(R_AX_PHYREG_SET, PHYREG_SET_ALL_CYCLE as u32, 0xFF),
    // Small settle delay (Linux uses 1 ms).
    pd(1000),
];

// ── TX power table envelope ─────────────────────────────────────────
//
// rtw89 TX-power tables are byrate (`rtw89_phy_load_txpwr_byrate` —
// phy.c:500..700) and store per-band, per-bw, per-rate power in
// 0.5 dB steps. The "regulatory" pin is just a [-127.5, +127.5] dB
// envelope clamped per RF chain.

/// One byrate entry: per-rate (e.g. MCS index) maximum TX-power in
/// 0.5 dB steps. Linux: `struct rtw89_pwr_byrate`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxPwrByRate {
    /// Modulation index — for HT/VHT/HE the MCS, for legacy the rate
    /// table index.
    pub rate_idx: u8,
    /// Max TX power in 0.5 dB steps; +60 = +30.0 dBm.
    pub max_pwr_q1: i8,
}

/// Clamp a target TX power to the legal envelope of the rate.
pub const fn tx_pwr_clamp(target_q1: i16, byrate: TxPwrByRate) -> i16 {
    let max = byrate.max_pwr_q1 as i16;
    let min = -max; // symmetric envelope for non-amplified chains
    if target_q1 > max {
        max
    } else if target_q1 < min {
        min
    } else {
        target_q1
    }
}

/// Total byrate-table size for AX HT/VHT/HE: 12 MCS × 3 mode × 4 BW.
pub const TXPWR_BYRATE_TABLE_SIZE: usize = 12 * 3 * 4;
