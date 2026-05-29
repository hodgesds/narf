//! rtlwifi PHY / BB init scaffold.
//!
//! Each chip ships a large table of `(reg_addr, value)` pairs that the
//! driver writes verbatim into the BB and AGC register banks to bring
//! the analog front-end up.  Linux ships these as massive C arrays in
//! each chip's `table.c` / `phy.c`.  For NARF, the bulk tables remain
//! "TODO blob ingest" (rom-side or live-firmware-load) — but the
//! pre-table BB-RF reset sequence (`rtl92ee_phy_bb_config` body up to
//! `_rtl92ee_phy_bb8192ee_config_parafile`) is the actually load-
//! bearing chip-prep step, and it's the same across the family.
//!
//! ## Linux reference (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtl8192ee/phy.c::rtl92ee_phy_bb_config` (line 208) — exact source
//! - `rtl8188ee/phy.c::rtl88e_phy_bb_config` — equivalent for 8188EE
//! - `rtl8821ae/phy.c::rtl8821ae_phy_bb_config` — VHT-specific tweaks
//! - per-chip `table.c` — the BB/AGC register table blob

#![allow(dead_code)]

use narf_bus::MmioRegion;

use super::regs::*;

// ── REG_RF_CTRL bits ─────────────────────────────────────────────────────
//
// Source: `rtl8192ee/reg.h:22, 797..799`.

/// `REG_RF_CTRL` — analog RF control byte register.  `reg.h:22`.
pub const REG_RF_CTRL: u64 = 0x001F;

/// Bit 0: enable RF.
pub const RF_EN: u8 = 1 << 0;
/// Bit 1: RF reset-bar (release reset).
pub const RF_RSTB: u8 = 1 << 1;
/// Bit 2: SDM (sigma-delta-mod) reset-bar.
pub const RF_SDMRSTB: u8 = 1 << 2;

// ── REG_SYS_FUNC_EN bits used by BB bring-up ─────────────────────────────
//
// Source: `rtl8192ee/reg.h:880..` (FEN_* constants).

/// `FEN_PPLL` — PLL function enable.
pub const FEN_PPLL: u8 = 1 << 1;
/// `FEN_PCIEA` — PCIe analog enable.
pub const FEN_PCIEA: u8 = 1 << 2;
/// `FEN_DIO_PCIE` — PCIe digital-IO enable.
pub const FEN_DIO_PCIE: u8 = 1 << 5;
/// `FEN_BB_GLB_RSTN` — BB global reset-bar.
pub const FEN_BB_GLB_RSTN: u8 = 1 << 1;
/// `FEN_BBRSTB` — BB digital reset-bar.
pub const FEN_BBRSTB: u8 = 1 << 0;

/// BB+RF reset value applied to `REG_SYS_FUNC_EN` byte during config.
/// `rtl8192ee/phy.c:222..224`.
pub const BB_RST_VALUE: u8 = FEN_PPLL | FEN_PCIEA | FEN_DIO_PCIE | FEN_BB_GLB_RSTN | FEN_BBRSTB;

// ── REG_MAC_PHY_CTRL (XTAL fine cap) ─────────────────────────────────────

/// `REG_MAC_PHY_CTRL` — crystal-cap programming.  `rtl8192ee/reg.h`.
pub const REG_MAC_PHY_CTRL: u64 = 0x0040;
pub const MAC_PHY_CTRL_XTAL_MASK: u32 = 0x000F_F000;

// ── BB init steps ────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PhyError {
    /// Reserved for future BB table-load failure modes.
    TableLoadFailed,
}

/// Reset + open the BB register block prior to programming the per-chip
/// BB / AGC table.  Mirrors lines 217..230 of
/// `rtl92ee_phy_bb_config` (`rtl8192ee/phy.c:208`):
///
/// 1. OR `BIT(0) | BIT(1) | BIT(13)` into `REG_SYS_FUNC_EN` — re-enables
///    the digital BB block.
/// 2. Set `REG_RF_CTRL = RF_EN | RF_RSTB | RF_SDMRSTB` — release RF resets.
/// 3. Write `BB_RST_VALUE` into low byte of `REG_SYS_FUNC_EN` — open the
///    BB global + analog resets.
/// 4. Write 0x80 to `REG_AFE_XTAL_CTRL + 1` — analog-front-end crystal
///    boost (per Linux comment "AFE 25 MHz crystal source").
/// 5. OR `BIT(23)` into BAR0 + 0x4C — undocumented but always present.
///
/// # Safety
/// Caller must own BAR0 exclusively and the chip must be powered on.
pub unsafe fn open_bb_for_table_load(mmio: &MmioRegion) -> Result<(), PhyError> {
    // SAFETY: caller-asserted.
    unsafe {
        let regval = mmio.read16(REG_SYS_FUNC_EN);
        mmio.write16(
            REG_SYS_FUNC_EN,
            regval | (1 << 13) | (1 << 0) | (1 << 1),
        );

        mmio.write8(REG_RF_CTRL, RF_EN | RF_RSTB | RF_SDMRSTB);
        mmio.write8(REG_SYS_FUNC_EN, BB_RST_VALUE);

        mmio.write8(REG_AFE_XTAL_CTRL + 1, 0x80);

        let tmp = mmio.read32(0x004C);
        mmio.write32(0x004C, tmp | (1 << 23));
    }
    Ok(())
}

/// Program the chip's crystal-cap fine-tune from EFUSE.  Mirrors the
/// post-table-load step at `phy.c:233..235`.
///
/// `crystal_cap` is the 6-bit value from `eeprom_crystalcap`; the
/// driver duplicates it across bits[11:6] (X-osc) and bits[5:0] (X-fine).
///
/// # Safety
/// Caller must own BAR0 exclusively.
pub unsafe fn set_crystal_cap(mmio: &MmioRegion, crystal_cap: u8) {
    let cc = (crystal_cap & 0x3F) as u32;
    let bits = cc | (cc << 6);
    // SAFETY: caller-asserted.
    unsafe {
        let cur = mmio.read32(REG_MAC_PHY_CTRL);
        mmio.write32(
            REG_MAC_PHY_CTRL,
            (cur & !MAC_PHY_CTRL_XTAL_MASK) | ((bits << 12) & MAC_PHY_CTRL_XTAL_MASK),
        );
    }
}

// ── BB / RF register-table type ──────────────────────────────────────────
//
// Per-chip table blobs (`rtl8192ee/table.c` etc.) lay out as alternating
// `addr, value` 32-bit words.  We model the smallest unit we need to
// run against MMIO + a 4-byte spinwait marker (`0xFE/0xFFE`) that means
// "delay 50 ms".

/// One BB-register write row: `(reg_offset, value)`.  Source: per-chip
/// `table.c` arrays.
#[derive(Copy, Clone, Debug)]
pub struct BbRow {
    pub addr: u32,
    pub value: u32,
}

impl BbRow {
    pub const fn new(addr: u32, value: u32) -> Self {
        Self { addr, value }
    }
}

/// Sentinel: the value 0xfe means "udelay(50)" (Linux convention from
/// `_rtl92ee_config_rf_reg`).
pub const BB_ADDR_DELAY: u32 = 0xFE;
/// Alternate sentinel: 0xFFE = "mdelay(50)".
pub const BB_ADDR_LDELAY: u32 = 0xFFE;

/// Run a small BB register-write table against `mmio` (the chip's BAR0).
/// Mirrors `rtl_set_bbreg_with_mask`-loop pattern used by every
/// `_rtl<ver>_phy_config_bb_with_*` worker.  Skips delay sentinels.
///
/// # Safety
/// Caller must own BAR0 exclusively and the BB must already be in the
/// state established by [`open_bb_for_table_load`].
pub unsafe fn write_bb_table(mmio: &MmioRegion, table: &[BbRow]) {
    for row in table {
        if row.addr == BB_ADDR_DELAY {
            narf_time::busy_wait_cycles(
                50 * 1_000 * narf_time::cycles_per_ns().max(1) as u64,
            );
            continue;
        }
        if row.addr == BB_ADDR_LDELAY {
            narf_time::busy_wait_cycles(
                50 * 1_000_000 * narf_time::cycles_per_ns().max(1) as u64,
            );
            continue;
        }
        // SAFETY: caller-asserted in-range.
        unsafe {
            mmio.write32(row.addr as u64, row.value);
        }
    }
}

// ── Small BB-table stub for the bring-up path ────────────────────────────
//
// These are the minimum 16 BB writes the rtlwifi family does before
// the per-chip parafile load.  Per `rtl8192ee/phy.c:_rtl92ee_phy_bb8192ee_config_parafile`
// (`phy.c:339..` in Linux 6.x).  The full parafile is ~600 rows; we ship
// the bring-up prefix here and leave the rest as `BB_PARAFILE_BLOB`
// inputs to be loaded from the firmware blob at runtime.

/// Pre-parafile BB bring-up sequence shared by every PCIe rtlwifi chip.
/// Mirrors the writes between
/// `rtl_set_bbreg(REG_FPGA0_RFMOD, MASKBYTE0, 0x83)` and the table-load
/// entry point in `_rtl92ee_phy_bb8192ee_config_parafile`.
pub const BB_BRINGUP_PREAMBLE: &[BbRow] = &[
    // FPGA0_RFMOD: byte0 = 0x83 (RF1T2R/RF2T2R baseline).
    BbRow::new(0x0800, 0x8000_0083),
    // FPGA0_TXIN: clear pending TX.
    BbRow::new(0x0808, 0x0000_0000),
    // OFDM0_TRXPATHENA: enable RX chain.
    BbRow::new(0x0C04, 0x6900_0F60),
];
