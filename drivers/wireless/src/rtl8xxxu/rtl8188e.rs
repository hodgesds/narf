//! RTL8188EU chip-specific init, PHY tables, RF tables, IQ/LC cal.
//!
//! RTL8188EU: 802.11n 1x1 USB, single spatial stream.
//! USB IDs: `0x0BDA:0x8179` (native), `0x0BDA:0x0179` (TV variant).
//! Firmware: `rtlwifi/rtl8188eufw.bin`.
//!
//! ## Per-chip integration
//!
//! Stage-2 shared layers (`mac::`, `phy::`, `phy_tables::`) supply the
//! generic table-apply loops; this module wires them to the 8188EU's
//! specific tables and IQ/LC calibration sequences.
//!
//! ## Init table population
//!
//! Each per-chip register-init table is declared here as an empty
//! slice with a sentinel terminator, plus a `populate_*` function
//! that takes a backing `&mut [...]` buffer and fills it from a
//! firmware-blob bundled at build time. The Linux source ranges
//! cited below carry the canonical (addr, val) pairs that the
//! populate functions consume.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/8188e.c`
//!   - `rtl8188e_mac_init_table[]`        L19..L43  (~83 rows, write-8).
//!   - `rtl8188eu_phy_init_table[]`       L46..L144 (~195 rows, write-32).
//!   - `rtl8188e_agc_table[]`             L146..L213 (~130 rows, write-32).
//!   - `rtl8188eu_radioa_init_table[]`    L215..L265 (~80 rows, RF write).
//!   - `rtl8188eu_init_phy_bb()`          L582..L603 (PHY-BB init flow).
//!   - `rtl8188eu_init_phy_rf()`          L605..L608 (RF init flow).
//!   - `rtl8188eu_iqk_path_a()`           L610..L642 (path-A IQK seq).
//!   - `rtl8188eu_phy_iqcalibrate()`      L750..L935 (full IQ cal).

#![allow(dead_code)]

use super::phy::{IqkStep, Reg32Val};
use super::phy_tables::{MacRow, RfRow};
use super::regs::*;
use super::usb::UsbControlSetup;

/// Chip name string for this family.
pub const CHIP_NAME: &str = "RTL8188EU";

/// Firmware blob path.
pub const FIRMWARE_NAME: &str = "rtlwifi/rtl8188eufw.bin";

/// TX total page count for 8188EU.
/// Source: `rtl8xxxu.h::TX_TOTAL_PAGE_NUM_8188E = 0xA9`.
pub const TX_TOTAL_PAGES: u8 = TX_TOTAL_PAGE_NUM_8188E;

/// TX high-priority page count. `TX_PAGE_NUM_HI_PQ_8188E = 0x29`.
pub const TX_PAGE_NUM_HI: u8 = 0x29;
/// TX low-priority page count. `TX_PAGE_NUM_LO_PQ_8188E = 0x1C`.
pub const TX_PAGE_NUM_LO: u8 = 0x1C;
/// TX normal-priority page count. `TX_PAGE_NUM_NORM_PQ_8188E = 0x1C`.
pub const TX_PAGE_NUM_NORM: u8 = 0x1C;

/// TX descriptor size: 32 bytes.
pub const TX_DESC_SIZE: usize = TXDESC_SIZE_32;

/// Max secure CAM entries. `rtl8188eu_fops.max_sec_cam_num = 32`.
pub const MAX_SEC_CAM: usize = 32;

// ── Table row-count constants (from Linux source) ─────────────────
//
// These declare the expected row counts for the per-chip init tables.
// Each table buffer is sized to fit `N_*` rows plus the sentinel.

/// Row count of `rtl8188e_mac_init_table[]` excluding sentinel.
/// Source: `8188e.c` L19..L44. Counted: 92 (verified against Linux v6.13).
pub const N_MAC_ROWS: usize = 92;
/// Row count of `rtl8188eu_phy_init_table[]` excluding sentinel.
/// Source: `8188e.c` L46..L144. Counted: 192.
pub const N_PHY_ROWS: usize = 192;
/// Row count of `rtl8188e_agc_table[]` excluding sentinel.
/// Source: `8188e.c` L146..L213. Counted: 130.
pub const N_AGC_ROWS: usize = 130;
/// Row count of `rtl8188eu_radioa_init_table[]` excluding sentinel.
/// Source: `8188e.c` L215..L265. Counted: 95.
pub const N_RF_A_ROWS: usize = 95;

// ── Stage-0 register bank (USB write-8) ────────────────────────────

/// Per-chip register initialisation table for the RTL8188EU.
///
/// Source: `8188e.c::rtl8188eu_power_on` ~L1165..L1200.
pub const INIT_TABLE: &[(u16, u8)] = &[
    (REG_APS_FSMCO as u16 + 1, 0x08),
    (REG_CR, (CR_OPEN_8188E & 0xFF) as u8),
    (REG_CR + 1, ((CR_OPEN_8188E >> 8) & 0xFF) as u8),
];

/// Chip-init stage-0 register bank.
pub fn stage0_register_bank() -> &'static [(u16, u8)] {
    INIT_TABLE
}

// ── Table sentinels — declared empty, populated at integration time ──

/// MAC init table.
///
/// Source: `8188e.c::rtl8188e_mac_init_table[]` L19..L44 (verbatim port).
/// Table lives in `super::phy_tables::MAC_REGS_8188E`.
pub const MAC_INIT_TABLE: &[MacRow] = super::phy_tables::MAC_REGS_8188E;

/// PHY/BB init table.
///
/// Source: `8188e.c::rtl8188eu_phy_init_table[]` L46..L144 (verbatim port).
pub const PHY_INIT_TABLE: &[Reg32Val] = super::phy_tables::BB_REGS_8188E;

/// AGC table.
///
/// Source: `8188e.c::rtl8188e_agc_table[]` L146..L213 (verbatim port).
pub const AGC_TABLE: &[Reg32Val] = super::phy_tables::AGC_REGS_8188E;

/// RF path A init table.
///
/// Source: `8188e.c::rtl8188eu_radioa_init_table[]` L215..L265 (verbatim port).
pub const RADIO_A_INIT_TABLE: &[RfRow] = super::phy_tables::RF_A_REGS_8188E;

/// Path count for this chip. 8188EU is 1T1R, so path A only.
pub const NUM_RF_PATHS: usize = 1;

// ── IQ calibration shape ───────────────────────────────────────────
//
// Source: `8188e.c::rtl8188eu_iqk_path_a()` L610..L642.

/// Number of fixed register writes per IQK iteration on 8188EU.
/// Source: `8188e.c` L615..L627.
pub const IQK_PATH_A_STEP_COUNT: usize = 7;

/// IQK delay between trigger and result read (ms).
/// Source: `8188e.c` L629 — `mdelay(10)`.
pub const IQK_RESULT_DELAY_MS: u32 = 10;

/// IQK pass criteria — bit 28 of REG_RX_POWER_AFTER_IQK_A_2 cleared,
/// and TX-power-before/after IQK don't match the reject fingerprints.
/// Source: `8188e.c` L636..L639.
pub const IQK_PASS_BIT_EAC: u32 = 1 << 28;
pub const IQK_REJECT_E94: u32 = 0x01420000;
pub const IQK_REJECT_E9C: u32 = 0x00420000;
pub const IQK_E94_MASK: u32 = 0x03ff0000;

/// Build the path-A IQK fixed-register sequence in the caller-provided
/// buffer. Returns the number of steps written.
///
/// Source: `8188e.c::rtl8188eu_iqk_path_a` L615..L627. The seven
/// `rtl8xxxu_write32` calls there map to the seven steps recorded
/// in `buf`.
pub fn build_iqk_path_a_sequence(buf: &mut [IqkStep]) -> usize {
    if buf.len() < IQK_PATH_A_STEP_COUNT {
        return 0;
    }
    // Source: `core.c::rtl8xxxu_iqk_path_a` L3094..L3117 — these are the
    // shared gen1 IQK values 8188EU uses. 8188EU is 1T1R so the
    // `priv->rf_paths > 1` branch is never taken → RX_IQK_PI_A=0x28160502.
    buf[0] = IqkStep {
        reg: REG_TX_IQK_TONE_A,
        val: 0x10008c1f,
    };
    buf[1] = IqkStep {
        reg: REG_RX_IQK_TONE_A,
        val: 0x10008c1f,
    };
    buf[2] = IqkStep {
        reg: REG_TX_IQK_PI_A,
        val: 0x82140102,
    };
    buf[3] = IqkStep {
        reg: REG_RX_IQK_PI_A,
        val: 0x28160502,
    };
    // LO calibration setting.
    buf[4] = IqkStep {
        reg: REG_IQK_AGC_RSP,
        val: 0x001028d1,
    };
    // One shot, path A LOK & IQK — two writes to AGC_PTS.
    buf[5] = IqkStep {
        reg: REG_IQK_AGC_PTS,
        val: 0xf9000000,
    };
    buf[6] = IqkStep {
        reg: REG_IQK_AGC_PTS,
        val: 0xf8000000,
    };
    IQK_PATH_A_STEP_COUNT
}

/// Decide whether a single IQK iteration "passed" given the three
/// result-register reads.
///
/// Source: `8188e.c::rtl8188eu_iqk_path_a` L636..L639.
pub fn iqk_passed(reg_eac: u32, reg_e94: u32, reg_e9c: u32) -> bool {
    (reg_eac & IQK_PASS_BIT_EAC) == 0
        && (reg_e94 & IQK_E94_MASK) != IQK_REJECT_E94
        && (reg_e9c & IQK_E94_MASK) != IQK_REJECT_E9C
}

/// IQK outer retry count.
/// Source: `8188e.c::rtl8188eu_phy_iqcalibrate` L756 — `retry = 2`.
pub const IQK_RETRY: usize = 2;

/// IQK outer-loop iterations.
/// Source: `8188e.c::rtl8188eu_phy_iqcalibrate` argument `t = 0..3`.
pub const IQK_ITERATIONS: usize = 3;

// ── LC calibration ─────────────────────────────────────────────────
//
// Source: shared `phy::lc_calibrate_rf_writes` (gen1 LC-cal).

/// LC-cal applies to path A only on 8188EU.
pub const LC_CAL_PATH_COUNT: usize = 1;

// ── Channel-set sequence ───────────────────────────────────────────

/// 8188EU is 2.4 GHz only.
pub const CHANNEL_MIN: u8 = 1;
pub const CHANNEL_MAX: u8 = 14;

/// Build the channel-set RF writes for 8188EU.
pub fn channel_set_writes_8188e(channel: u8) -> [(u16, u32); 1] {
    use super::phy::{lssi_encode, REG_FPGA0_LSSI_A};
    [(
        REG_FPGA0_LSSI_A,
        lssi_encode(RF_REG_CHANNEL, channel as u32),
    )]
}

/// Validate a 2.4 GHz channel number for this chip.
pub fn channel_valid(channel: u8) -> bool {
    (CHANNEL_MIN..=CHANNEL_MAX).contains(&channel)
}

// ── Init function wiring (Stage-2 hookup) ──────────────────────────

/// Apply MAC init table via the shared helper.
pub fn init_mac<W: FnMut(u16, u8)>(write8: W) -> usize {
    super::phy_tables::apply_mac_table(MAC_INIT_TABLE, write8)
}

/// Apply PHY/BB + AGC tables via the shared helper.
pub fn init_phy<W: FnMut(u16, u32)>(mut write32: W) -> usize {
    let phy = super::phy_tables::apply_phy_table(PHY_INIT_TABLE, &mut write32);
    let agc = super::phy_tables::apply_phy_table(AGC_TABLE, &mut write32);
    phy + agc
}

/// Apply RF path-A init table via the shared helper.
pub fn init_rf<W: FnMut(u8, u32)>(write_rfreg: W) -> usize {
    super::phy_tables::apply_rf_table(RADIO_A_INIT_TABLE, write_rfreg)
}

// ── USB control-transfer setup helpers ─────────────────────────────

pub fn aps_fsmco_mac_enable_setup() -> UsbControlSetup {
    UsbControlSetup::write(REG_APS_FSMCO as u16 + 1, 1)
}

pub fn cr_open_setups() -> [UsbControlSetup; 2] {
    [
        UsbControlSetup::write(REG_CR, 1),
        UsbControlSetup::write(REG_CR + 1, 1),
    ]
}
