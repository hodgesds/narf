//! RTL8723BU chip-specific init, PHY tables, RF tables, IQ/LC cal, BT-coex.
//!
//! RTL8723BU: 802.11n 1x1 USB + Bluetooth combo (single 2.4 GHz antenna).
//! USB IDs: `0x0BDA:0xB720` (native), `0x7392:0xA611` (rebranded).
//! Firmware: `rtlwifi/rtl8723bufw.bin`.
//!
//! ## Per-chip integration
//!
//! 8723B is gen2 (uses `rtl8xxxu_gen2_*` shared helpers) but only 1T1R.
//! Multi-function EFUSE cell selection happens in the EFUSE preamble.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/8723b.c`
//!   - `rtl8723b_mac_init_table[]`         L19..L49  (~95 rows, write-8).
//!   - `rtl8723b_phy_1t_init_table[]`      L50..L150 (~200 rows, write-32).
//!   - `rtl8xxx_agc_8723bu_table[]`        L151..L220 (~140 rows, AGC).
//!   - `rtl8723bu_radioa_1t_init_table[]`  L222..L300 (~155 rows, RF A).
//!   - `rtl8723bu_init_phy_bb()`           L498..L519.
//!   - `rtl8723bu_init_phy_rf()`           L521..L535.
//!   - `rtl8723bu_iqk_path_a()`            L575..L893.
//!   - `rtl8723bu_phy_iqcalibrate()`       L894..L1127.
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c`
//!   - `rtl8723bu_set_coex_with_type()`    L5867..L5916 (coex tables).
//!   - `rtl8723bu_update_bt_link_info()`   L5918..L5980 (BT state).

#![allow(dead_code)]

use super::phy::{IqkStep, Reg32Val};
use super::phy_tables::{MacRow, RfRow};
use super::regs::*;
use super::usb::UsbControlSetup;

/// Chip name string.
pub const CHIP_NAME: &str = "RTL8723BU";

/// Firmware blob path.
pub const FIRMWARE_NAME: &str = "rtlwifi/rtl8723bufw.bin";

/// TX total pages. `TX_TOTAL_PAGE_NUM_8723B = 0xF7`.
pub const TX_TOTAL_PAGES: u8 = TX_TOTAL_PAGE_NUM_8723B;

/// TX high-priority page count. `TX_PAGE_NUM_HI_PQ_8723B = 0x0C`.
pub const TX_PAGE_NUM_HI: u8 = 0x0C;
/// TX low-priority page count. `TX_PAGE_NUM_LO_PQ_8723B = 0x02`.
pub const TX_PAGE_NUM_LO: u8 = 0x02;
/// TX normal-priority page count. `TX_PAGE_NUM_NORM_PQ_8723B = 0x02`.
pub const TX_PAGE_NUM_NORM: u8 = 0x02;

/// TX descriptor size: 32 bytes.
pub const TX_DESC_SIZE: usize = TXDESC_SIZE_32;

/// Number of channel groups for 8723B RF calibration.
pub const CHANNEL_GROUPS: usize = 6;
/// Maximum RF paths on 8723B.
pub const TX_COUNT: usize = 4;
/// Maximum RF paths.
pub const MAX_RF_PATHS: usize = 4;

// ── Row-count constants ───────────────────────────────────────────

/// Row count of `rtl8723b_mac_init_table[]`.
/// Source: `8723b.c` L19..L49.
pub const N_MAC_ROWS: usize = 95;
/// Row count of `rtl8723b_phy_1t_init_table[]`.
/// Source: `8723b.c` L50..L150.
pub const N_PHY_ROWS: usize = 200;
/// Row count of `rtl8xxx_agc_8723bu_table[]`.
/// Source: `8723b.c` L151..L220.
pub const N_AGC_ROWS: usize = 140;
/// Row count of `rtl8723bu_radioa_1t_init_table[]`.
/// Source: `8723b.c` L222..L300.
pub const N_RF_A_ROWS: usize = 155;

/// Stage 0 / 1 register init table for RTL8723BU.
pub const INIT_TABLE: &[(u16, u8)] = &[
    (REG_EFUSE_ACCESS, EFUSE_ACCESS_ENABLE),
    (REG_APS_FSMCO + 1, 0x08),
    (REG_CR, (CR_OPEN_8188E & 0xFF) as u8),
    (REG_CR + 1, ((CR_OPEN_8188E >> 8) & 0xFF) as u8),
];

/// Chip-init stage-0 register bank.
pub fn stage0_register_bank() -> &'static [(u16, u8)] {
    INIT_TABLE
}

// ── Per-chip table sentinels (populated at integration time) ───────

/// MAC init table. Source: `8723b.c` L19..L49.
pub const MAC_INIT_TABLE: &[MacRow] = &[MacRow::SENTINEL];

/// PHY/BB init table. Source: `8723b.c` L50..L150.
pub const PHY_INIT_TABLE: &[Reg32Val] = &[Reg32Val::SENTINEL];

/// AGC table. Source: `8723b.c` L151..L220.
pub const AGC_TABLE: &[Reg32Val] = &[Reg32Val::SENTINEL];

/// RF path A init table. Source: `8723b.c` L222..L300.
pub const RADIO_A_INIT_TABLE: &[RfRow] = &[RfRow::SENTINEL];

/// Path count. 8723BU is 1T1R.
pub const NUM_RF_PATHS: usize = 1;

// ── IQ calibration (gen2 path-A) ───────────────────────────────────
//
// Source: `8723b.c::rtl8723bu_iqk_path_a()` L575..L893.

/// Number of fixed-register writes per IQK iteration on 8723BU.
pub const IQK_PATH_A_STEP_COUNT: usize = 10;

/// IQK result-read delay (ms).
/// Source: `8723b.c` IQK path L860-ish — `mdelay(10)`.
pub const IQK_RESULT_DELAY_MS: u32 = 10;

/// IQK pass criteria — bit 28 of REG_RX_POWER_AFTER_IQK_A_2 cleared.
pub const IQK_PASS_BIT_EAC: u32 = 1 << 28;
pub const IQK_REJECT_E94: u32 = 0x01420000;
pub const IQK_REJECT_E9C: u32 = 0x00420000;
pub const IQK_E94_MASK: u32 = 0x03ff0000;

/// Build IQK fixed-register sequence skeleton.
/// Source: `8723b.c::rtl8723bu_iqk_path_a` L575..L893.
pub fn build_iqk_path_a_sequence(buf: &mut [IqkStep]) -> usize {
    if buf.len() < IQK_PATH_A_STEP_COUNT {
        return 0;
    }
    buf[0] = IqkStep {
        reg: REG_FPGA0_IQK,
        val: 0,
    };
    buf[1] = IqkStep {
        reg: REG_TX_IQK_TONE_A,
        val: 0,
    };
    buf[2] = IqkStep {
        reg: REG_RX_IQK_TONE_A,
        val: 0,
    };
    buf[3] = IqkStep {
        reg: REG_TX_IQK_PI_A,
        val: 0,
    };
    buf[4] = IqkStep {
        reg: REG_RX_IQK_PI_A,
        val: 0,
    };
    buf[5] = IqkStep {
        reg: REG_TX_IQK,
        val: 0,
    };
    buf[6] = IqkStep {
        reg: REG_RX_IQK,
        val: 0,
    };
    buf[7] = IqkStep {
        reg: REG_IQK_AGC_RSP,
        val: 0,
    };
    buf[8] = IqkStep {
        reg: REG_IQK_AGC_PTS,
        val: 0,
    };
    buf[9] = IqkStep {
        reg: REG_IQK_AGC_PTS,
        val: 0,
    };
    IQK_PATH_A_STEP_COUNT
}

/// IQK pass predicate.
pub fn iqk_passed(reg_eac: u32, reg_e94: u32, reg_e9c: u32) -> bool {
    (reg_eac & IQK_PASS_BIT_EAC) == 0
        && (reg_e94 & IQK_E94_MASK) != IQK_REJECT_E94
        && (reg_e9c & IQK_E94_MASK) != IQK_REJECT_E9C
}

/// IQK outer retry count. `8723b.c::rtl8723bu_phy_iqcalibrate` L900 — `retry = 2`.
pub const IQK_RETRY: usize = 2;

/// IQK outer iterations.
pub const IQK_ITERATIONS: usize = 3;

// ── LC calibration (post-init RF tweaks for D-cut PHY LCK) ─────────
//
// Source: `8723b.c::rtl8723bu_init_phy_rf` L521..L535. The chip
// requires a special LCK sequence written to RF_A reg 0xB0 with
// 200 ms hold, followed by RF mode write.

/// LCK pre-write to RF_A reg 0xB0.
pub const LC_CAL_RF_REG_PRE: u8 = 0xB0;
/// LCK initial value (per L529).
pub const LC_CAL_INIT_VAL: u32 = 0xDFBE0;
/// LCK final value (per L532).
pub const LC_CAL_FINAL_VAL: u32 = 0xDFFE0;
/// LCK hold duration (ms).
pub const LC_CAL_HOLD_MS: u32 = 200;
/// LCK MODE_AG write value (per L530).
pub const LC_CAL_MODE_AG_VAL: u32 = 0x8C01;

/// Build the LC-cal RF write sequence for 8723BU.
/// Returns (RF reg, value) pairs to apply via `write_rfreg` on path A.
pub fn lc_calibrate_sequence_8723b() -> [(u8, u32); 3] {
    [
        (LC_CAL_RF_REG_PRE, LC_CAL_INIT_VAL),
        (RF6052_REG_MODE_AG, LC_CAL_MODE_AG_VAL),
        // hold(200 ms) is the caller's responsibility.
        (LC_CAL_RF_REG_PRE, LC_CAL_FINAL_VAL),
    ]
}

// ── Channel-set sequence (gen2, 2.4 GHz only) ──────────────────────

pub const CHANNEL_MIN: u8 = 1;
pub const CHANNEL_MAX: u8 = 14;

/// Build the gen2-style channel-set RF write — encodes channel into
/// MODE_AG[7:0] via path-A LSSI.
/// Source: `core.c::rtl8xxxu_gen2_config_channel` L1328+.
pub fn channel_set_writes_8723b(channel: u8) -> [(u16, u32); 1] {
    use super::phy::{lssi_encode, REG_FPGA0_LSSI_A};
    [(
        REG_FPGA0_LSSI_A,
        lssi_encode(RF6052_REG_MODE_AG, channel as u32),
    )]
}

pub fn channel_valid(channel: u8) -> bool {
    (CHANNEL_MIN..=CHANNEL_MAX).contains(&channel)
}

// ── BT coexistence wiring ──────────────────────────────────────────

/// Re-export the BT coex decision logic so callers can drive the 8723BU
/// PTA from a single namespace.
pub use super::btcoex::{
    coex_table_write_for_type, coex_type_for_state, Bt8723b1AntStatus, BtLinkProfile,
    CoexTableWrite, CoexType, REG_BT_COEX_TABLE1, REG_BT_COEX_TABLE2, REG_BT_COEX_TABLE3,
    REG_BT_COEX_TABLE4,
};

/// Apply a BT coex table-write set via the supplied register writers.
///
/// Source: `core.c::rtl8723bu_set_coex_with_type` L5867..L5916.
pub fn apply_coex_table_write<W32: FnMut(u16, u32), W8: FnMut(u16, u8)>(
    write: &CoexTableWrite,
    mut write32: W32,
    mut write8: W8,
) {
    write32(REG_BT_COEX_TABLE1, write.table1);
    write32(REG_BT_COEX_TABLE2, write.table2);
    write32(REG_BT_COEX_TABLE3, write.table3);
    write8(REG_BT_COEX_TABLE4, write.table4);
}

// ── Init function wiring ───────────────────────────────────────────

pub fn init_mac<W: FnMut(u16, u8)>(write8: W) -> usize {
    super::phy_tables::apply_mac_table(MAC_INIT_TABLE, write8)
}

pub fn init_phy<W: FnMut(u16, u32)>(mut write32: W) -> usize {
    let phy = super::phy_tables::apply_phy_table(PHY_INIT_TABLE, &mut write32);
    let agc = super::phy_tables::apply_phy_table(AGC_TABLE, &mut write32);
    phy + agc
}

pub fn init_rf<W: FnMut(u8, u32)>(write_rfreg: W) -> usize {
    super::phy_tables::apply_rf_table(RADIO_A_INIT_TABLE, write_rfreg)
}

// ── USB control-transfer setup helpers ─────────────────────────────

/// Build USB control-transfer setup to select the WiFi EFUSE cell.
pub fn efuse_wifi_select_setup() -> UsbControlSetup {
    UsbControlSetup::write(REG_EFUSE_TEST, 4)
}

/// Apply `EFUSE_WIFI_SELECT` to an existing `REG_EFUSE_TEST` value.
pub fn apply_efuse_wifi_select(existing: u32) -> u32 {
    (existing & !EFUSE_SELECT_MASK) | EFUSE_WIFI_SELECT
}
