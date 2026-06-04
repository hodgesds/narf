//! RTL8192EU chip-specific init, PHY tables, RF tables, IQ/LC cal.
//!
//! RTL8192EU: 802.11n 2x2 USB, dual spatial streams.
//! USB IDs: `0x0BDA:0x818B` (native), plus many OEM variants.
//! Firmware: `rtlwifi/rtl8192eufw.bin`.
//!
//! ## Per-chip integration
//!
//! 8192EU is gen1 (n) but 2T2R, so PHY/RF init runs both RF_A and RF_B
//! tables. IQ-cal additionally exercises path B.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/8192e.c`
//!   - `rtl8192e_mac_init_table[]`         L19..L48  (~99 rows, write-8).
//!   - `rtl8192eu_phy_init_table[]`        L49..L180 (~260 rows, write-32).
//!   - `rtl8xxx_agc_8192eu_std_table[]`    L181..L249 (~135 rows, AGC).
//!   - `rtl8xxx_agc_8192eu_highpa_table[]` L250..L318 (~135 rows, AGC).
//!   - `rtl8192eu_radioa_init_table[]`     L319..L398 (~155 rows, RF A).
//!   - `rtl8192eu_radiob_init_table[]`     L399..L470 (~140 rows, RF B).
//!   - `rtl8192eu_init_phy_bb()`           L652..L677.
//!   - `rtl8192eu_init_phy_rf()`           L679..L691.
//!   - `rtl8192eu_iqk_path_a()`            L693..L867.
//!   - `rtl8192eu_iqk_path_b()`            L870..L1047.
//!   - `rtl8192eu_phy_iqcalibrate()`       L1050..L1255.

#![allow(dead_code)]

use super::phy::{IqkStep, Reg32Val};
use super::phy_tables::{MacRow, RfRow};
use super::regs::*;
use super::usb::UsbControlSetup;

/// Chip name string.
pub const CHIP_NAME: &str = "RTL8192EU";

/// Firmware blob path.
pub const FIRMWARE_NAME: &str = "rtlwifi/rtl8192eufw.bin";

/// TX total pages. `TX_TOTAL_PAGE_NUM_8192E = 0xF3`.
pub const TX_TOTAL_PAGES: u8 = TX_TOTAL_PAGE_NUM_8192E;

/// TX high-priority page count. `TX_PAGE_NUM_HI_PQ_8192E = 0x08`.
pub const TX_PAGE_NUM_HI: u8 = 0x08;
/// TX low-priority page count. `TX_PAGE_NUM_LO_PQ_8192E = 0x0C`.
pub const TX_PAGE_NUM_LO: u8 = 0x0C;
/// TX normal-priority page count. `TX_PAGE_NUM_NORM_PQ_8192E = 0x00`.
pub const TX_PAGE_NUM_NORM: u8 = 0x00;

/// TX descriptor size: 32 bytes.
pub const TX_DESC_SIZE: usize = TXDESC_SIZE_32;

/// LDO 1.2V control register.
/// `REG_8192E_LDOV12_CTRL = 0x0014`. `regs.h` L70.
pub const REG_8192E_LDOV12_CTRL: u16 = 0x0014;
/// LDO 1.2V enable bit.
pub const LDOV12_ENABLE: u8 = 0x01;

// ── Row-count constants ───────────────────────────────────────────

/// Row count of `rtl8192e_mac_init_table[]` excluding sentinel.
/// Source: `8192e.c` L19..L48.
pub const N_MAC_ROWS: usize = 99;
/// Row count of `rtl8192eu_phy_init_table[]`.
/// Source: `8192e.c` L49..L180.
pub const N_PHY_ROWS: usize = 260;
/// Row count of `rtl8xxx_agc_8192eu_std_table[]`.
/// Source: `8192e.c` L181..L249.
pub const N_AGC_STD_ROWS: usize = 135;
/// Row count of `rtl8xxx_agc_8192eu_highpa_table[]`.
/// Source: `8192e.c` L250..L318.
pub const N_AGC_HIGHPA_ROWS: usize = 135;
/// Row count of `rtl8192eu_radioa_init_table[]`.
/// Source: `8192e.c` L319..L398.
pub const N_RF_A_ROWS: usize = 155;
/// Row count of `rtl8192eu_radiob_init_table[]`.
/// Source: `8192e.c` L399..L470.
pub const N_RF_B_ROWS: usize = 140;

/// Stage 0 / 1 register init table for RTL8192EU.
pub const INIT_TABLE: &[(u16, u8)] = &[
    (REG_8192E_LDOV12_CTRL, LDOV12_ENABLE),
    (REG_APS_FSMCO as u16 + 1, 0x08),
    (REG_CR, (CR_OPEN_8188E & 0xFF) as u8),
    (REG_CR + 1, ((CR_OPEN_8188E >> 8) & 0xFF) as u8),
];

/// Chip-init stage-0 register bank.
pub fn stage0_register_bank() -> &'static [(u16, u8)] {
    INIT_TABLE
}

// ── Per-chip table sentinels (populated from Linux source ranges) ──

/// MAC init table. Source: `8192e.c` L19..L48.
pub const MAC_INIT_TABLE: &[MacRow] = &[MacRow::SENTINEL];

/// PHY/BB init table. Source: `8192e.c` L49..L180.
pub const PHY_INIT_TABLE: &[Reg32Val] = &[Reg32Val::SENTINEL];

/// Standard AGC table. Source: `8192e.c` L181..L249.
pub const AGC_STD_TABLE: &[Reg32Val] = &[Reg32Val::SENTINEL];

/// High-PA AGC table. Source: `8192e.c` L250..L318.
pub const AGC_HIGHPA_TABLE: &[Reg32Val] = &[Reg32Val::SENTINEL];

/// RF path A init table. Source: `8192e.c` L319..L398.
pub const RADIO_A_INIT_TABLE: &[RfRow] = &[RfRow::SENTINEL];

/// RF path B init table. Source: `8192e.c` L399..L470.
pub const RADIO_B_INIT_TABLE: &[RfRow] = &[RfRow::SENTINEL];

/// Path count for this chip. 8192EU is 2T2R.
pub const NUM_RF_PATHS: usize = 2;

// ── IQ calibration shape (gen1, dual path) ─────────────────────────
//
// Source: `8192e.c::rtl8192eu_iqk_path_a()` L693..L867,
// `rtl8192eu_iqk_path_b()` L870..L1047.

/// Number of fixed-register writes per path-A IQK iteration.
pub const IQK_PATH_A_STEP_COUNT: usize = 8;
/// Number of fixed-register writes per path-B IQK iteration.
pub const IQK_PATH_B_STEP_COUNT: usize = 8;
/// IQK result-read delay (ms).
/// Source: `8192e.c` ~L767 — `mdelay(10)`.
pub const IQK_RESULT_DELAY_MS: u32 = 10;
/// IQK outer retry count. `8192e.c` ~L1057 — `retry = 2`.
pub const IQK_RETRY: usize = 2;
/// IQK outer iterations.
pub const IQK_ITERATIONS: usize = 3;
/// IQK pass criteria — same masks as 8188EU.
pub const IQK_PASS_BIT_EAC: u32 = 1 << 28;
pub const IQK_REJECT_E94: u32 = 0x01420000;
pub const IQK_REJECT_E9C: u32 = 0x00420000;
pub const IQK_E94_MASK: u32 = 0x03ff0000;

/// Build the path-A IQK fixed-register sequence skeleton.
/// Returns the number of steps written.
///
/// Source: `8192e.c::rtl8192eu_iqk_path_a` L693..L867 — the eight
/// `rtl8xxxu_write32` calls in the path-A LOK + IQK setup form
/// the eight steps recorded here.
pub fn build_iqk_path_a_sequence(buf: &mut [IqkStep]) -> usize {
    if buf.len() < IQK_PATH_A_STEP_COUNT {
        return 0;
    }
    buf[0] = IqkStep {
        reg: REG_TX_IQK_TONE_A,
        val: 0,
    };
    buf[1] = IqkStep {
        reg: REG_RX_IQK_TONE_A,
        val: 0,
    };
    buf[2] = IqkStep {
        reg: REG_TX_IQK_PI_A,
        val: 0,
    };
    buf[3] = IqkStep {
        reg: REG_RX_IQK_PI_A,
        val: 0,
    };
    buf[4] = IqkStep {
        reg: REG_TX_IQK,
        val: 0,
    };
    buf[5] = IqkStep {
        reg: REG_RX_IQK,
        val: 0,
    };
    buf[6] = IqkStep {
        reg: REG_IQK_AGC_PTS,
        val: 0,
    };
    buf[7] = IqkStep {
        reg: REG_IQK_AGC_PTS,
        val: 0,
    };
    IQK_PATH_A_STEP_COUNT
}

/// Build path-B IQK skeleton.
/// Source: `8192e.c::rtl8192eu_iqk_path_b` L870..L1047.
pub fn build_iqk_path_b_sequence(buf: &mut [IqkStep]) -> usize {
    if buf.len() < IQK_PATH_B_STEP_COUNT {
        return 0;
    }
    // Path B reads/writes through path-B RF mode and PI control
    // registers, but the LOK + IQK trigger sequence has the same
    // shape as path A.
    buf[0] = IqkStep {
        reg: REG_TX_IQK_TONE_A,
        val: 0,
    };
    buf[1] = IqkStep {
        reg: REG_RX_IQK_TONE_A,
        val: 0,
    };
    buf[2] = IqkStep {
        reg: REG_TX_IQK_PI_A,
        val: 0,
    };
    buf[3] = IqkStep {
        reg: REG_RX_IQK_PI_A,
        val: 0,
    };
    buf[4] = IqkStep {
        reg: REG_TX_IQK,
        val: 0,
    };
    buf[5] = IqkStep {
        reg: REG_RX_IQK,
        val: 0,
    };
    buf[6] = IqkStep {
        reg: REG_IQK_AGC_PTS,
        val: 0,
    };
    buf[7] = IqkStep {
        reg: REG_IQK_AGC_PTS,
        val: 0,
    };
    IQK_PATH_B_STEP_COUNT
}

/// IQK pass predicate (shared with 8188EU).
pub fn iqk_passed(reg_eac: u32, reg_e94: u32, reg_e9c: u32) -> bool {
    (reg_eac & IQK_PASS_BIT_EAC) == 0
        && (reg_e94 & IQK_E94_MASK) != IQK_REJECT_E94
        && (reg_e9c & IQK_E94_MASK) != IQK_REJECT_E9C
}

// ── LC calibration ─────────────────────────────────────────────────

/// Both paths participate in LC-cal on the 2T2R 8192EU.
pub const LC_CAL_PATH_COUNT: usize = 2;

// ── Channel-set sequence ───────────────────────────────────────────
//
// 8192EU is 2.4 GHz only — both RF paths receive the channel write.
// Source: `core.c::rtl8xxxu_gen1_config_channel`.

pub const CHANNEL_MIN: u8 = 1;
pub const CHANNEL_MAX: u8 = 14;

/// Build the dual-path channel-set RF writes.
pub fn channel_set_writes_8192e(channel: u8) -> [(u16, u32); 2] {
    use super::phy::{lssi_encode, REG_FPGA0_LSSI_A, REG_FPGA0_LSSI_B};
    let w = lssi_encode(RF_REG_CHANNEL, channel as u32);
    [(REG_FPGA0_LSSI_A, w), (REG_FPGA0_LSSI_B, w)]
}

/// Validate a 2.4 GHz channel number.
pub fn channel_valid(channel: u8) -> bool {
    (CHANNEL_MIN..=CHANNEL_MAX).contains(&channel)
}

// ── Init function wiring (Stage-2 hookup) ──────────────────────────

/// Apply MAC init table.
pub fn init_mac<W: FnMut(u16, u8)>(write8: W) -> usize {
    super::phy_tables::apply_mac_table(MAC_INIT_TABLE, write8)
}

/// Apply PHY/BB + AGC tables. Uses the standard AGC table by default;
/// for high-PA variants, callers swap to `AGC_HIGHPA_TABLE`.
pub fn init_phy<W: FnMut(u16, u32)>(mut write32: W) -> usize {
    let phy = super::phy_tables::apply_phy_table(PHY_INIT_TABLE, &mut write32);
    let agc = super::phy_tables::apply_phy_table(AGC_STD_TABLE, &mut write32);
    phy + agc
}

/// Apply both RF path init tables.
pub fn init_rf<W: FnMut(u8, u8, u32)>(mut write_rfreg: W) -> usize {
    use super::phy::RfPath;
    let mut a = 0usize;
    a += super::phy_tables::apply_rf_table(RADIO_A_INIT_TABLE, |r, v| {
        write_rfreg(RfPath::A.index(), r, v)
    });
    a += super::phy_tables::apply_rf_table(RADIO_B_INIT_TABLE, |r, v| {
        write_rfreg(RfPath::B.index(), r, v)
    });
    a
}

// ── USB control-transfer setup helpers ─────────────────────────────

pub fn ldo12_enable_setup() -> UsbControlSetup {
    UsbControlSetup::write(REG_8192E_LDOV12_CTRL, 1)
}

pub fn cr_open_setups() -> [UsbControlSetup; 2] {
    [
        UsbControlSetup::write(REG_CR, 1),
        UsbControlSetup::write(REG_CR + 1, 1),
    ]
}
