//! RTL8192EU LC calibration and two-path IQ calibration as
//! `rtl8xxxu_init_device` runs them (`fops->phy_lc_calibrate`, then
//! `fops->phy_iq_calibrate`).
//!
//! Linux references (GPL-2.0-or-later, Linux 7.3-rc4):
//! - `rtl8xxxu/core.c::{rtl8723a_phy_lc_calibrate, rtl8xxxu_save_regs,
//!   rtl8xxxu_restore_regs, rtl8xxxu_save_mac_regs,
//!   rtl8xxxu_restore_mac_regs, rtl8xxxu_path_adda_on,
//!   rtl8xxxu_mac_calibration, rtl8xxxu_gen2_simularity_compare,
//!   rtl8xxxu_fill_iqk_matrix_a, rtl8xxxu_fill_iqk_matrix_b}`
//! - `rtl8xxxu/8192e.c::{rtl8192eu_iqk_path_a, rtl8192eu_rx_iqk_path_a,
//!   rtl8192eu_iqk_path_b, rtl8192eu_rx_iqk_path_b,
//!   rtl8192eu_phy_iqcalibrate, rtl8192eu_phy_iq_calibrate}`
//!
//! Every register write, RF write, delay and retry follows Linux. The one
//! deliberate difference: Linux silently keeps the power-on IQ matrix when
//! the chosen candidate has no path-A TX result (and, on 2T boards, no
//! path-B TX result); this owner reports `Error::Calibration` instead, as
//! the RTL8188EU owner does. Any USB error is terminal immediately.

use super::firmware_transport::{ControlIo, Error, Owner};
use super::rtl8192e_phy::write_rfreg;
use super::rtl8192e_radio::read_rfreg;

const REG_GPIO_MUXCFG: u16 = 0x0040;
const REG_TXPAUSE: u16 = 0x0522;
const REG_BEACON_CTRL: u16 = 0x0550;
const REG_BEACON_CTRL_1: u16 = 0x0551;
const REG_FPGA0_XCD_SWITCH_CTRL: u16 = 0x085c;
const REG_FPGA0_XA_RF_INT_OE: u16 = 0x0860;
const REG_FPGA0_XB_RF_INT_OE: u16 = 0x0864;
const REG_FPGA0_XAB_RF_SW_CTRL: u16 = 0x0870;
const REG_FPGA0_XCD_RF_SW_CTRL: u16 = 0x0874;
const FPGA0_RF_PAPE: u32 = 1 << 10;
const FPGA0_RF_BD_CTRL_SHIFT: u32 = 16;
const REG_CCK0_AFE_SETTING: u16 = 0x0a04;
const REG_CONFIG_ANT_A: u16 = 0x0b68;
const REG_CONFIG_ANT_B: u16 = 0x0b6c;
const REG_OFDM0_TRX_PATH_ENABLE: u16 = 0x0c04;
const REG_OFDM0_TR_MUX_PAR: u16 = 0x0c08;
const REG_OFDM0_XA_RX_IQ_IMBALANCE: u16 = 0x0c14;
const REG_OFDM0_XB_RX_IQ_IMBALANCE: u16 = 0x0c1c;
const REG_OFDM0_ENERGY_CCA_THRES: u16 = 0x0c4c;
const REG_OFDM0_XA_AGC_CORE1: u16 = 0x0c50;
const REG_OFDM0_XB_AGC_CORE1: u16 = 0x0c58;
const REG_OFDM0_AGC_RSSI_TABLE: u16 = 0x0c78;
const REG_OFDM0_XA_TX_IQ_IMBALANCE: u16 = 0x0c80;
const REG_OFDM0_XB_TX_IQ_IMBALANCE: u16 = 0x0c88;
const REG_OFDM0_XC_TX_AFE: u16 = 0x0c94;
const REG_OFDM0_XD_TX_AFE: u16 = 0x0c9c;
const REG_OFDM0_RX_IQ_EXT_ANTA: u16 = 0x0ca0;
const REG_OFDM1_LSTF: u16 = 0x0d00;
const OFDM_LSTF_MASK: u32 = 0x7000_0000;
const REG_FPGA0_IQK: u16 = 0x0e28;
const REG_TX_IQK_TONE_A: u16 = 0x0e30;
const REG_RX_IQK_TONE_A: u16 = 0x0e34;
const REG_TX_IQK_PI_A: u16 = 0x0e38;
const REG_RX_IQK_PI_A: u16 = 0x0e3c;
const REG_TX_IQK: u16 = 0x0e40;
const REG_RX_IQK: u16 = 0x0e44;
const REG_IQK_AGC_PTS: u16 = 0x0e48;
const REG_IQK_AGC_RSP: u16 = 0x0e4c;
const REG_TX_IQK_TONE_B: u16 = 0x0e50;
const REG_RX_IQK_TONE_B: u16 = 0x0e54;
const REG_TX_IQK_PI_B: u16 = 0x0e58;
const REG_RX_IQK_PI_B: u16 = 0x0e5c;
const REG_BLUETOOTH: u16 = 0x0e6c;
const REG_RX_WAIT_CCA: u16 = 0x0e70;
const REG_TX_CCK_RFON: u16 = 0x0e74;
const REG_TX_CCK_BBON: u16 = 0x0e78;
const REG_TX_OFDM_RFON: u16 = 0x0e7c;
const REG_TX_OFDM_BBON: u16 = 0x0e80;
const REG_TX_TO_RX: u16 = 0x0e84;
const REG_TX_TO_TX: u16 = 0x0e88;
const REG_RX_CCK: u16 = 0x0e8c;
const REG_TX_POWER_BEFORE_IQK_A: u16 = 0x0e94;
const REG_TX_POWER_AFTER_IQK_A: u16 = 0x0e9c;
const REG_RX_POWER_BEFORE_IQK_A_2: u16 = 0x0ea4;
const REG_RX_POWER_AFTER_IQK_A_2: u16 = 0x0eac;
const REG_TX_POWER_BEFORE_IQK_B: u16 = 0x0eb4;
const REG_TX_POWER_AFTER_IQK_B: u16 = 0x0ebc;
const REG_RX_POWER_BEFORE_IQK_B_2: u16 = 0x0ec4;
const REG_RX_POWER_AFTER_IQK_B_2: u16 = 0x0ecc;
const REG_RX_OFDM: u16 = 0x0ed0;
const REG_RX_WAIT_RIFS: u16 = 0x0ed4;
const REG_RX_TO_RX: u16 = 0x0ed8;
const REG_STANDBY: u16 = 0x0edc;
const REG_SLEEP: u16 = 0x0ee0;
const REG_PMPD_ANAEN: u16 = 0x0eec;

const RF_AC: u8 = 0x00;
const RF_MODE_AG: u8 = 0x18;
const RF_RCK_OS: u8 = 0x30;
const RF_TXPA_G1: u8 = 0x31;
const RF_TXPA_G2: u8 = 0x32;
const RF_PAD_TXG: u8 = 0x56;
const RF_GAIN_CCA: u8 = 0xdf;
const RF_WE_LUT: u8 = 0xef;

/// `rtl8192eu_fops.adda_*` (all four are `0x0fc01616`).
const ADDA_PATH_ON: u32 = 0x0fc0_1616;
/// `MAX_TOLERANCE`.
const MAX_TOLERANCE: i32 = 5;

const ADDA_REGS: [u16; 16] = [
    REG_FPGA0_XCD_SWITCH_CTRL,
    REG_BLUETOOTH,
    REG_RX_WAIT_CCA,
    REG_TX_CCK_RFON,
    REG_TX_CCK_BBON,
    REG_TX_OFDM_RFON,
    REG_TX_OFDM_BBON,
    REG_TX_TO_RX,
    REG_TX_TO_TX,
    REG_RX_CCK,
    REG_RX_OFDM,
    REG_RX_WAIT_RIFS,
    REG_RX_TO_RX,
    REG_STANDBY,
    REG_SLEEP,
    REG_PMPD_ANAEN,
];
const MAC_REGS: [u16; 4] = [
    REG_TXPAUSE,
    REG_BEACON_CTRL,
    REG_BEACON_CTRL_1,
    REG_GPIO_MUXCFG,
];
const BB_REGS: [u16; 9] = [
    REG_OFDM0_TRX_PATH_ENABLE,
    REG_OFDM0_TR_MUX_PAR,
    REG_FPGA0_XCD_RF_SW_CTRL,
    REG_CONFIG_ANT_A,
    REG_CONFIG_ANT_B,
    REG_FPGA0_XAB_RF_SW_CTRL,
    REG_FPGA0_XA_RF_INT_OE,
    REG_FPGA0_XB_RF_INT_OE,
    REG_CCK0_AFE_SETTING,
];
/// `rtl8xxxu_iqk_phy_iq_bb_reg[]` (saved as `bb_recovery_backup`).
pub(super) const PHY_IQ_BB_REGS: [u16; 9] = [
    REG_OFDM0_XA_RX_IQ_IMBALANCE,
    REG_OFDM0_XB_RX_IQ_IMBALANCE,
    REG_OFDM0_ENERGY_CCA_THRES,
    REG_OFDM0_AGC_RSSI_TABLE,
    REG_OFDM0_XA_TX_IQ_IMBALANCE,
    REG_OFDM0_XB_TX_IQ_IMBALANCE,
    REG_OFDM0_XC_TX_AFE,
    REG_OFDM0_XD_TX_AFE,
    REG_OFDM0_RX_IQ_EXT_ANTA,
];

/// One `result[t][0..8]` row: path A TX x/y, path A RX x/y, path B TX x/y,
/// path B RX x/y (10-bit fields).
pub type Row = [u32; 8];

/// Outcome of `rtl8192eu_phy_iq_calibrate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Iqk {
    /// Linux `candidate` (0, 1 or 3).
    pub candidate: usize,
    /// The chosen row (`result[candidate]`).
    pub row: Row,
    /// `priv->bb_recovery_backup`.
    pub recovery: [u32; 9],
}

fn sign10(value: u32) -> u32 {
    if value & 0x200 != 0 {
        value | 0xffff_fc00
    } else {
        value
    }
}

/// `rtl8xxxu_gen2_simularity_compare`, updating `result[3]` exactly as
/// Linux does. `bound` is 8 for two TX paths, 4 otherwise.
pub fn simularity_compare(result: &mut [Row; 4], c1: usize, c2: usize, tx_paths: u8) -> bool {
    let bound = if tx_paths > 1 { 8 } else { 4 };
    let mut candidate: [Option<usize>; 2] = [None, None];
    let mut bitmap = 0u32;
    for i in 0..bound {
        let (a, b) = if i & 1 != 0 {
            (sign10(result[c1][i]) as i32, sign10(result[c2][i]) as i32)
        } else {
            (result[c1][i] as i32, result[c2][i] as i32)
        };
        if a.abs_diff(b) as i32 > MAX_TOLERANCE {
            if (i == 2 || i == 6) && bitmap == 0 {
                if result[c1][i] + result[c1][i + 1] == 0 {
                    candidate[i / 4] = Some(c2);
                } else if result[c2][i] + result[c2][i + 1] == 0 {
                    candidate[i / 4] = Some(c1);
                } else {
                    bitmap |= 1 << i;
                }
            } else {
                bitmap |= 1 << i;
            }
        }
    }
    if bitmap == 0 {
        let mut same = true;
        for (i, chosen) in candidate.iter().enumerate().take(bound / 4) {
            if let Some(c) = *chosen {
                let source = result[c];
                result[3][i * 4..(i + 1) * 4 - 2].copy_from_slice(&source[i * 4..(i + 1) * 4 - 2]);
                same = false;
            }
        }
        return same;
    }
    let groups: [(u32, core::ops::Range<usize>, bool); 4] = [
        (0x03, 0..2, true),
        (0x0c, 2..4, true),
        (0x30, 4..6, tx_paths > 1),
        (0xc0, 6..8, tx_paths > 1),
    ];
    for (mask, range, enabled) in groups {
        if enabled && bitmap & mask == 0 {
            let source = result[c1];
            result[3][range.clone()].copy_from_slice(&source[range]);
        }
    }
    false
}

/// `rtl8192eu_phy_iq_calibrate` candidate selection over the three runs.
/// Returns the candidate index once Linux would stop iterating, or `None`
/// to keep calibrating.
fn choose(result: &mut [Row; 4], t: usize, tx_paths: u8) -> Option<usize> {
    match t {
        1 if simularity_compare(result, 0, 1, tx_paths) => Some(0),
        2 => {
            if simularity_compare(result, 0, 2, tx_paths) {
                Some(0)
            } else if simularity_compare(result, 1, 2, tx_paths) {
                Some(1)
            } else {
                Some(3)
            }
        }
        _ => None,
    }
}

async fn rmw32<I: ControlIo>(o: &Owner<I>, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = o.read32(reg).await?;
    o.write32(reg, (value & !clear) | set).await
}

async fn writes<I: ControlIo>(o: &Owner<I>, sequence: &[(u16, u32)]) -> Result<(), Error> {
    for &(reg, value) in sequence {
        o.write32(reg, value).await?;
    }
    Ok(())
}

async fn rf_writes<I: ControlIo>(
    o: &Owner<I>,
    path_b: bool,
    sequence: &[(u8, u32)],
) -> Result<(), Error> {
    for &(reg, value) in sequence {
        write_rfreg(o, path_b, reg, value).await?;
    }
    Ok(())
}

/// The `WE_LUT/RCK_OS/TXPA_G1/TXPA_G2` mode-table quartet.
async fn pa_table<I: ControlIo>(
    o: &Owner<I>,
    path_b: bool,
    rck: u32,
    g2: u32,
) -> Result<(), Error> {
    rf_writes(
        o,
        path_b,
        &[
            (RF_WE_LUT, 0x800a0),
            (RF_RCK_OS, rck),
            (RF_TXPA_G1, 0x0000f),
            (RF_TXPA_G2, g2),
        ],
    )
    .await
}

/// The four IQK tone registers; the tone under test is `0x18008c1c`, the
/// others `0x38008c1c`.
async fn tones<I: ControlIo>(
    o: &Owner<I>,
    tx_a: u32,
    rx_a: u32,
    tx_b: u32,
    rx_b: u32,
) -> Result<(), Error> {
    writes(
        o,
        &[
            (REG_TX_IQK_TONE_A, tx_a),
            (REG_RX_IQK_TONE_A, rx_a),
            (REG_TX_IQK_TONE_B, tx_b),
            (REG_RX_IQK_TONE_B, rx_b),
        ],
    )
    .await
}

async fn one_shot<I: ControlIo>(o: &Owner<I>, path_b: bool, delay_us: u64) -> Result<(), Error> {
    let start = if path_b { 0xfa00_0000 } else { 0xf900_0000 };
    o.write32(REG_IQK_AGC_PTS, start).await?;
    o.write32(REG_IQK_AGC_PTS, 0xf800_0000).await?;
    o.delay_us(delay_us).await;
    Ok(())
}

fn tx_ok(eac: u32, eac_bit: u32, before: u32, after: u32) -> bool {
    eac & (1 << eac_bit) == 0
        && before & 0x03ff_0000 != 0x0142_0000
        && after & 0x03ff_0000 != 0x0042_0000
}

fn rx_ok(eac_bit_value: u32, eac_bit: u32, before: u32, after: u32) -> bool {
    eac_bit_value & (1 << eac_bit) == 0
        && before & 0x03ff_0000 != 0x0132_0000
        && after & 0x03ff_0000 != 0x0036_0000
}

/// `rtl8192eu_iqk_path_a`.
async fn iqk_path_a<I: ControlIo>(o: &Owner<I>) -> Result<bool, Error> {
    o.write32(REG_FPGA0_IQK, 0).await?;
    write_rfreg(o, false, RF_GAIN_CCA, 0x00180).await?;
    pa_table(o, false, 0x20000, 0x07f77).await?;
    o.write32(REG_FPGA0_IQK, 0x8080_0000).await?;
    tones(o, 0x1800_8c1c, 0x3800_8c1c, 0x3800_8c1c, 0x3800_8c1c).await?;
    writes(
        o,
        &[
            (REG_TX_IQK_PI_A, 0x8214_0303),
            (REG_RX_IQK_PI_A, 0x6816_0000),
            (REG_IQK_AGC_RSP, 0x0046_2911),
        ],
    )
    .await?;
    one_shot(o, false, 10_000).await?;
    let eac = o.read32(REG_RX_POWER_AFTER_IQK_A_2).await?;
    let e94 = o.read32(REG_TX_POWER_BEFORE_IQK_A).await?;
    let e9c = o.read32(REG_TX_POWER_AFTER_IQK_A).await?;
    Ok(tx_ok(eac, 28, e94, e9c))
}

/// `rtl8192eu_rx_iqk_path_a`: returns the Linux bitmask (bit 0 TX, bit 1 RX).
async fn rx_iqk_path_a<I: ControlIo>(o: &Owner<I>) -> Result<u8, Error> {
    o.write32(REG_FPGA0_IQK, 0).await?;
    pa_table(o, false, 0x30000, 0xf1173).await?;
    pa_table(o, true, 0x30000, 0xf1173).await?;
    rf_writes(o, false, &[(RF_GAIN_CCA, 0x00980), (RF_PAD_TXG, 0x511e0)]).await?;
    o.write32(REG_FPGA0_IQK, 0x8080_0000).await?;
    writes(o, &[(REG_TX_IQK, 0x0100_7c00), (REG_RX_IQK, 0x0100_4800)]).await?;
    tones(o, 0x1800_8c1c, 0x3800_8c1c, 0x3800_8c1c, 0x3800_8c1c).await?;
    writes(
        o,
        &[
            (REG_TX_IQK_PI_A, 0x8216_031f),
            (REG_RX_IQK_PI_A, 0x6816_031f),
            (REG_IQK_AGC_RSP, 0x0046_a911),
        ],
    )
    .await?;
    one_shot(o, false, 10_000).await?;
    let eac = o.read32(REG_RX_POWER_AFTER_IQK_A_2).await?;
    let e94 = o.read32(REG_TX_POWER_BEFORE_IQK_A).await?;
    let e9c = o.read32(REG_TX_POWER_AFTER_IQK_A).await?;
    if !tx_ok(eac, 28, e94, e9c) {
        o.write32(REG_FPGA0_IQK, 0).await?;
        write_rfreg(o, false, RF_GAIN_CCA, 0x180).await?;
        return Ok(0);
    }
    o.write32(
        REG_TX_IQK,
        0x8000_7c00 | (e94 & 0x03ff_0000) | ((e9c >> 16) & 0x03ff),
    )
    .await?;
    o.write32(REG_FPGA0_IQK, 0).await?;
    pa_table(o, false, 0x30000, 0xf7ff2).await?;
    pa_table(o, true, 0x30000, 0xf7ff2).await?;
    rf_writes(o, false, &[(RF_GAIN_CCA, 0x00980), (RF_PAD_TXG, 0x510e0)]).await?;
    o.write32(REG_FPGA0_IQK, 0x8080_0000).await?;
    o.write32(REG_RX_IQK, 0x0100_4800).await?;
    tones(o, 0x3800_8c1c, 0x1800_8c1c, 0x3800_8c1c, 0x3800_8c1c).await?;
    writes(
        o,
        &[
            (REG_TX_IQK_PI_A, 0x8216_08ff),
            (REG_RX_IQK_PI_A, 0x2816_08ff),
            (REG_IQK_AGC_RSP, 0x0046_a891),
        ],
    )
    .await?;
    one_shot(o, false, 10_000).await?;
    let eac = o.read32(REG_RX_POWER_AFTER_IQK_A_2).await?;
    let ea4 = o.read32(REG_RX_POWER_BEFORE_IQK_A_2).await?;
    o.write32(REG_FPGA0_IQK, 0).await?;
    write_rfreg(o, false, RF_GAIN_CCA, 0x180).await?;
    Ok(if rx_ok(eac, 27, ea4, eac) { 0x03 } else { 0x01 })
}

/// `rtl8192eu_iqk_path_b` (one-shot settles for 1 ms, as in Linux).
async fn iqk_path_b<I: ControlIo>(o: &Owner<I>) -> Result<bool, Error> {
    o.write32(REG_FPGA0_IQK, 0).await?;
    write_rfreg(o, true, RF_GAIN_CCA, 0x00180).await?;
    pa_table(o, true, 0x20000, 0x07f77).await?;
    o.write32(REG_FPGA0_IQK, 0x8080_0000).await?;
    tones(o, 0x3800_8c1c, 0x3800_8c1c, 0x1800_8c1c, 0x3800_8c1c).await?;
    writes(
        o,
        &[
            (REG_TX_IQK_PI_B, 0x8214_0303),
            (REG_RX_IQK_PI_B, 0x6816_0000),
            (REG_IQK_AGC_RSP, 0x0046_2911),
        ],
    )
    .await?;
    one_shot(o, true, 1_000).await?;
    let eac = o.read32(REG_RX_POWER_AFTER_IQK_A_2).await?;
    let eb4 = o.read32(REG_TX_POWER_BEFORE_IQK_B).await?;
    let ebc = o.read32(REG_TX_POWER_AFTER_IQK_B).await?;
    Ok(tx_ok(eac, 31, eb4, ebc))
}

/// `rtl8192eu_rx_iqk_path_b`. The final RX stage programs the path-A PI
/// registers, verbatim from Linux.
async fn rx_iqk_path_b<I: ControlIo>(o: &Owner<I>) -> Result<u8, Error> {
    o.write32(REG_FPGA0_IQK, 0).await?;
    pa_table(o, true, 0x30000, 0xf1173).await?;
    pa_table(o, false, 0x30000, 0xf1173).await?;
    rf_writes(o, true, &[(RF_GAIN_CCA, 0x00980), (RF_PAD_TXG, 0x511e0)]).await?;
    o.write32(REG_FPGA0_IQK, 0x8080_0000).await?;
    writes(o, &[(REG_TX_IQK, 0x0100_7c00), (REG_RX_IQK, 0x0100_4800)]).await?;
    tones(o, 0x3800_8c1c, 0x3800_8c1c, 0x1800_8c1c, 0x3800_8c1c).await?;
    writes(
        o,
        &[
            (REG_TX_IQK_PI_B, 0x8216_031f),
            (REG_RX_IQK_PI_B, 0x6816_031f),
            (REG_IQK_AGC_RSP, 0x0046_a911),
        ],
    )
    .await?;
    one_shot(o, true, 10_000).await?;
    let eac = o.read32(REG_RX_POWER_AFTER_IQK_A_2).await?;
    let eb4 = o.read32(REG_TX_POWER_BEFORE_IQK_B).await?;
    let ebc = o.read32(REG_TX_POWER_AFTER_IQK_B).await?;
    if !tx_ok(eac, 31, eb4, ebc) {
        o.write32(REG_FPGA0_IQK, 0).await?;
        write_rfreg(o, true, RF_GAIN_CCA, 0x180).await?;
        return Ok(0);
    }
    o.write32(
        REG_TX_IQK,
        0x8000_7c00 | (eb4 & 0x03ff_0000) | ((ebc >> 16) & 0x03ff),
    )
    .await?;
    o.write32(REG_FPGA0_IQK, 0).await?;
    pa_table(o, true, 0x30000, 0xf7ff2).await?;
    pa_table(o, false, 0x30000, 0xf7ff2).await?;
    rf_writes(o, true, &[(RF_GAIN_CCA, 0x00980), (RF_PAD_TXG, 0x510e0)]).await?;
    o.write32(REG_FPGA0_IQK, 0x8080_0000).await?;
    o.write32(REG_RX_IQK, 0x0100_4800).await?;
    tones(o, 0x3800_8c1c, 0x3800_8c1c, 0x3800_8c1c, 0x1800_8c1c).await?;
    writes(
        o,
        &[
            (REG_TX_IQK_PI_A, 0x8216_08ff),
            (REG_RX_IQK_PI_A, 0x2816_08ff),
            (REG_IQK_AGC_RSP, 0x0046_a891),
        ],
    )
    .await?;
    one_shot(o, true, 10_000).await?;
    let eac = o.read32(REG_RX_POWER_AFTER_IQK_A_2).await?;
    let ec4 = o.read32(REG_RX_POWER_BEFORE_IQK_B_2).await?;
    let ecc = o.read32(REG_RX_POWER_AFTER_IQK_B_2).await?;
    o.write32(REG_FPGA0_IQK, 0).await?;
    write_rfreg(o, true, RF_GAIN_CCA, 0x180).await?;
    Ok(if rx_ok(eac, 30, ec4, ecc) { 0x03 } else { 0x01 })
}

/// Register state saved on the first run (`priv->{adda,mac,bb}_backup`).
struct Backup {
    adda: [u32; 16],
    mac: [u32; 4],
    bb: [u32; 9],
}

impl Backup {
    async fn save<I: ControlIo>(o: &Owner<I>) -> Result<Self, Error> {
        let mut backup = Self {
            adda: [0; 16],
            mac: [0; 4],
            bb: [0; 9],
        };
        for (slot, &reg) in backup.adda.iter_mut().zip(ADDA_REGS.iter()) {
            *slot = o.read32(reg).await?;
        }
        for (slot, &reg) in backup.mac[..3].iter_mut().zip(MAC_REGS[..3].iter()) {
            *slot = o.read8(reg).await? as u32;
        }
        backup.mac[3] = o.read32(MAC_REGS[3]).await?;
        for (slot, &reg) in backup.bb.iter_mut().zip(BB_REGS.iter()) {
            *slot = o.read32(reg).await?;
        }
        Ok(backup)
    }

    async fn restore<I: ControlIo>(&self, o: &Owner<I>) -> Result<(), Error> {
        for (&value, &reg) in self.adda.iter().zip(ADDA_REGS.iter()) {
            o.write32(reg, value).await?;
        }
        for (&value, &reg) in self.mac[..3].iter().zip(MAC_REGS[..3].iter()) {
            o.write8(reg, value as u8).await?;
        }
        o.write32(MAC_REGS[3], self.mac[3]).await?;
        for (&value, &reg) in self.bb.iter().zip(BB_REGS.iter()) {
            o.write32(reg, value).await?;
        }
        Ok(())
    }
}

/// `rtl8xxxu_path_adda_on` with the 8192EU ADDA words (identical for 1T and
/// both 2T paths).
async fn path_adda_on<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    for &reg in ADDA_REGS.iter() {
        o.write32(reg, ADDA_PATH_ON).await?;
    }
    Ok(())
}

/// `rtl8192eu_phy_iqcalibrate` for run `t`.
async fn iqcalibrate<I: ControlIo>(
    o: &Owner<I>,
    result: &mut [Row; 4],
    t: usize,
    saved: &mut Option<Backup>,
) -> Result<(), Error> {
    let xa_agc = o.read32(REG_OFDM0_XA_AGC_CORE1).await? & 0xff;
    let xb_agc = o.read32(REG_OFDM0_XB_AGC_CORE1).await? & 0xff;
    if t == 0 {
        *saved = Some(Backup::save(o).await?);
    }
    let backup = saved.as_ref().ok_or(Error::Calibration)?;
    path_adda_on(o).await?;
    // rtl8xxxu_mac_calibration
    o.write8(MAC_REGS[0], 0x3f).await?;
    for (&reg, &value) in MAC_REGS[1..3].iter().zip(backup.mac[1..3].iter()) {
        o.write8(reg, (value & !(1 << 3)) as u8).await?;
    }
    o.write8(MAC_REGS[3], (backup.mac[3] & !(1 << 5)) as u8)
        .await?;
    rmw32(o, REG_CCK0_AFE_SETTING, 0, 0x0f00_0000).await?;
    writes(
        o,
        &[
            (REG_OFDM0_TRX_PATH_ENABLE, 0x03a0_5600),
            (REG_OFDM0_TR_MUX_PAR, 0x0008_00e4),
            (REG_FPGA0_XCD_RF_SW_CTRL, 0x2220_8200),
        ],
    )
    .await?;
    rmw32(
        o,
        REG_FPGA0_XAB_RF_SW_CTRL,
        0,
        FPGA0_RF_PAPE | FPGA0_RF_PAPE << FPGA0_RF_BD_CTRL_SHIFT,
    )
    .await?;
    rmw32(o, REG_FPGA0_XA_RF_INT_OE, 0, 1 << 10).await?;
    rmw32(o, REG_FPGA0_XB_RF_INT_OE, 0, 1 << 10).await?;
    let enter = [
        (REG_FPGA0_IQK, 0x8080_0000),
        (REG_TX_IQK, 0x0100_7c00),
        (REG_RX_IQK, 0x0100_4800),
    ];
    writes(o, &enter).await?;
    for _ in 0..2 {
        if iqk_path_a(o).await? {
            result[t][0] = (o.read32(REG_TX_POWER_BEFORE_IQK_A).await? >> 16) & 0x3ff;
            result[t][1] = (o.read32(REG_TX_POWER_AFTER_IQK_A).await? >> 16) & 0x3ff;
            break;
        }
    }
    for _ in 0..2 {
        if rx_iqk_path_a(o).await? == 0x03 {
            result[t][2] = (o.read32(REG_RX_POWER_BEFORE_IQK_A_2).await? >> 16) & 0x3ff;
            result[t][3] = (o.read32(REG_RX_POWER_AFTER_IQK_A_2).await? >> 16) & 0x3ff;
            break;
        }
    }
    // priv->rf_paths is 2 for both the 8192EU and the 1T2R 8191EU.
    o.write32(REG_FPGA0_IQK, 0).await?;
    write_rfreg(o, false, RF_AC, 0x10000).await?;
    o.write32(REG_FPGA0_IQK, 0x8080_0000).await?;
    path_adda_on(o).await?;
    writes(o, &enter).await?;
    for _ in 0..2 {
        if iqk_path_b(o).await? {
            result[t][4] = (o.read32(REG_TX_POWER_BEFORE_IQK_B).await? >> 16) & 0x3ff;
            result[t][5] = (o.read32(REG_TX_POWER_AFTER_IQK_B).await? >> 16) & 0x3ff;
            break;
        }
    }
    for _ in 0..2 {
        if rx_iqk_path_b(o).await? == 0x03 {
            result[t][6] = (o.read32(REG_RX_POWER_BEFORE_IQK_B_2).await? >> 16) & 0x3ff;
            result[t][7] = (o.read32(REG_RX_POWER_AFTER_IQK_B_2).await? >> 16) & 0x3ff;
            break;
        }
    }
    o.write32(REG_FPGA0_IQK, 0).await?;
    if t != 0 {
        backup.restore(o).await?;
        for (reg, agc) in [
            (REG_OFDM0_XA_AGC_CORE1, xa_agc),
            (REG_OFDM0_XB_AGC_CORE1, xb_agc),
        ] {
            let value = o.read32(reg).await? & 0xffff_ff00;
            o.write32(reg, value | 0x50).await?;
            o.write32(reg, value | agc).await?;
        }
        writes(
            o,
            &[
                (REG_TX_IQK_TONE_A, 0x0100_8c00),
                (REG_RX_IQK_TONE_A, 0x0100_8c00),
            ],
        )
        .await?;
    }
    Ok(())
}

/// One path of `rtl8xxxu_fill_iqk_matrix_{a,b}`. Arithmetic is Linux's u32
/// arithmetic, including the unmasked OR of `tx_a` into `[9:0]`.
pub(super) struct MatrixRegs {
    pub(super) tx_iq: u16,
    pub(super) tx_afe: u16,
    pub(super) rx_iq: u16,
    pub(super) cca_x_bit: u32,
    pub(super) cca_y_bit: u32,
}

pub(super) async fn fill_matrix<I: ControlIo>(
    o: &Owner<I>,
    regs: &MatrixRegs,
    vals: [u32; 4],
    tx_only: bool,
    path_b: bool,
) -> Result<(), Error> {
    let oldval = o.read32(regs.tx_iq).await? >> 22;
    let x = sign10(vals[0]);
    let product = x.wrapping_mul(oldval);
    let value = o.read32(regs.tx_iq).await?;
    o.write32(regs.tx_iq, (value & !0x3ff) | (product >> 8))
        .await?;
    let value = o.read32(REG_OFDM0_ENERGY_CCA_THRES).await?;
    o.write32(
        REG_OFDM0_ENERGY_CCA_THRES,
        (value & !(1 << regs.cca_x_bit)) | ((product >> 7) & 1) << regs.cca_x_bit,
    )
    .await?;
    let y = sign10(vals[1]);
    let product = y.wrapping_mul(oldval);
    let c = product >> 8;
    let value = o.read32(regs.tx_afe).await?;
    o.write32(
        regs.tx_afe,
        (value & !0xf000_0000) | ((c & 0x3c0) >> 6) << 28,
    )
    .await?;
    let value = o.read32(regs.tx_iq).await?;
    o.write32(regs.tx_iq, (value & !0x003f_0000) | (c & 0x3f) << 16)
        .await?;
    let value = o.read32(REG_OFDM0_ENERGY_CCA_THRES).await?;
    o.write32(
        REG_OFDM0_ENERGY_CCA_THRES,
        (value & !(1 << regs.cca_y_bit)) | ((product >> 7) & 1) << regs.cca_y_bit,
    )
    .await?;
    if tx_only {
        return Ok(());
    }
    let value = o.read32(regs.rx_iq).await?;
    o.write32(regs.rx_iq, (value & !0x3ff) | (vals[2] & 0x3ff))
        .await?;
    let value = o.read32(regs.rx_iq).await?;
    o.write32(
        regs.rx_iq,
        (value & !0xfc00) | (((vals[3] & 0x3f) << 10) & 0xfc00),
    )
    .await?;
    let ext = (vals[3] >> 6) & 0xf;
    if path_b {
        rmw32(o, REG_OFDM0_AGC_RSSI_TABLE, 0x0000_f000, ext << 12).await
    } else {
        rmw32(o, REG_OFDM0_RX_IQ_EXT_ANTA, 0xf000_0000, ext << 28).await
    }
}

/// `rtl8192eu_phy_iq_calibrate`.
pub(super) async fn iq_calibrate<I: ControlIo>(o: &Owner<I>, tx_paths: u8) -> Result<Iqk, Error> {
    let mut result = [[0u32; 8]; 4];
    let mut backup = None;
    let mut candidate = None;
    for t in 0..3 {
        iqcalibrate(o, &mut result, t, &mut backup).await?;
        candidate = choose(&mut result, t, tx_paths);
        if candidate.is_some() {
            break;
        }
    }
    let candidate = candidate.ok_or(Error::Calibration)?;
    let row = result[candidate];
    if row[0] == 0 || (tx_paths > 1 && row[4] == 0) {
        return Err(Error::Calibration);
    }
    fill_matrix(
        o,
        &MatrixRegs {
            tx_iq: REG_OFDM0_XA_TX_IQ_IMBALANCE,
            tx_afe: REG_OFDM0_XC_TX_AFE,
            rx_iq: REG_OFDM0_XA_RX_IQ_IMBALANCE,
            cca_x_bit: 31,
            cca_y_bit: 29,
        },
        [row[0], row[1], row[2], row[3]],
        row[2] == 0,
        false,
    )
    .await?;
    fill_matrix(
        o,
        &MatrixRegs {
            tx_iq: REG_OFDM0_XB_TX_IQ_IMBALANCE,
            tx_afe: REG_OFDM0_XD_TX_AFE,
            rx_iq: REG_OFDM0_XB_RX_IQ_IMBALANCE,
            cca_x_bit: 27,
            cca_y_bit: 25,
        },
        [row[4], row[5], row[6], row[7]],
        row[6] == 0,
        true,
    )
    .await?;
    let mut recovery = [0u32; 9];
    for (slot, &reg) in recovery.iter_mut().zip(PHY_IQ_BB_REGS.iter()) {
        *slot = o.read32(reg).await?;
    }
    Ok(Iqk {
        candidate,
        row,
        recovery,
    })
}

/// `rtl8723a_phy_lc_calibrate` (the 8192EU fops hook; `has_s0s1 = 0`).
pub(super) async fn lc_calibrate<I: ControlIo>(o: &Owner<I>, tx_paths: u8) -> Result<(), Error> {
    let lstf = o.read32(REG_OFDM1_LSTF).await?;
    let continuous = lstf & OFDM_LSTF_MASK != 0;
    let (mut a_mode, mut b_mode) = (0, 0);
    if continuous {
        o.write32(REG_OFDM1_LSTF, lstf & !OFDM_LSTF_MASK).await?;
        a_mode = read_rfreg(o, false, RF_AC).await?;
        write_rfreg(o, false, RF_AC, (a_mode & 0x8ffff) | 0x10000).await?;
        if tx_paths > 1 {
            b_mode = read_rfreg(o, true, RF_AC).await?;
            write_rfreg(o, true, RF_AC, (b_mode & 0x8ffff) | 0x10000).await?;
        }
    } else {
        o.write8(REG_TXPAUSE, 0xff).await?;
    }
    let mode = read_rfreg(o, false, RF_MODE_AG).await?;
    write_rfreg(o, false, RF_MODE_AG, mode | 0x08000).await?;
    o.delay_us(100_000).await;
    if continuous {
        o.write32(REG_OFDM1_LSTF, lstf).await?;
        write_rfreg(o, false, RF_AC, a_mode).await?;
        if tx_paths > 1 {
            write_rfreg(o, true, RF_AC, b_mode).await?;
        }
    } else {
        o.write8(REG_TXPAUSE, 0).await?;
    }
    Ok(())
}
