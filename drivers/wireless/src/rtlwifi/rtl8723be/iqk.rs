// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE IQ calibration over the S0/S1 antenna paths.
//!
//! Exact `rtl8723be/phy.c` + `rtl8723com/phy_common.c`:
//!
//! - `rtl8723be_phy_iq_calibrate(hw, false)`: save `0x948`, up to three
//!   `_rtl8723be_phy_iq_calibrate(t, is2t = true)` runs with
//!   `_rtl8723be_phy_simularity_compare` after the second and third (12 → 0;
//!   13 → 0; 23 → 1; else 3 when any `result[3]` entry is non-zero, else
//!   0xff), `rtl8723_phy_path_a_fill_iqk_matrix` /
//!   `_rtl8723be_phy_path_b_fill_iqk_matrix`, the `iqk_matrix` row, the save
//!   of the nine result registers (`iqk_bb_backup`, reloaded by the
//!   `b_recovery` form [`recover`]) and the `0x948` restore. The result
//!   table starts all-zero (unlike RTL8192EE's `0x100` seeds).
//! - `_rtl8723be_phy_iq_calibrate(t)`: `0xc50`/`0xc58` byte samples; at
//!   `t == 0` the ADDA / MAC / BB backups and the `rfpi_enable` read;
//!   `rtl8723_phy_path_adda_on` (`0x01c00014` on all sixteen for 8723BE),
//!   the current `0x948`, `rtl8723_phy_mac_setting_calibration`, the BB
//!   setting writes, two retries each of S1 path A TX (`0x01`) / RX
//!   (`0x03`) and S0 path B TX / RX (both through RF path A, `0x948 = 0`
//!   or `0x280`), leave IQK mode; for `t != 0` the reloads, the `0x948`
//!   restore, the `0xc50`/`0xc58` initial-gain toggles and the tone resets.
//!   Linux does not restore after `t == 0`; neither does this.
//! - Matrix fills keep Linux's u32 wrapping products. The 64-bit `long`
//!   arithmetic for `tx0_c` / `tx1_c` only differs above bit 31, which the
//!   masked writes never reach. Path B's RX-extension write is commented out
//!   in Linux and is not issued here.
//!
//! `rtl8723be_hw_init` skips IQK on one-antenna (`ANT_X1`) boards because
//! `get_btc_status()` is always true for 8723BE ([`required`]).

use super::adapter::{Adapter, AntNum};
use super::phy::{get_bb, set_bb, set_rf, Path, MASKDWORD, RFREG_OFFSET_MASK};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const RFPGA0_XA_HSSIPARAMETER1: u16 = 0x820;
pub const RFPGA0_XCD_RFINTERFACESW: u16 = 0x874;
pub const ROFDM0_TRXPATHENABLE: u16 = 0xc04;
pub const ROFDM0_TRMUXPAR: u16 = 0xc08;
pub const ROFDM0_XARXIQIMBALANCE: u16 = 0xc14;
pub const ROFDM0_XBRXIQIMBALANCE: u16 = 0xc1c;
pub const ROFDM0_ECCATHRESHOLD: u16 = 0xc4c;
pub const ROFDM0_AGCRSSITABLE: u16 = 0xc78;
pub const ROFDM0_XATXIQIMBALANCE: u16 = 0xc80;
pub const ROFDM0_XBTXIQIMBALANCE: u16 = 0xc88;
pub const ROFDM0_XCTXAFE: u16 = 0xc94;
pub const ROFDM0_XDTXAFE: u16 = 0xc9c;
pub const ROFDM0_RXIQEXTANTA: u16 = 0xca0;
pub const RFPGA0_IQK: u16 = 0xe28;
pub const RTX_IQK_TONE_A: u16 = 0xe30;
pub const RRX_IQK_TONE_A: u16 = 0xe34;
pub const RTX_IQK_PI_A: u16 = 0xe38;
pub const RRX_IQK_PI_A: u16 = 0xe3c;
pub const RTX_IQK: u16 = 0xe40;
pub const RRX_IQK: u16 = 0xe44;
pub const RIQK_AGC_PTS: u16 = 0xe48;
pub const RIQK_AGC_RSP: u16 = 0xe4c;
pub const RTX_IQK_TONE_B: u16 = 0xe50;
pub const RRX_IQK_TONE_B: u16 = 0xe54;
pub const RTX_IQK_PI_B: u16 = 0xe58;
pub const RRX_IQK_PI_B: u16 = 0xe5c;
pub const RTX_POWER_BEFORE_IQK_A: u16 = 0xe94;
pub const RTX_POWER_AFTER_IQK_A: u16 = 0xe9c;
pub const RRX_POWER_BEFORE_IQK_A_2: u16 = 0xea4;
pub const RRX_POWER_AFTER_IQK_A_2: u16 = 0xeac;
/// `0x948`: S0/S1 path select.
pub const REG_S0S1_PATH_SWITCH: u16 = 0x948;

pub const RF_WE_LUT: u32 = 0xef;
pub const RF_RCK_OS: u32 = 0x30;
pub const RF_TXPA_G1: u32 = 0x31;
pub const RF_TXPA_G2: u32 = 0x32;
/// `IQK_DELAY_TIME` (10 ms, `mdelay`).
pub const IQK_DELAY_US: u64 = 10_000;
/// `MAX_TOLERANCE`.
pub const MAX_TOLERANCE: u32 = 5;
const RETRY: usize = 2;

pub const ADDA_REGS: [u16; 16] = [
    0x85c, 0xe6c, 0xe70, 0xe74, 0xe78, 0xe7c, 0xe80, 0xe84, 0xe88, 0xe8c, 0xed0, 0xed4, 0xed8,
    0xedc, 0xee0, 0xeec,
];
/// `iqk_mac_reg`: three byte backups then a dword (`0x040`).
pub const MAC_REGS: [u16; 4] = [0x522, 0x550, 0x551, 0x040];
pub const BB_REGS: [u16; 9] = [
    ROFDM0_TRXPATHENABLE,
    ROFDM0_TRMUXPAR,
    RFPGA0_XCD_RFINTERFACESW,
    0xb68,
    0xb6c,
    0x870,
    0x860,
    0x864,
    0xa04,
];
/// `rtl8723be_phy_iq_calibrate`'s result-register backup (`iqk_bb_reg`).
pub const RESULT_REGS: [u16; 9] = [
    ROFDM0_XARXIQIMBALANCE,
    ROFDM0_XBRXIQIMBALANCE,
    ROFDM0_ECCATHRESHOLD,
    ROFDM0_AGCRSSITABLE,
    ROFDM0_XATXIQIMBALANCE,
    ROFDM0_XBTXIQIMBALANCE,
    ROFDM0_XCTXAFE,
    ROFDM0_XDTXAFE,
    ROFDM0_RXIQEXTANTA,
];

/// `rtl8723be_hw_init`'s IQK condition: `ant_num == ANT_X2 ||
/// !get_btc_status()`, and `rtl8723be_get_btc_status` returns true.
pub const fn required(adapter: &Adapter) -> bool {
    matches!(adapter.ant_num, AntNum::X2)
}

/// Backups taken at `t == 0`.
#[derive(Clone, Copy, Debug, Default)]
struct Backup {
    adda: [u32; 16],
    mac: [u32; 4],
    bb: [u32; 9],
}

/// Outcome of one full calibration (the `rtlphy` IQK state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub result: [[u32; 8]; 4],
    pub final_candidate: u8,
    /// `rtlphy->reg_e94`, `reg_e9c`, `reg_eb4`, `reg_ebc`.
    pub reg_e94: u32,
    pub reg_e9c: u32,
    pub reg_eb4: u32,
    pub reg_ebc: u32,
    /// `rtlphy->iqk_matrix[0].value[0]` (`None` when `iqk_done` stays
    /// false). Channel place is always 0 on 2.4 GHz.
    pub matrix: Option<[u32; 8]>,
    /// `rtlphy->iqk_bb_backup` after the fill (input to [`recover`]).
    pub saved: [u32; 9],
}

const fn field(v: u32) -> u32 {
    (v & 0x03ff_0000) >> 16
}

async fn shot(io: &impl Io) -> Result<(), Error> {
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0x8080_0000)?;
    set_bb(io, RIQK_AGC_PTS, MASKDWORD, 0xf900_0000)?;
    set_bb(io, RIQK_AGC_PTS, MASKDWORD, 0xf800_0000)?;
    io.delay_us(IQK_DELAY_US).await;
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0)
}

fn tones(io: &impl Io, v: [u32; 8]) -> Result<(), Error> {
    for (reg, value) in [
        RTX_IQK_TONE_A,
        RRX_IQK_TONE_A,
        RTX_IQK_TONE_B,
        RRX_IQK_TONE_B,
        RTX_IQK_PI_A,
        RRX_IQK_PI_A,
        RTX_IQK_PI_B,
        RRX_IQK_PI_B,
    ]
    .into_iter()
    .zip(v)
    {
        set_bb(io, reg, MASKDWORD, value)?;
    }
    Ok(())
}

async fn rf_a(io: &impl Io, reg: u32, value: u32) -> Result<(), Error> {
    set_rf(io, Path::A, reg, RFREG_OFFSET_MASK, value).await
}

/// The first TX check of every path. Once it passes `result` already
/// holds `0x01`, so a failing second check ([`tx_settled`]) still returns
/// `0x01` from the TX-only paths and only stops the RX paths early.
fn tx_ok(eac: u32, e94: u32, e9c: u32) -> bool {
    eac & (1 << 28) == 0 && field(e94) != 0x142 && field(e9c) != 0x42
}

/// The second TX check (`Allen 20131125`).
fn tx_settled(eac: u32, e94: u32, e9c: u32) -> bool {
    let mut tmp = field(e9c);
    if tmp & 0x200 != 0 {
        tmp = 0x400 - tmp;
    }
    eac & (1 << 28) == 0 && field(e94) < 0x110 && field(e94) > 0xf0 && tmp < 0xf
}

/// The RX check of both RX paths.
fn rx_ok(eac: u32, ea4: u32) -> bool {
    let mut tmp = field(eac);
    if tmp & 0x200 != 0 {
        tmp = 0x400 - tmp;
    }
    eac & (1 << 27) == 0
        && ((field(ea4) != 0x132 && field(eac) != 0x36)
            || (field(ea4) < 0x110 && field(ea4) > 0xf0 && tmp < 0xf))
}

fn tx_registers(io: &impl Io) -> Result<(u32, u32, u32), Error> {
    Ok((
        get_bb(io, RRX_POWER_AFTER_IQK_A_2, MASKDWORD)?,
        get_bb(io, RTX_POWER_BEFORE_IQK_A, MASKDWORD)?,
        get_bb(io, RTX_POWER_AFTER_IQK_A, MASKDWORD)?,
    ))
}

const TX_TONES: [u32; 8] = [
    0x1800_8c1c,
    0x3800_8c1c,
    0x3800_8c1c,
    0x3800_8c1c,
    0x8214_03ea,
    0x2816_0000,
    0x8211_0000,
    0x2811_0000,
];
const TXIMR_TONES: [u32; 8] = [
    0x1800_8c1c,
    0x3800_8c1c,
    0x3800_8c1c,
    0x3800_8c1c,
    0x8216_0ff0,
    0x2811_0000,
    0x8211_0000,
    0x2811_0000,
];
const RX_TONES: [u32; 8] = [
    0x3800_8c1c,
    0x1800_8c1c,
    0x3800_8c1c,
    0x3800_8c1c,
    0x8211_0000,
    0x2816_001f,
    0x8211_0000,
    0x2811_0000,
];

/// `_rtl8723be_phy_path_a_iqk` (S1 TX).
pub async fn path_a_tx(io: &impl Io) -> Result<u8, Error> {
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0)?;
    set_bb(io, REG_S0S1_PATH_SWITCH, MASKDWORD, 0)?;
    rf_a(io, RF_WE_LUT, 0x800a0).await?;
    rf_a(io, RF_RCK_OS, 0x20000).await?;
    rf_a(io, RF_TXPA_G1, 0x0003f).await?;
    rf_a(io, RF_TXPA_G2, 0xc7f87).await?;
    set_bb(io, RTX_IQK, MASKDWORD, 0x0100_7c00)?;
    set_bb(io, RRX_IQK, MASKDWORD, 0x0100_4800)?;
    tones(io, TX_TONES)?;
    set_bb(io, RIQK_AGC_RSP, MASKDWORD, 0x0046_2911)?;
    shot(io).await?;
    // Linux reads 0xeac / 0xe94 / 0xe9c by number here.
    let (eac, e94, e9c) = tx_registers(io)?;
    Ok(u8::from(tx_ok(eac, e94, e9c)))
}

/// `_rtl8723be_phy_path_b_iqk` (S0 TX, still RF path A).
pub async fn path_b_tx(io: &impl Io) -> Result<u8, Error> {
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0)?;
    set_bb(io, REG_S0S1_PATH_SWITCH, MASKDWORD, 0x280)?;
    rf_a(io, 0xed, 0x00020).await?;
    rf_a(io, 0x43, 0x40fc1).await?;
    set_bb(io, RTX_IQK, MASKDWORD, 0x0100_7c00)?;
    set_bb(io, RRX_IQK, MASKDWORD, 0x0100_4800)?;
    let mut t = TX_TONES;
    t[5] = 0x2811_0000;
    tones(io, t)?;
    set_bb(io, RIQK_AGC_RSP, MASKDWORD, 0x0046_2911)?;
    shot(io).await?;
    let (eac, e94, e9c) = tx_registers(io)?;
    Ok(u8::from(tx_ok(eac, e94, e9c)))
}

/// The RX shot shared by both RX paths after their RF setup. Returns
/// `(eac, ea4)`.
async fn rx_shot(io: &impl Io) -> Result<(u32, u32), Error> {
    set_bb(io, RRX_IQK, MASKDWORD, 0x0100_4800)?;
    tones(io, RX_TONES)?;
    set_bb(io, RIQK_AGC_RSP, MASKDWORD, 0x0046_a8d1)?;
    shot(io).await?;
    Ok((
        get_bb(io, RRX_POWER_AFTER_IQK_A_2, MASKDWORD)?,
        get_bb(io, RRX_POWER_BEFORE_IQK_A_2, MASKDWORD)?,
    ))
}

/// The TXIMR half of both RX paths: the early exits (`Some`) carry Linux's
/// partial result (`0` when the first TX check fails, `0x01` when only
/// the second does).
async fn tximr_shot(io: &impl Io) -> Result<Option<u8>, Error> {
    set_bb(io, RTX_IQK, MASKDWORD, 0x0100_7c00)?;
    set_bb(io, RRX_IQK, MASKDWORD, 0x0100_4800)?;
    tones(io, TXIMR_TONES)?;
    set_bb(io, RIQK_AGC_RSP, MASKDWORD, 0x0046_a911)?;
    shot(io).await?;
    let (eac, e94, e9c) = tx_registers(io)?;
    if !tx_ok(eac, e94, e9c) {
        return Ok(Some(0));
    }
    if !tx_settled(eac, e94, e9c) {
        return Ok(Some(0x01));
    }
    let u32tmp = 0x8000_7c00 | (e94 & 0x03ff_0000) | field(e9c);
    set_bb(io, RTX_IQK, MASKDWORD, u32tmp)?;
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0)?;
    Ok(None)
}

/// `_rtl8723be_phy_path_a_rx_iqk` (S1; bit0 TX OK, bit1 RX OK).
pub async fn path_a_rx(io: &impl Io) -> Result<u8, Error> {
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0)?;
    set_bb(io, REG_S0S1_PATH_SWITCH, MASKDWORD, 0)?;
    set_rf(io, Path::A, RF_WE_LUT, 0x80000, 0x1).await?;
    rf_a(io, RF_RCK_OS, 0x30000).await?;
    rf_a(io, RF_TXPA_G1, 0x0001f).await?;
    rf_a(io, RF_TXPA_G2, 0xf7fb7).await?;
    // Linux enters IQK mode once before the TXIMR settings as well.
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0x8080_0000)?;
    if let Some(partial) = tximr_shot(io).await? {
        return Ok(partial);
    }
    set_rf(io, Path::A, RF_WE_LUT, 0x80000, 0x1).await?;
    rf_a(io, RF_RCK_OS, 0x30000).await?;
    rf_a(io, RF_TXPA_G1, 0x0001f).await?;
    rf_a(io, RF_TXPA_G2, 0xf7d77).await?;
    rf_a(io, 0xdf, 0xf80).await?;
    rf_a(io, 0x55, 0x4021f).await?;
    let (eac, ea4) = rx_shot(io).await?;
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0)?;
    rf_a(io, 0xdf, 0x780).await?;
    Ok(0x01 | if rx_ok(eac, ea4) { 0x02 } else { 0 })
}

/// `_rtl8723be_phy_path_b_rx_iqk` (S0 through RF path A).
pub async fn path_b_rx(io: &impl Io) -> Result<u8, Error> {
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0)?;
    set_bb(io, REG_S0S1_PATH_SWITCH, MASKDWORD, 0x280)?;
    rf_a(io, RF_WE_LUT, 0x800a0).await?;
    rf_a(io, RF_RCK_OS, 0x30000).await?;
    rf_a(io, RF_TXPA_G1, 0x0001f).await?;
    rf_a(io, RF_TXPA_G2, 0xf7ff7).await?;
    rf_a(io, 0xed, 0x00020).await?;
    rf_a(io, 0x43, 0x60fed).await?;
    if let Some(partial) = tximr_shot(io).await? {
        return Ok(partial);
    }
    set_rf(io, Path::A, RF_WE_LUT, 0x80000, 0x1).await?;
    rf_a(io, RF_RCK_OS, 0x30000).await?;
    rf_a(io, RF_TXPA_G1, 0x0001f).await?;
    rf_a(io, RF_TXPA_G2, 0xf7d77).await?;
    set_rf(io, Path::A, RF_WE_LUT, 0x80000, 0x0).await?;
    rf_a(io, 0xed, 0x00020).await?;
    rf_a(io, 0x43, 0x60fbd).await?;
    let (eac, ea4) = rx_shot(io).await?;
    Ok(0x01 | if rx_ok(eac, ea4) { 0x02 } else { 0 })
}

fn signed10(v: u32) -> i32 {
    if v & 0x200 != 0 {
        (v | 0xffff_fc00) as i32
    } else {
        v as i32
    }
}

/// `_rtl8723be_phy_simularity_compare` (`bound = 8`).
pub fn simularity_compare(result: &mut [[u32; 8]; 4], c1: usize, c2: usize) -> bool {
    let mut candidate = [0xffu8; 2];
    let mut bitmap = 0u32;
    for i in 0..8 {
        let (t1, t2) = if i % 2 == 1 {
            (signed10(result[c1][i]), signed10(result[c2][i]))
        } else {
            (result[c1][i] as i32, result[c2][i] as i32)
        };
        if t1.abs_diff(t2) > MAX_TOLERANCE {
            if (i == 2 || i == 6) && bitmap == 0 {
                if result[c1][i].wrapping_add(result[c1][i + 1]) == 0 {
                    candidate[i / 4] = c2 as u8;
                } else if result[c2][i].wrapping_add(result[c2][i + 1]) == 0 {
                    candidate[i / 4] = c1 as u8;
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
        for (i, c) in candidate.iter().copied().enumerate() {
            if c != 0xff {
                let range = i * 4..(i + 1) * 4 - 2;
                let src = result[usize::from(c)];
                result[3][range.clone()].copy_from_slice(&src[range]);
                same = false;
            }
        }
        return same;
    }
    for (mask, range) in [(0x03u32, 0..2), (0x0c, 2..4), (0x30, 4..6), (0xc0, 6..8)] {
        if bitmap & mask == 0 {
            let src = result[c1];
            result[3][range.clone()].copy_from_slice(&src[range]);
        }
    }
    false
}

/// `rtl8723_phy_path_a_fill_iqk_matrix` / `_rtl8723be_phy_path_b_fill_iqk_matrix`.
fn fill(
    io: &impl Io,
    path: Path,
    ok: bool,
    result: &[[u32; 8]; 4],
    candidate: u8,
    tx_only: bool,
) -> Result<(), Error> {
    if candidate == 0xff || !ok {
        return Ok(());
    }
    let row = &result[usize::from(candidate)];
    let (base, bit_a, bit_c, txafe, tx_iq, rx_iq) = match path {
        Path::A => (
            0,
            31,
            29,
            ROFDM0_XCTXAFE,
            ROFDM0_XATXIQIMBALANCE,
            ROFDM0_XARXIQIMBALANCE,
        ),
        Path::B => (
            4,
            27,
            25,
            ROFDM0_XDTXAFE,
            ROFDM0_XBTXIQIMBALANCE,
            ROFDM0_XBRXIQIMBALANCE,
        ),
    };
    let old = (get_bb(io, tx_iq, MASKDWORD)? >> 22) & 0x3ff;
    let mut x = row[base];
    if x & 0x200 != 0 {
        x |= 0xffff_fc00;
    }
    set_bb(io, tx_iq, 0x3ff, x.wrapping_mul(old) >> 8)?;
    set_bb(
        io,
        ROFDM0_ECCATHRESHOLD,
        1 << bit_a,
        (x.wrapping_mul(old) >> 7) & 1,
    )?;
    let mut y = row[base + 1];
    if y & 0x200 != 0 {
        y |= 0xffff_fc00;
    }
    let tx_c = y.wrapping_mul(old) >> 8;
    set_bb(io, txafe, 0xf000_0000, (tx_c & 0x3c0) >> 6)?;
    set_bb(io, tx_iq, 0x003f_0000, tx_c & 0x3f)?;
    set_bb(
        io,
        ROFDM0_ECCATHRESHOLD,
        1 << bit_c,
        (y.wrapping_mul(old) >> 7) & 1,
    )?;
    if tx_only {
        return Ok(());
    }
    set_bb(io, rx_iq, 0x3ff, row[base + 2])?;
    set_bb(io, rx_iq, 0xfc00, row[base + 3] & 0x3f)?;
    if path == Path::A {
        set_bb(io, ROFDM0_RXIQEXTANTA, 0xf000_0000, (row[3] >> 6) & 0xf)?;
    }
    Ok(())
}

/// `_rtl8723be_phy_iq_calibrate(hw, result, t, is2t = true)`.
async fn calibrate_once(
    io: &impl Io,
    result: &mut [[u32; 8]; 4],
    t: usize,
    backup: &mut Backup,
) -> Result<(), Error> {
    let c50 = get_bb(io, 0xc50, 0xff)?;
    let c58 = get_bb(io, 0xc58, 0xff)?;
    if t == 0 {
        for (b, r) in backup.adda.iter_mut().zip(ADDA_REGS) {
            *b = get_bb(io, r, MASKDWORD)?;
        }
        for (b, r) in backup.mac.iter_mut().zip(MAC_REGS).take(3) {
            *b = u32::from(io.read8(r)?);
        }
        backup.mac[3] = io.read32(MAC_REGS[3])?;
        for (b, r) in backup.bb.iter_mut().zip(BB_REGS) {
            *b = get_bb(io, r, MASKDWORD)?;
        }
    }
    // rtl8723_phy_path_adda_on: 8723BE writes 0x01c00014 to all sixteen.
    for r in ADDA_REGS {
        set_bb(io, r, MASKDWORD, 0x01c0_0014)?;
    }
    if t == 0 {
        // rtlphy->rfpi_enable (recorded, not consumed by 8723BE).
        get_bb(io, RFPGA0_XA_HSSIPARAMETER1, 1 << 8)?;
    }
    let path_sel_bb = get_bb(io, REG_S0S1_PATH_SWITCH, MASKDWORD)?;
    // rtl8723_phy_mac_setting_calibration.
    io.write8(MAC_REGS[0], 0x3f)?;
    for (r, b) in MAC_REGS.iter().zip(backup.mac).take(3).skip(1) {
        io.write8(*r, (b & !(1 << 3)) as u8)?;
    }
    io.write8(MAC_REGS[3], (backup.mac[3] & !(1 << 5)) as u8)?;
    set_bb(io, 0xa04, 0x0f00_0000, 0xf)?;
    set_bb(io, 0xc04, MASKDWORD, 0x03a0_5600)?;
    set_bb(io, 0xc08, MASKDWORD, 0x0008_00e4)?;
    set_bb(io, 0x874, MASKDWORD, 0x2220_4000)?;
    for _ in 0..RETRY {
        if path_a_tx(io).await? == 0x01 {
            result[t][0] = field(get_bb(io, RTX_POWER_BEFORE_IQK_A, MASKDWORD)?);
            result[t][1] = field(get_bb(io, RTX_POWER_AFTER_IQK_A, MASKDWORD)?);
            break;
        }
    }
    for _ in 0..RETRY {
        if path_a_rx(io).await? == 0x03 {
            result[t][2] = field(get_bb(io, RRX_POWER_BEFORE_IQK_A_2, MASKDWORD)?);
            result[t][3] = field(get_bb(io, RRX_POWER_AFTER_IQK_A_2, MASKDWORD)?);
            break;
        }
    }
    for _ in 0..RETRY {
        if path_b_tx(io).await? == 0x01 {
            result[t][4] = field(get_bb(io, RTX_POWER_BEFORE_IQK_A, MASKDWORD)?);
            result[t][5] = field(get_bb(io, RTX_POWER_AFTER_IQK_A, MASKDWORD)?);
            break;
        }
    }
    for _ in 0..RETRY {
        if path_b_rx(io).await? == 0x03 {
            result[t][6] = field(get_bb(io, RRX_POWER_BEFORE_IQK_A_2, MASKDWORD)?);
            result[t][7] = field(get_bb(io, RRX_POWER_AFTER_IQK_A_2, MASKDWORD)?);
            break;
        }
    }
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0)?;
    if t != 0 {
        for (b, r) in backup.adda.iter().zip(ADDA_REGS) {
            set_bb(io, r, MASKDWORD, *b)?;
        }
        for (b, r) in backup.mac.iter().zip(MAC_REGS).take(3) {
            io.write8(r, *b as u8)?;
        }
        io.write32(MAC_REGS[3], backup.mac[3])?;
        for (b, r) in backup.bb.iter().zip(BB_REGS) {
            set_bb(io, r, MASKDWORD, *b)?;
        }
        set_bb(io, REG_S0S1_PATH_SWITCH, MASKDWORD, path_sel_bb)?;
        set_bb(io, 0xc50, 0xff, 0x50)?;
        set_bb(io, 0xc50, 0xff, c50)?;
        set_bb(io, 0xc58, 0xff, 0x50)?;
        set_bb(io, 0xc58, 0xff, c58)?;
        set_bb(io, RTX_IQK_TONE_A, MASKDWORD, 0x0100_8c00)?;
        set_bb(io, RRX_IQK_TONE_A, MASKDWORD, 0x0100_8c00)?;
    }
    Ok(())
}

/// `rtl8723be_phy_iq_calibrate(hw, false)`.
pub async fn calibrate(io: &impl Io) -> Result<Report, Error> {
    let path_sel_bb = get_bb(io, REG_S0S1_PATH_SWITCH, MASKDWORD)?;
    let mut result = [[0u32; 8]; 4];
    let mut backup = Backup::default();
    let mut candidate = 0xffu8;
    for t in 0..3 {
        calibrate_once(io, &mut result, t, &mut backup).await?;
        if t == 1 && simularity_compare(&mut result, 0, 1) {
            candidate = 0;
            break;
        }
        if t == 2 {
            if simularity_compare(&mut result, 0, 2) {
                candidate = 0;
                break;
            }
            candidate = if simularity_compare(&mut result, 1, 2) {
                1
            } else if result[3].iter().any(|v| *v != 0) {
                3
            } else {
                0xff
            };
        }
    }
    let ok = candidate != 0xff;
    // With no candidate Linux's last loop leaves the reg_* locals at
    // result[3]; both fills return early on 0xff regardless.
    let pick = if ok { usize::from(candidate) } else { 3 };
    let row = result[pick];
    let (reg_e94, reg_e9c, reg_eb4, reg_ebc) = if ok {
        (row[0], row[1], row[4], row[5])
    } else {
        (0x100, 0, 0x100, 0)
    };
    if row[0] != 0 {
        fill(io, Path::A, ok, &result, candidate, row[2] == 0)?;
    }
    if row[4] != 0 {
        fill(io, Path::B, ok, &result, candidate, row[6] == 0)?;
    }
    let matrix = (candidate < 4).then_some(row);
    let mut saved = [0u32; 9];
    for (s, r) in saved.iter_mut().zip(RESULT_REGS) {
        *s = get_bb(io, r, MASKDWORD)?;
    }
    set_bb(io, REG_S0S1_PATH_SWITCH, MASKDWORD, path_sel_bb)?;
    Ok(Report {
        result,
        final_candidate: candidate,
        reg_e94,
        reg_e9c,
        reg_eb4,
        reg_ebc,
        matrix,
        saved,
    })
}

/// `rtl8723be_phy_iq_calibrate(hw, true)`: reload the saved result registers.
pub fn recover(io: &impl Io, saved: &[u32; 9]) -> Result<(), Error> {
    for (s, r) in saved.iter().zip(RESULT_REGS) {
        set_bb(io, r, MASKDWORD, *s)?;
    }
    Ok(())
}
