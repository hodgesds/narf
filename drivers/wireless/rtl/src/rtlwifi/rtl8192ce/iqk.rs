// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE IQ calibration (`rtl92c_phy_iq_calibrate(false)`).
//!
//! Exact `rtl8192c/phy_common.c` register effects for both RF types
//! (`is2t = IS_92C_SERIAL`): up to three `_rtl92c_phy_iq_calibrate(t)`
//! runs (t = 0 backs up the 16 ADDA dwords, the `0x522/0x550/0x551` bytes
//! and the `0x040` dword, `0xc04/0xc08/0x874`, and latches `rfpi_enable`
//! from `0x820` BIT(8)); ADDA on (`0x0b1b25a0` / `0x0bdb25a0` for 1T,
//! `0x04db25a4` path A / `0x0b1b25a4` path B for 2T); PI mode on when the
//! board runs SI; two tries of path A (and, for 2T, path-A standby then two
//! tries of path B) with Linux's brace-less `result[t][1]` / `result[t][5]`
//! assignments kept; the restores (PI/ADDA/MAC reloads only for t != 0).
//! `_rtl92c_phy_simularity_compare` (MAX_TOLERANCE 5, bound 8 or 4, the
//! zero-RX candidate rule), the candidate choice, the path A (and 2T path
//! B) matrix fills with Linux's u32 / long arithmetic, then the save of the
//! ten `iqk_bb_reg` dwords. `_rtl92c_phy_ap_calibrate` is empty in Linux
//! and no APK runs on this family.

use super::phy::{get_bb, set_bb, MASKDWORD, RFPGA0_XA_HSSIPARAMETER1};
use super::version::Version;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const ROFDM0_XARXIQIMBALANCE: u16 = 0x0c14;
pub const ROFDM0_XBRXIQIMBALANCE: u16 = 0x0c1c;
pub const ROFDM0_ECCATHRESHOLD: u16 = 0x0c4c;
pub const ROFDM0_AGCRSSITABLE: u16 = 0x0c78;
pub const ROFDM0_XATXIQIMBALANCE: u16 = 0x0c80;
pub const ROFDM0_XBTXIQIMBALANCE: u16 = 0x0c88;
pub const ROFDM0_XCTXIQIMBALANCE: u16 = 0x0c90;
pub const ROFDM0_XCTXAFE: u16 = 0x0c94;
pub const ROFDM0_XDTXAFE: u16 = 0x0c9c;
pub const ROFDM0_RXIQEXTANTA: u16 = 0x0ca0;

pub const ADDA_REGS: [u16; 16] = [
    0x85c, 0xe6c, 0xe70, 0xe74, 0xe78, 0xe7c, 0xe80, 0xe84, 0xe88, 0xe8c, 0xed0, 0xed4, 0xed8,
    0xedc, 0xee0, 0xeec,
];
pub const MAC_REGS: [u16; 4] = [0x522, 0x550, 0x551, 0x040];
pub const BB_REGS: [u16; 10] = [
    ROFDM0_XARXIQIMBALANCE,
    ROFDM0_XBRXIQIMBALANCE,
    ROFDM0_ECCATHRESHOLD,
    ROFDM0_AGCRSSITABLE,
    ROFDM0_XATXIQIMBALANCE,
    ROFDM0_XBTXIQIMBALANCE,
    ROFDM0_XCTXIQIMBALANCE,
    ROFDM0_XCTXAFE,
    ROFDM0_XDTXAFE,
    ROFDM0_RXIQEXTANTA,
];
/// `MAX_TOLERANCE`.
pub const MAX_TOLERANCE: u32 = 5;
/// `IQK_DELAY_TIME` (ms).
const IQK_DELAY_US: u64 = 1_000;
const RETRY: usize = 2;

/// Saved registers of the first run (`rtlphy->adda_backup`,
/// `iqk_mac_backup`, `reg_c04/c08/874`, `rfpi_enable`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Backup {
    adda: [u32; 16],
    mac: [u32; 4],
    c04: u32,
    c08: u32,
    r874: u32,
    rfpi: bool,
}

/// Outcome of one calibration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub result: [[i64; 8]; 4],
    /// `final_candidate` (0xff: none).
    pub candidate: u8,
    /// `rtlphy->reg_e94 / reg_e9c / reg_eb4 / reg_ebc`.
    pub e94: i64,
    pub e9c: i64,
    pub eb4: i64,
    pub ebc: i64,
    /// `rtlphy->iqk_bb_backup` (the recovery image).
    pub bb_backup: [u32; 10],
}

fn field(io: &impl Io, at: u16) -> Result<i64, Error> {
    Ok(i64::from((get_bb(io, at, MASKDWORD)? & 0x03ff_0000) >> 16))
}

/// `_rtl92c_phy_path_a_iqk`.
async fn path_a_iqk(io: &impl Io, config_pathb: bool) -> Result<u8, Error> {
    set_bb(io, 0xe30, MASKDWORD, 0x1000_8c1f)?;
    set_bb(io, 0xe34, MASKDWORD, 0x1000_8c1f)?;
    set_bb(io, 0xe38, MASKDWORD, 0x8214_0102)?;
    set_bb(
        io,
        0xe3c,
        MASKDWORD,
        if config_pathb {
            0x2816_0202
        } else {
            0x2816_0502
        },
    )?;
    if config_pathb {
        set_bb(io, 0xe50, MASKDWORD, 0x1000_8c22)?;
        set_bb(io, 0xe54, MASKDWORD, 0x1000_8c22)?;
        set_bb(io, 0xe58, MASKDWORD, 0x8214_0102)?;
        set_bb(io, 0xe5c, MASKDWORD, 0x2816_0202)?;
    }
    set_bb(io, 0xe4c, MASKDWORD, 0x0010_28d1)?;
    set_bb(io, 0xe48, MASKDWORD, 0xf900_0000)?;
    set_bb(io, 0xe48, MASKDWORD, 0xf800_0000)?;
    io.delay_us(IQK_DELAY_US).await;
    let eac = get_bb(io, 0xeac, MASKDWORD)?;
    let e94 = get_bb(io, 0xe94, MASKDWORD)?;
    let e9c = get_bb(io, 0xe9c, MASKDWORD)?;
    let ea4 = get_bb(io, 0xea4, MASKDWORD)?;
    let f = |v: u32| (v & 0x03ff_0000) >> 16;
    let mut result = 0;
    if eac & (1 << 28) == 0 && f(e94) != 0x142 && f(e9c) != 0x42 {
        result |= 0x01;
    } else {
        return Ok(result);
    }
    if eac & (1 << 27) == 0 && f(ea4) != 0x132 && f(eac) != 0x36 {
        result |= 0x02;
    }
    Ok(result)
}

/// `_rtl92c_phy_path_b_iqk`.
async fn path_b_iqk(io: &impl Io) -> Result<u8, Error> {
    set_bb(io, 0xe60, MASKDWORD, 0x0000_0002)?;
    set_bb(io, 0xe60, MASKDWORD, 0x0000_0000)?;
    io.delay_us(IQK_DELAY_US).await;
    let eac = get_bb(io, 0xeac, MASKDWORD)?;
    let eb4 = get_bb(io, 0xeb4, MASKDWORD)?;
    let ebc = get_bb(io, 0xebc, MASKDWORD)?;
    let ec4 = get_bb(io, 0xec4, MASKDWORD)?;
    let ecc = get_bb(io, 0xecc, MASKDWORD)?;
    let f = |v: u32| (v & 0x03ff_0000) >> 16;
    let mut result = 0;
    if eac & (1 << 31) == 0 && f(eb4) != 0x142 && f(ebc) != 0x42 {
        result |= 0x01;
    } else {
        return Ok(result);
    }
    if eac & (1 << 30) == 0 && f(ec4) != 0x132 && f(ecc) != 0x36 {
        result |= 0x02;
    }
    Ok(result)
}

/// `_rtl92c_phy_path_adda_on`.
fn adda_on(io: &impl Io, patha_on: bool, is2t: bool) -> Result<(), Error> {
    let mut pathon = if patha_on { 0x04db_25a4 } else { 0x0b1b_25a4 };
    if !is2t {
        pathon = 0x0bdb_25a0;
        set_bb(io, ADDA_REGS[0], MASKDWORD, 0x0b1b_25a0)?;
    } else {
        set_bb(io, ADDA_REGS[0], MASKDWORD, pathon)?;
    }
    for r in &ADDA_REGS[1..] {
        set_bb(io, *r, MASKDWORD, pathon)?;
    }
    Ok(())
}

/// `_rtl92c_phy_pi_mode_switch`.
fn pi_mode(io: &impl Io, on: bool) -> Result<(), Error> {
    let mode = if on { 0x0100_0100 } else { 0x0100_0000 };
    set_bb(io, 0x820, MASKDWORD, mode)?;
    set_bb(io, 0x828, MASKDWORD, mode)
}

/// `_rtl92c_phy_iq_calibrate(result, t, is2t)`.
async fn run(
    io: &impl Io,
    result: &mut [[i64; 8]; 4],
    t: usize,
    is2t: bool,
    backup: &mut Backup,
) -> Result<(), Error> {
    if t == 0 {
        get_bb(io, 0x800, MASKDWORD)?;
        for (b, r) in backup.adda.iter_mut().zip(ADDA_REGS) {
            *b = get_bb(io, r, MASKDWORD)?;
        }
        for (i, (b, r)) in backup.mac.iter_mut().zip(MAC_REGS).enumerate() {
            *b = if i < 3 {
                u32::from(io.read8(r)?)
            } else {
                io.read32(r)?
            };
        }
    }
    adda_on(io, true, is2t)?;
    if t == 0 {
        backup.rfpi = get_bb(io, RFPGA0_XA_HSSIPARAMETER1, 1 << 8)? != 0;
    }
    if !backup.rfpi {
        pi_mode(io, true)?;
    }
    if t == 0 {
        backup.c04 = get_bb(io, 0xc04, MASKDWORD)?;
        backup.c08 = get_bb(io, 0xc08, MASKDWORD)?;
        backup.r874 = get_bb(io, 0x874, MASKDWORD)?;
    }
    set_bb(io, 0xc04, MASKDWORD, 0x03a0_5600)?;
    set_bb(io, 0xc08, MASKDWORD, 0x0008_00e4)?;
    set_bb(io, 0x874, MASKDWORD, 0x2220_4000)?;
    if is2t {
        set_bb(io, 0x840, MASKDWORD, 0x0001_0000)?;
        set_bb(io, 0x844, MASKDWORD, 0x0001_0000)?;
    }
    // _rtl92c_phy_mac_setting_calibration.
    io.write8(MAC_REGS[0], 0x3f)?;
    for (r, b) in MAC_REGS[1..3].iter().zip(&backup.mac[1..3]) {
        io.write8(*r, (b & !(1 << 3)) as u8)?;
    }
    io.write8(MAC_REGS[3], (backup.mac[3] & !(1 << 5)) as u8)?;
    set_bb(io, 0xb68, MASKDWORD, 0x0008_0000)?;
    if is2t {
        set_bb(io, 0xb6c, MASKDWORD, 0x0008_0000)?;
    }
    set_bb(io, 0xe28, MASKDWORD, 0x8080_0000)?;
    set_bb(io, 0xe40, MASKDWORD, 0x0100_7c00)?;
    set_bb(io, 0xe44, MASKDWORD, 0x0100_4800)?;
    for i in 0..RETRY {
        let ok = path_a_iqk(io, is2t).await?;
        if ok == 0x03 {
            result[t][0] = field(io, 0xe94)?;
            result[t][1] = field(io, 0xe9c)?;
            result[t][2] = field(io, 0xea4)?;
            result[t][3] = field(io, 0xeac)?;
            break;
        } else if i == RETRY - 1 && ok == 0x01 {
            result[t][0] = field(io, 0xe94)?;
        }
        // Linux: outside the brace-less else-if, on every unfinished try.
        result[t][1] = field(io, 0xe9c)?;
    }
    if is2t {
        // _rtl92c_phy_path_a_standby.
        set_bb(io, 0xe28, MASKDWORD, 0)?;
        set_bb(io, 0x840, MASKDWORD, 0x0001_0000)?;
        set_bb(io, 0xe28, MASKDWORD, 0x8080_0000)?;
        adda_on(io, false, is2t)?;
        for i in 0..RETRY {
            let ok = path_b_iqk(io).await?;
            if ok == 0x03 {
                result[t][4] = field(io, 0xeb4)?;
                result[t][5] = field(io, 0xebc)?;
                result[t][6] = field(io, 0xec4)?;
                result[t][7] = field(io, 0xecc)?;
                break;
            } else if i == RETRY - 1 && ok == 0x01 {
                result[t][4] = field(io, 0xeb4)?;
            }
            result[t][5] = field(io, 0xebc)?;
        }
    }
    set_bb(io, 0xc04, MASKDWORD, backup.c04)?;
    set_bb(io, 0x874, MASKDWORD, backup.r874)?;
    set_bb(io, 0xc08, MASKDWORD, backup.c08)?;
    set_bb(io, 0xe28, MASKDWORD, 0)?;
    set_bb(io, 0x840, MASKDWORD, 0x0003_2ed3)?;
    if is2t {
        set_bb(io, 0x844, MASKDWORD, 0x0003_2ed3)?;
    }
    if t != 0 {
        if !backup.rfpi {
            pi_mode(io, false)?;
        }
        for (r, v) in ADDA_REGS.iter().zip(backup.adda) {
            set_bb(io, *r, MASKDWORD, v)?;
        }
        for (r, b) in MAC_REGS[..3].iter().zip(&backup.mac[..3]) {
            io.write8(*r, *b as u8)?;
        }
        io.write32(MAC_REGS[3], backup.mac[3])?;
    }
    Ok(())
}

/// `_rtl92c_phy_simularity_compare(result, c1, c2)`.
pub fn simularity_compare(result: &mut [[i64; 8]; 4], c1: usize, c2: usize, is2t: bool) -> bool {
    let bound = if is2t { 8 } else { 4 };
    let mut candidate = [0xffu8; 2];
    let mut bitmap = 0u32;
    for i in 0..bound {
        let diff = result[c1][i].abs_diff(result[c2][i]) as u32;
        if diff > MAX_TOLERANCE {
            if (i == 2 || i == 6) && bitmap == 0 {
                if result[c1][i] + result[c1][i + 1] == 0 {
                    candidate[i / 4] = c2 as u8;
                } else if result[c2][i] + result[c2][i + 1] == 0 {
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
        for i in 0..bound / 4 {
            if candidate[i] != 0xff {
                let src = result[usize::from(candidate[i])];
                result[3][i * 4..(i + 1) * 4 - 2].copy_from_slice(&src[i * 4..(i + 1) * 4 - 2]);
                same = false;
            }
        }
        same
    } else if bitmap & 0x0f == 0 {
        let src = result[c1];
        result[3][..4].copy_from_slice(&src[..4]);
        false
    } else if bitmap & 0xf0 == 0 && is2t {
        let src = result[c1];
        result[3][4..].copy_from_slice(&src[4..]);
        false
    } else {
        false
    }
}

/// `_rtl92c_phy_path_{a,b}_fill_iqk_matrix` (`b_iqk_ok` true, a candidate
/// chosen). `regs` = (TX IQ imbalance, ECCA bits for x/y, C/D TX AFE, RX
/// IQ imbalance, RX extension register and mask).
#[allow(clippy::too_many_arguments)]
fn fill(
    io: &impl Io,
    r: &[i64; 8],
    off: usize,
    tx: u16,
    ecca_x: u32,
    ecca_y: u32,
    txafe: u16,
    rx: u16,
    ext: (u16, u32),
    txonly: bool,
) -> Result<(), Error> {
    let oldval = (get_bb(io, tx, MASKDWORD)? >> 22) & 0x3ff;
    let mut x = r[off] as u32;
    if x & 0x200 != 0 {
        x |= 0xffff_fc00;
    }
    let tx_a = x.wrapping_mul(oldval) >> 8;
    set_bb(io, tx, 0x3ff, tx_a)?;
    set_bb(
        io,
        ROFDM0_ECCATHRESHOLD,
        ecca_x,
        (x.wrapping_mul(oldval) >> 7) & 1,
    )?;
    // `long y`: 0xFFFFFC00 ORs in as a positive value; only low bits are used.
    let mut y = r[off + 1];
    if y & 0x200 != 0 {
        y |= 0xffff_fc00;
    }
    let tx_c = y.wrapping_mul(i64::from(oldval)) >> 8;
    set_bb(io, txafe, 0xf000_0000, ((tx_c & 0x3c0) >> 6) as u32)?;
    set_bb(io, tx, 0x003f_0000, (tx_c & 0x3f) as u32)?;
    set_bb(
        io,
        ROFDM0_ECCATHRESHOLD,
        ecca_y,
        ((y.wrapping_mul(i64::from(oldval)) >> 7) & 1) as u32,
    )?;
    if txonly {
        return Ok(());
    }
    set_bb(io, rx, 0x3ff, r[off + 2] as u32)?;
    set_bb(io, rx, 0xfc00, (r[off + 3] & 0x3f) as u32)?;
    set_bb(io, ext.0, ext.1, ((r[off + 3] >> 6) & 0xf) as u32)
}

/// `rtl92c_phy_iq_calibrate(hw, false)` for the qualified version.
pub async fn calibrate(io: &impl Io, version: Version) -> Result<Report, Error> {
    let is2t = version.is_92c_serial();
    let mut result = [[0i64; 8]; 4];
    let mut backup = Backup::default();
    let mut candidate = 0xffu8;
    for t in 0..3 {
        run(io, &mut result, t, is2t, &mut backup).await?;
        if t == 1 && simularity_compare(&mut result, 0, 1, is2t) {
            candidate = 0;
            break;
        }
        if t == 2 {
            if simularity_compare(&mut result, 0, 2, is2t) {
                candidate = 0;
                break;
            }
            if simularity_compare(&mut result, 1, 2, is2t) {
                candidate = 1;
            } else {
                let sum: i64 = result[3].iter().sum();
                candidate = if sum != 0 { 3 } else { 0xff };
            }
        }
    }
    // Linux's trailing loop leaves the locals at result[3] when no
    // candidate exists; the fills then return at `final_candidate == 0xFF`.
    let pick = result[usize::from(candidate.min(3))];
    let (e94, e9c, eb4, ebc) = if candidate != 0xff {
        (pick[0], pick[1], pick[4], pick[5])
    } else {
        (0x100, 0, 0x100, 0)
    };
    if candidate != 0xff {
        if pick[0] != 0 {
            fill(
                io,
                &pick,
                0,
                ROFDM0_XATXIQIMBALANCE,
                1 << 31,
                1 << 29,
                ROFDM0_XCTXAFE,
                ROFDM0_XARXIQIMBALANCE,
                (ROFDM0_RXIQEXTANTA, 0xf000_0000),
                pick[2] == 0,
            )?;
        }
        if is2t && pick[4] != 0 {
            fill(
                io,
                &pick,
                4,
                ROFDM0_XBTXIQIMBALANCE,
                1 << 27,
                1 << 25,
                ROFDM0_XDTXAFE,
                ROFDM0_XBRXIQIMBALANCE,
                (ROFDM0_AGCRSSITABLE, 0x0000_f000),
                pick[6] == 0,
            )?;
        }
    }
    let mut bb_backup = [0u32; 10];
    for (b, r) in bb_backup.iter_mut().zip(BB_REGS) {
        *b = get_bb(io, r, MASKDWORD)?;
    }
    Ok(Report {
        result,
        candidate,
        e94,
        e9c,
        eb4,
        ebc,
        bb_backup,
    })
}

/// `rtl92c_phy_iq_calibrate(hw, true)`: reload the saved result registers.
pub fn recover(io: &impl Io, report: &Report) -> Result<(), Error> {
    for (r, v) in BB_REGS.iter().zip(report.bb_backup) {
        set_bb(io, *r, MASKDWORD, v)?;
    }
    Ok(())
}
