// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE BB/RF configuration over the `table.c` arrays (2T2R).
//!
//! Exact Linux `rtl8192ee/phy.c` / `rf.c` register effects:
//!
//! - `rtl92ee_phy_set_bb_reg` / `rtl92ee_phy_query_bb_reg` (the shifted
//!   value is not re-masked, as in Linux).
//! - `_rtl92ee_phy_rf_serial_write` / `_rtl92ee_phy_rf_serial_read` over the
//!   `phy_init_bb_rf_register_def` path definitions (LSSI write word, HSSI
//!   read-edge toggle on `0x824`, 20 us settle, PI/SI read-back selection).
//! - `_rtl92ee_phy_config_mac_with_headerfile`: every MAC row as a byte
//!   write (Linux does not run `_check_condition` over this array).
//! - `rtl92ee_phy_bb_config`: BB enable, PHY_REG walk, the PHY_REG_PG
//!   power-by-rate store (`phy_config_bb_with_pghdrfile`) with
//!   `_rtl92ee_phy_txpower_by_rate_configuration` (base and relative
//!   conversion), the AGC walk, `cck_high_power` and the crystal cap.
//! - `rtl92ee_phy_rf6052_config` (`RF_2T2R`: paths A and B) with
//!   `_rtl92ee_config_rf_reg`'s `0xb6` / `0xb2` read-back retries.
//!
//! Only provisioned boards reach this module (the adapter decode refuses
//! an autoload failure), so the PG walk always runs, as Linux does when
//! `!autoload_failflag`.

use super::headerfile::{bb_action, rf_action, walk, BbAction, Condition, RfAction};
use super::tables;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;
use alloc::vec::Vec;

pub const REG_SYS_FUNC_EN: u16 = 0x0002;
pub const REG_RF_CTRL: u16 = 0x001f;
pub const REG_AFE_XTAL_CTRL: u16 = 0x0024;
pub const REG_MAC_PHY_CTRL: u16 = 0x002c;
/// `REG_SYS_FUNC_EN` byte written after the RF enable (`FEN_PPLL |
/// FEN_PCIEA | FEN_DIO_PCIE | FEN_BB_GLB_RSTN | FEN_BBRSTB`).
pub const SYS_FUNC_EN_BB: u8 = 0x80 | 0x40 | 0x20 | 0x02 | 0x01;
/// `RF_EN | RF_RSTB | RF_SDMRSTB`.
pub const RF_CTRL_ON: u8 = 0x07;

pub const RFPGA0_RFMOD: u16 = 0x0800;
pub const RFPGA0_XA_HSSIPARAMETER1: u16 = 0x0820;
pub const RFPGA0_XA_HSSIPARAMETER2: u16 = 0x0824;
pub const RFPGA0_XB_HSSIPARAMETER1: u16 = 0x0828;
pub const RFPGA0_XB_HSSIPARAMETER2: u16 = 0x082c;
pub const RFPGA0_XA_LSSIPARAMETER: u16 = 0x0840;
pub const RFPGA0_XB_LSSIPARAMETER: u16 = 0x0844;
pub const RFPGA0_XA_RFINTERFACEOE: u16 = 0x0860;
pub const RFPGA0_XB_RFINTERFACEOE: u16 = 0x0864;
pub const RFPGA0_XAB_RFINTERFACESW: u16 = 0x0870;
pub const RFPGA0_XA_LSSIREADBACK: u16 = 0x08a0;
pub const RFPGA0_XB_LSSIREADBACK: u16 = 0x08a4;
pub const TRANSCEIVEA_HSPI_READBACK: u16 = 0x08b8;
pub const TRANSCEIVEB_HSPI_READBACK: u16 = 0x08bc;

pub const MASKDWORD: u32 = u32::MAX;
pub const RFREG_OFFSET_MASK: u32 = 0x000f_ffff;
pub const BLSSIREADADDRESS: u32 = 0x7f80_0000;
pub const BLSSIREADEDGE: u32 = 0x8000_0000;
pub const BLSSIREADBACKDATA: u32 = 0x000f_ffff;
pub const BRFSI_RFENV: u32 = 0x10;
pub const B3WIREADDREAALENGTH: u32 = 0x400;
pub const B3WIREDATALENGTH: u32 = 0x800;
pub const BCCKEN: u32 = 0x0100_0000;
pub const BOFDMEN: u32 = 0x0200_0000;

/// RF registers used by the init tail and channel code (`reg.h`).
pub const RF_CHNLBW: u32 = 0x18;
pub const RF_RX_G1: u32 = 0x1a;

/// `RF90_PATH_A` / `RF90_PATH_B` (`rtlphy->num_total_rfpath = 2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    A = 0,
    B = 1,
}

pub const PATHS: [Path; 2] = [Path::A, Path::B];

/// `phy_init_bb_rf_register_def` for one path.
#[derive(Clone, Copy, Debug)]
pub struct PathRegs {
    pub rfintfs: u16,
    pub rfintfo: u16,
    pub rfintfe: u16,
    pub rf3wire_offset: u16,
    pub rfhssi_para1: u16,
    pub rfhssi_para2: u16,
    pub rf_rb: u16,
    pub rf_rbpi: u16,
}

impl Path {
    pub const fn regs(self) -> PathRegs {
        match self {
            Path::A => PathRegs {
                rfintfs: RFPGA0_XAB_RFINTERFACESW,
                rfintfo: RFPGA0_XA_RFINTERFACEOE,
                rfintfe: RFPGA0_XA_RFINTERFACEOE,
                rf3wire_offset: RFPGA0_XA_LSSIPARAMETER,
                rfhssi_para1: RFPGA0_XA_HSSIPARAMETER1,
                rfhssi_para2: RFPGA0_XA_HSSIPARAMETER2,
                rf_rb: RFPGA0_XA_LSSIREADBACK,
                rf_rbpi: TRANSCEIVEA_HSPI_READBACK,
            },
            Path::B => PathRegs {
                rfintfs: RFPGA0_XAB_RFINTERFACESW,
                rfintfo: RFPGA0_XB_RFINTERFACEOE,
                rfintfe: RFPGA0_XB_RFINTERFACEOE,
                rf3wire_offset: RFPGA0_XB_LSSIPARAMETER,
                rfhssi_para1: RFPGA0_XB_HSSIPARAMETER1,
                rfhssi_para2: RFPGA0_XB_HSSIPARAMETER2,
                rf_rb: RFPGA0_XB_LSSIREADBACK,
                rf_rbpi: TRANSCEIVEB_HSPI_READBACK,
            },
        }
    }
}

fn shift(mask: u32) -> u32 {
    mask.trailing_zeros() & 31
}

fn reg(addr: u32) -> Result<u16, Error> {
    u16::try_from(addr)
        .ok()
        .filter(|r| r & 3 == 0)
        .ok_or(Error::Descriptor)
}

/// `rtl92ee_phy_set_bb_reg`.
pub fn set_bb(io: &impl Io, at: u16, mask: u32, value: u32) -> Result<(), Error> {
    let data = if mask == MASKDWORD {
        value
    } else {
        (io.read32(at)? & !mask) | (value << shift(mask))
    };
    io.write32(at, data)?;
    Ok(())
}

/// `rtl92ee_phy_query_bb_reg`.
pub fn get_bb(io: &impl Io, at: u16, mask: u32) -> Result<u32, Error> {
    Ok((io.read32(at)? & mask) >> shift(mask))
}

/// `_rtl92ee_phy_rf_serial_write`.
pub fn rf_write(io: &impl Io, path: Path, offset: u32, data: u32) -> Result<(), Error> {
    let word = (((offset & 0xff) << 20) | (data & 0x000f_ffff)) & 0x0fff_ffff;
    set_bb(io, path.regs().rf3wire_offset, MASKDWORD, word)
}

/// `_rtl92ee_phy_rf_serial_read`.
pub async fn rf_read(io: &impl Io, path: Path, offset: u32) -> Result<u32, Error> {
    let regs = path.regs();
    let offset = offset & 0xff;
    let tmplong = get_bb(io, RFPGA0_XA_HSSIPARAMETER2, MASKDWORD)?;
    let tmplong2 = if path == Path::A {
        tmplong
    } else {
        get_bb(io, regs.rfhssi_para2, MASKDWORD)?
    };
    let tmplong2 = (tmplong2 & !BLSSIREADADDRESS) | (offset << 23) | BLSSIREADEDGE;
    set_bb(
        io,
        RFPGA0_XA_HSSIPARAMETER2,
        MASKDWORD,
        tmplong & !BLSSIREADEDGE,
    )?;
    set_bb(io, regs.rfhssi_para2, MASKDWORD, tmplong2)?;
    io.delay_us(20).await;
    let pi = get_bb(io, regs.rfhssi_para1, 1 << 8)? != 0;
    get_bb(
        io,
        if pi { regs.rf_rbpi } else { regs.rf_rb },
        BLSSIREADBACKDATA,
    )
}

/// `rtl92ee_phy_set_rf_reg` (the shifted value is not re-masked).
pub async fn set_rf(
    io: &impl Io,
    path: Path,
    offset: u32,
    mask: u32,
    value: u32,
) -> Result<(), Error> {
    let data = if mask == RFREG_OFFSET_MASK {
        value
    } else {
        (rf_read(io, path, offset).await? & !mask) | (value << shift(mask))
    };
    rf_write(io, path, offset, data)
}

/// `rtl92ee_phy_query_rf_reg`.
pub async fn get_rf(io: &impl Io, path: Path, offset: u32, mask: u32) -> Result<u32, Error> {
    Ok((rf_read(io, path, offset).await? & mask) >> shift(mask))
}

/// Rows the walker selects for this board, in source order.
pub fn selected(table: &[[u32; 2]], condition: &Condition) -> Vec<(u32, u32)> {
    let mut rows = Vec::new();
    let _ = walk::<()>(table, condition, |a, d| {
        rows.push((a, d));
        Ok(())
    });
    rows
}

/// `_rtl92ee_phy_config_mac_with_headerfile`: every row, byte writes.
pub fn mac_config(io: &impl Io) -> Result<(), Error> {
    for [addr, data] in tables::MAC.iter().copied() {
        let at = u16::try_from(addr).map_err(|_| Error::Descriptor)?;
        io.write8(at, data as u8)?;
    }
    Ok(())
}

// ── Power by rate (`PHY_REG_PG`) ─────────────────────────────────────────

/// `TX_PWR_BY_RATE_NUM_SECTION`.
pub const SECTIONS: usize = 12;
/// `MAX_RF_PATH` (rf path and tx-number bound of the store).
pub const MAX_RF_PATH: usize = 4;
/// `RF_1TX` / `RF_2TX`.
pub const RF_1TX: usize = 0;
pub const RF_2TX: usize = 1;

/// `_rtl92ee_get_rate_section_index`.
pub fn rate_section_index(regaddr: u32) -> usize {
    match regaddr {
        0xe00 | 0x830 => 0,
        0xe04 | 0x834 => 1,
        0xe08 | 0x838 => 2,
        0x86c => 3,
        0xe10 | 0x83c => 4,
        0xe14 | 0x848 => 5,
        0xe18 | 0x84c => 6,
        0xe1c | 0x868 => 7,
        _ => {
            let r = regaddr & 0xfff;
            if (0xc20..=0xc4c).contains(&r) {
                ((r - 0xc20) / 4) as usize
            } else if (0xe20..=0xe4c).contains(&r) {
                ((r - 0xe20) / 4) as usize
            } else {
                0
            }
        }
    }
}

/// `rtlphy->tx_power_by_rate_offset[BAND_ON_2_4G]` and
/// `txpwr_by_rate_base_24g` after `_rtl92ee_phy_txpower_by_rate_configuration`.
/// Rows for `BAND_ON_5G` are stored by Linux but never read on this chip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByRate {
    pub offset: [[[u32; SECTIONS]; MAX_RF_PATH]; MAX_RF_PATH],
    /// `[path][txnum][CCK, OFDM, HT_MCS0_MCS7, HT_MCS8_MCS15]`.
    pub base: [[[u8; 4]; 2]; 2],
}

fn bcd(raw: u32) -> u8 {
    let raw = (raw & 0xff) as u8;
    (raw >> 4).wrapping_mul(10).wrapping_add(raw & 0xf)
}

/// `_phy_convert_txpower_dbm_to_relative_value`.
pub fn to_relative(data: u32, start: u8, end: u8, base: u8) -> u32 {
    let mut out = 0u32;
    for i in (0..4u8).rev() {
        let tmp = if i >= start && i <= end {
            let lo = ((data >> (u32::from(i) * 8)) & 0xf) as u8;
            let hi = ((data >> (u32::from(i) * 8 + 4)) & 0xf) as u8;
            // `(tmp > base) ? tmp - base : base - tmp`.
            lo.wrapping_add(hi.wrapping_mul(10)).abs_diff(base)
        } else {
            (data >> (u32::from(i) * 8)) as u8
        };
        out = (out << 8) | u32::from(tmp);
    }
    out
}

impl ByRate {
    /// `phy_config_bb_with_pghdrfile` (rows `v1 < 0xcdcdcdcd` stored, the
    /// rest skipped six words at a time) then `_rtl92ee_phy_store_txpower_by_rate_base`
    /// and `phy_convert_txpwr_dbm_to_rel_val`.
    pub fn from_pg(table: &[[u32; 6]]) -> Self {
        let mut offset = [[[0u32; SECTIONS]; MAX_RF_PATH]; MAX_RF_PATH];
        for [band, rf, txnum, regaddr, _mask, data] in table.iter().copied() {
            if band >= 0xcdcd_cdcd {
                continue;
            }
            // _rtl92ee_store_tx_power_by_rate: invalid band/path/txnum dropped.
            if band != 0 || rf as usize >= MAX_RF_PATH || txnum as usize >= MAX_RF_PATH {
                continue;
            }
            offset[rf as usize][txnum as usize][rate_section_index(regaddr)] = data;
        }
        let mut base = [[[0u8; 4]; 2]; 2];
        for path in 0..2 {
            let cck = if path == 0 {
                offset[0][RF_1TX][3] >> 24
            } else {
                offset[1][RF_1TX][3]
            };
            base[path][RF_1TX][0] = bcd(cck);
            base[path][RF_1TX][1] = bcd(offset[path][RF_1TX][1] >> 24);
            base[path][RF_1TX][2] = bcd(offset[path][RF_1TX][5] >> 24);
            base[path][RF_2TX][3] = bcd(offset[path][RF_2TX][7] >> 24);
        }
        for rf in 0..2 {
            let b = base[rf][RF_1TX][0];
            if rf == 0 {
                offset[rf][RF_1TX][2] = to_relative(offset[rf][RF_1TX][2], 1, 1, b);
                offset[rf][RF_1TX][3] = to_relative(offset[rf][RF_1TX][3], 1, 3, b);
            } else {
                offset[rf][RF_1TX][3] = to_relative(offset[rf][RF_1TX][3], 0, 0, b);
                offset[rf][RF_1TX][2] = to_relative(offset[rf][RF_1TX][2], 1, 3, b);
            }
            let b = base[rf][RF_1TX][1];
            offset[rf][RF_1TX][0] = to_relative(offset[rf][RF_1TX][0], 0, 3, b);
            offset[rf][RF_1TX][1] = to_relative(offset[rf][RF_1TX][1], 0, 3, b);
            let b = base[rf][RF_1TX][2];
            offset[rf][RF_1TX][4] = to_relative(offset[rf][RF_1TX][4], 0, 3, b);
            offset[rf][RF_1TX][5] = to_relative(offset[rf][RF_1TX][5], 0, 3, b);
            let b = base[rf][RF_2TX][3];
            offset[rf][RF_2TX][6] = to_relative(offset[rf][RF_2TX][6], 0, 3, b);
            offset[rf][RF_2TX][7] = to_relative(offset[rf][RF_2TX][7], 0, 3, b);
        }
        Self { offset, base }
    }
}

// ── BB / RF configuration ────────────────────────────────────────────────

/// Facts produced by BB/RF configuration of one provisioned board.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub crystal_cap: u8,
    /// `rtlphy->cck_high_power` read back after the AGC table.
    pub cck_high_power: bool,
    pub by_rate: ByRate,
}

/// `rtl92ee_phy_bb_config` register effects in Linux order.
pub async fn bb_config(
    io: &impl Io,
    condition: &Condition,
    crystal_cap: u8,
) -> Result<(bool, ByRate), Error> {
    // rtl_read_word / rtl_write_word(REG_SYS_FUNC_EN, | BIT13 | BIT0 | BIT1).
    let lo = io.read8(REG_SYS_FUNC_EN)?;
    let hi = io.read8(REG_SYS_FUNC_EN + 1)?;
    let regval = u16::from_le_bytes([lo, hi]) | (1 << 13) | 1 | (1 << 1);
    io.write16(REG_SYS_FUNC_EN, regval)?;
    io.write8(REG_RF_CTRL, RF_CTRL_ON)?;
    io.write8(REG_SYS_FUNC_EN, SYS_FUNC_EN_BB)?;
    io.write8(REG_AFE_XTAL_CTRL + 1, 0x80)?;
    let tmp = io.read32(0x4c)?;
    io.write32(0x4c, tmp | (1 << 23))?;
    // phy_config_bb_with_hdr_file(BASEBAND_CONFIG_PHY_REG).
    for (addr, data) in selected(tables::PHY_REG, condition) {
        match bb_action(addr, data) {
            BbAction::DelayUs(us) => io.delay_us(u64::from(us)).await,
            BbAction::Write { addr, data } => set_bb(io, reg(u32::from(addr))?, MASKDWORD, data)?,
        }
        io.delay_us(1).await;
    }
    let by_rate = ByRate::from_pg(tables::PHY_REG_PG);
    // BASEBAND_CONFIG_AGC_TAB: every row a dword write + udelay(1).
    for (addr, data) in selected(tables::AGC, condition) {
        set_bb(io, reg(addr)?, MASKDWORD, data)?;
        io.delay_us(1).await;
    }
    let cck_high_power = get_bb(io, RFPGA0_XA_HSSIPARAMETER2, 0x200)? != 0;
    let cap = u32::from(crystal_cap & 0x3f);
    set_bb(io, REG_MAC_PHY_CTRL, 0x00ff_f000, cap | (cap << 6))?;
    Ok((cck_high_power, by_rate))
}

/// `_rtl92ee_config_rf_reg` (`regaddr = addr | (content & 0xE000)` is
/// `addr` for both radio contents `0x1000`/`0x1001`).
pub async fn config_rf_reg(io: &impl Io, path: Path, addr: u32, data: u32) -> Result<(), Error> {
    match rf_action(addr, data) {
        RfAction::DelayUs(us) => {
            io.delay_us(u64::from(us)).await;
            return Ok(());
        }
        RfAction::Write { .. } => {}
    }
    set_rf(io, path, addr, RFREG_OFFSET_MASK, data).await?;
    io.delay_us(1).await;
    if addr == 0xb6 {
        let mut got = get_rf(io, path, addr, MASKDWORD).await?;
        io.delay_us(1).await;
        let mut count = 0u8;
        while (got >> 8) != (data >> 8) {
            count += 1;
            set_rf(io, path, addr, RFREG_OFFSET_MASK, data).await?;
            io.delay_us(1).await;
            got = get_rf(io, path, addr, MASKDWORD).await?;
            if count > 5 {
                break;
            }
        }
    }
    if addr == 0xb2 {
        let mut got = get_rf(io, path, addr, MASKDWORD).await?;
        io.delay_us(1).await;
        let mut count = 0u8;
        while got != data {
            count += 1;
            set_rf(io, path, addr, RFREG_OFFSET_MASK, data).await?;
            io.delay_us(1).await;
            set_rf(io, path, 0x18, RFREG_OFFSET_MASK, 0x0fc07).await?;
            io.delay_us(1).await;
            got = get_rf(io, path, addr, MASKDWORD).await?;
            if count > 5 {
                break;
            }
        }
    }
    Ok(())
}

/// `_rtl92ee_phy_rf6052_config_parafile` for `RF_2T2R`.
pub async fn rf_config(io: &impl Io, condition: &Condition) -> Result<(), Error> {
    for path in PATHS {
        let regs = path.regs();
        let env_mask = match path {
            Path::A => BRFSI_RFENV,
            Path::B => BRFSI_RFENV << 16,
        };
        let saved = get_bb(io, regs.rfintfs, env_mask)?;
        set_bb(io, regs.rfintfe, BRFSI_RFENV << 16, 0x1)?;
        io.delay_us(1).await;
        set_bb(io, regs.rfintfo, BRFSI_RFENV, 0x1)?;
        io.delay_us(1).await;
        set_bb(io, regs.rfhssi_para2, B3WIREADDREAALENGTH, 0x0)?;
        io.delay_us(1).await;
        set_bb(io, regs.rfhssi_para2, B3WIREDATALENGTH, 0x0)?;
        io.delay_us(1).await;
        let table = match path {
            Path::A => tables::RADIOA,
            Path::B => tables::RADIOB,
        };
        for (addr, data) in selected(table, condition) {
            config_rf_reg(io, path, addr, data).await?;
        }
        set_bb(io, regs.rfintfs, env_mask, saved)?;
    }
    Ok(())
}

/// `rtl92ee_hw_init` from `rtl92ee_phy_mac_config` through the
/// `RF_CHNLBW` / CCK-OFDM-on / RF `0xB1` writes that follow the RF tables.
/// Returns the report and `rtlphy->rfreg_chnlval` (`[0]` after the 20 MHz
/// update; `[1]` as read) and `backup_rf_0x1a`.
pub async fn configure(
    io: &impl Io,
    condition: &Condition,
    crystal_cap: u8,
) -> Result<(Report, [u32; 2], u32), Error> {
    mac_config(io)?;
    let (cck_high_power, by_rate) = bb_config(io, condition, crystal_cap).await?;
    rf_config(io, condition).await?;
    let mut chnlval = [
        get_rf(io, Path::A, RF_CHNLBW, RFREG_OFFSET_MASK).await?,
        get_rf(io, Path::B, RF_CHNLBW, RFREG_OFFSET_MASK).await?,
    ];
    let backup_rf_0x1a = get_rf(io, Path::A, RF_RX_G1, RFREG_OFFSET_MASK).await?;
    chnlval[0] = (chnlval[0] & 0xffff_f3ff) | (1 << 10) | (1 << 11);
    set_rf(io, Path::A, RF_CHNLBW, RFREG_OFFSET_MASK, chnlval[0]).await?;
    set_rf(io, Path::B, RF_CHNLBW, RFREG_OFFSET_MASK, chnlval[0]).await?;
    set_bb(io, RFPGA0_RFMOD, BCCKEN, 0x1)?;
    set_bb(io, RFPGA0_RFMOD, BOFDMEN, 0x1)?;
    set_rf(io, Path::A, 0xb1, RFREG_OFFSET_MASK, 0x54418).await?;
    Ok((
        Report {
            crystal_cap,
            cck_high_power,
            by_rate,
        },
        chnlval,
        backup_rf_0x1a,
    ))
}
