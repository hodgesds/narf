// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE BB/RF register access and the `table.c` configuration walks.
//!
//! Exact Linux `rtl8723com/phy_common.c` + `rtl8723be/{phy,rf}.c` register
//! effects:
//!
//! - `rtl8723_phy_set_bb_reg` / `rtl8723_phy_query_bb_reg` (the shifted
//!   value is not re-masked, as in Linux).
//! - `rtl8723_phy_rf_serial_write` / `rtl8723_phy_rf_serial_read`
//!   (`offset &= 0xff`; read: `0x824` edge low, the path's HSSI2 with the
//!   address and edge, `0x824` edge high, one `udelay(120)`, then the PI/SI
//!   read-back chosen by the path's HSSI1 BIT(8)) and
//!   `rtl8723be_phy_{query,set}_rf_reg` (RMW unless the mask is
//!   `RFREG_OFFSET_MASK`).
//! - `rtl8723be_phy_config_with_headerfile` + `_rtl8723be_check_positive`
//!   ([`Condition`], [`walk`]): the cut, `rtlhal->package_type`, PCIe and
//!   `rtlhal->board_type` (`ODM_BOARD_BT` on BT boards). RTL8723BE never
//!   sets `type_{glna,gpa,alna,apa}`, so `driver2` is zero as in Linux.
//! - `rtl8723be_phy_mac_config` (MAC rows as byte writes, `0x4ca = 0x0b`).
//! - `rtl8723be_phy_bb_config` (BB/RF enable writes, `0x4c[23]`, the
//!   `AFE_XTAL_CTRL+1` write, `_rtl8723be_phy_bb8723b_config_parafile`:
//!   the `0x948` antenna-to-BT write by `single_ant_path`, PHY_REG walk
//!   with `_rtl8723be_config_bb_reg`, AGC walk, `cck_high_power`; then the
//!   crystal cap into `REG_MAC_PHY_CTRL[23:12]`). The PHY_REG_PG
//!   by-rate store is software state (`super::txpower`).
//! - `rtl8723be_phy_rf6052_config` (`num_total_rfpath` 1 for the 1T1R
//!   part) with `_rtl8723be_config_rf_radio_a` rows and the
//!   `RT_CID_819X_HP` `RF 0x52 = 0x7E4BD` row.

use super::adapter::{Adapter, AntPath, Oem};
use super::tables;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const REG_SYS_FUNC_EN: u16 = 0x0002;
pub const REG_RF_CTRL: u16 = 0x001f;
pub const REG_AFE_XTAL_CTRL: u16 = 0x0024;
pub const REG_MAC_PHY_CTRL: u16 = 0x002c;
/// `rtl8723be_phy_mac_config` tail register.
pub const REG_MAX_AGGR_NUM: u16 = 0x04ca;
/// `FEN_PPLL | FEN_PCIEA | FEN_DIO_PCIE | FEN_BB_GLB_RSTN | FEN_BBRSTB`.
pub const SYS_FUNC_EN_BB: u8 = 0x80 | 0x40 | 0x20 | 0x02 | 0x01;
/// `RF_EN | RF_RSTB | RF_SDMRSTB`.
pub const RF_CTRL_ON: u8 = 0x07;
/// `0x948` antenna-switch register (`_rtl8723be_phy_bb8723b_config_parafile`).
pub const REG_S0S1_PATH_SWITCH: u16 = 0x0948;

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
/// `RF_CHNLBW`.
pub const RF_CHNLBW: u32 = 0x18;

/// `RF90_PATH_A` / `RF90_PATH_B`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    A = 0,
    B = 1,
}

/// `rtl8723_phy_init_bb_rf_reg_def` for one path (the registers this
/// driver's RF access and RF6052 configuration use).
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

const fn shift(mask: u32) -> u32 {
    mask.trailing_zeros()
}

/// `rtl8723_phy_query_bb_reg`.
pub fn get_bb(io: &impl Io, reg: u16, mask: u32) -> Result<u32, Error> {
    let value = io.read32(reg)?;
    Ok((value & mask) >> shift(mask))
}

/// `rtl8723_phy_set_bb_reg`.
pub fn set_bb(io: &impl Io, reg: u16, mask: u32, data: u32) -> Result<(), Error> {
    let value = if mask == MASKDWORD {
        data
    } else {
        (io.read32(reg)? & !mask) | (data << shift(mask))
    };
    Ok(io.write32(reg, value)?)
}

/// `rtl8723_phy_rf_serial_read`.
pub async fn rf_serial_read(io: &impl Io, path: Path, offset: u32) -> Result<u32, Error> {
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
    set_bb(
        io,
        RFPGA0_XA_HSSIPARAMETER2,
        MASKDWORD,
        tmplong | BLSSIREADEDGE,
    )?;
    io.delay_us(120).await;
    let pi = get_bb(io, regs.rfhssi_para1, 1 << 8)? != 0;
    let readback = if pi { regs.rf_rbpi } else { regs.rf_rb };
    get_bb(io, readback, BLSSIREADBACKDATA)
}

/// `rtl8723_phy_rf_serial_write`.
pub fn rf_serial_write(io: &impl Io, path: Path, offset: u32, data: u32) -> Result<(), Error> {
    let data_and_addr = (((offset & 0xff) << 20) | (data & 0x000f_ffff)) & 0x0fff_ffff;
    set_bb(io, path.regs().rf3wire_offset, MASKDWORD, data_and_addr)
}

/// `rtl8723be_phy_query_rf_reg`.
pub async fn get_rf(io: &impl Io, path: Path, reg: u32, mask: u32) -> Result<u32, Error> {
    let value = rf_serial_read(io, path, reg).await?;
    Ok((value & mask) >> shift(mask))
}

/// `rtl8723be_phy_set_rf_reg`.
pub async fn set_rf(io: &impl Io, path: Path, reg: u32, mask: u32, data: u32) -> Result<(), Error> {
    let data = if mask == RFREG_OFFSET_MASK {
        data
    } else {
        (rf_serial_read(io, path, reg).await? & !mask) | (data << shift(mask))
    };
    rf_serial_write(io, path, reg, data)
}

/// Selector inputs of `_rtl8723be_check_positive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Condition {
    /// `(rtlhal->version & CHIP_VER_RTL_MASK) >> CHIP_VER_RTL_SHIFT`.
    pub cut: u8,
    /// `rtlhal->package_type` (`_rtl8723be_read_package_type`).
    pub package_type: u8,
    /// `rtlhal->board_type`.
    pub board_type: u8,
}

impl Condition {
    pub const fn from_adapter(adapter: &Adapter) -> Self {
        Self {
            cut: adapter.version.cut(),
            package_type: adapter.package_type,
            board_type: adapter.board_type,
        }
    }

    /// `_rtl8723be_check_positive`.
    pub fn positive(&self, cond1: u32, cond2: u32) -> bool {
        let b = u32::from(self.board_type);
        let board = ((b >> 4) & 1)        // _GLNA
            | ((b >> 3) & 1) << 1         // _GPA
            | ((b >> 7) & 1) << 2         // _ALNA
            | ((b >> 6) & 1) << 3         // _APA
            | ((b >> 2) & 1) << 4; // _BT
        let intf = 1u32; // PCIe: BIT(0)
        let driver1 = u32::from(self.cut) << 24
            | 0x04 << 16
            | u32::from(self.package_type) << 12
            | intf << 8
            | board;
        let driver2 = 0u32;
        if cond1 & 0x0000_f000 != 0 && cond1 & 0x0000_f000 != driver1 & 0x0000_f000 {
            return false;
        }
        if cond1 & 0x0f00_0000 != 0 && cond1 & 0x0f00_0000 != driver1 & 0x0f00_0000 {
            return false;
        }
        let c1 = cond1 & 0x00ff_0fff;
        let d1 = driver1 & 0x00ff_0fff;
        if c1 & d1 != c1 {
            return false;
        }
        if c1 & 0x0f == 0 {
            return true;
        }
        let mut mask = 0u32;
        if c1 & 1 != 0 {
            mask |= 0x0000_00ff;
        }
        if c1 & 2 != 0 {
            mask |= 0x0000_ff00;
        }
        if c1 & 4 != 0 {
            mask |= 0x00ff_0000;
        }
        if c1 & 8 != 0 {
            mask |= 0xff00_0000;
        }
        cond2 & mask == driver2 & mask
    }
}

/// `rtl8723be_phy_config_with_headerfile`: `set` for every selected row in
/// source order; IF / ELSE-IF / ELSE / ENDIF rows (`BIT31`) select blocks,
/// `BIT30` negative rows are ignored. The rows are yielded lazily, so async
/// row actions (delays) run between selections exactly in table order.
pub fn select<'a>(
    table: &'a [[u32; 2]],
    condition: &Condition,
) -> impl Iterator<Item = (u32, u32)> + 'a {
    const COND_ELSE: u32 = 2;
    const COND_ENDIF: u32 = 3;
    let c = *condition;
    let (mut matched, mut skipped) = (true, false);
    table.iter().filter_map(move |&[v1, v2]| {
        if v1 & 0xc000_0000 != 0 {
            if v1 & 0x8000_0000 != 0 {
                match (v1 >> 28) & 3 {
                    COND_ENDIF => {
                        matched = true;
                        skipped = false;
                    }
                    COND_ELSE => matched = !skipped,
                    _ if skipped => matched = false,
                    _ if c.positive(v1, v2) => {
                        matched = true;
                        skipped = true;
                    }
                    _ => {
                        matched = false;
                        skipped = false;
                    }
                }
            }
            None
        } else if matched {
            Some((v1, v2))
        } else {
            None
        }
    })
}

/// `_rtl8723be_config_bb_reg` delay rows (`0xf9..=0xfe`), in microseconds.
pub const fn bb_delay_us(addr: u32) -> Option<u64> {
    match addr {
        0xfe => Some(50_000),
        0xfd => Some(5_000),
        0xfc => Some(1_000),
        0xfb => Some(50),
        0xfa => Some(5),
        0xf9 => Some(1),
        _ => None,
    }
}

/// `rtl8723be_phy_mac_config`.
pub fn mac_config(io: &impl Io, condition: &Condition) -> Result<(), Error> {
    for (addr, data) in select(&tables::MAC, condition) {
        // rtl_write_byte_with_val32.
        io.write8(addr as u16, data as u8)?;
    }
    Ok(io.write8(REG_MAX_AGGR_NUM, 0x0b)?)
}

/// `rtl8723be_phy_bb_config`. Returns `rtlphy->cck_high_power`.
pub async fn bb_config(io: &impl Io, adapter: &Adapter) -> Result<bool, Error> {
    let condition = Condition::from_adapter(adapter);
    let regval = u16::from_le_bytes([io.read8(REG_SYS_FUNC_EN)?, io.read8(REG_SYS_FUNC_EN + 1)?]);
    io.write16(REG_SYS_FUNC_EN, regval | (1 << 13) | 1 | (1 << 1))?;
    io.write8(REG_RF_CTRL, RF_CTRL_ON)?;
    io.write8(REG_SYS_FUNC_EN, SYS_FUNC_EN_BB)?;
    let tmp = io.read32(0x4c)?;
    io.write32(0x4c, tmp | (1 << 23))?;
    io.write8(REG_AFE_XTAL_CTRL + 1, 0x80)?;
    // _rtl8723be_phy_bb8723b_config_parafile: switch ant to BT (PCIe).
    let path_switch = match adapter.single_ant_path {
        AntPath::Main => 0x280,
        AntPath::Aux => 0,
    };
    io.write32(REG_S0S1_PATH_SWITCH, path_switch)?;
    for (addr, data) in select(&tables::PHY_REG, &condition) {
        match bb_delay_us(addr) {
            Some(us) => io.delay_us(us).await,
            None => {
                set_bb(io, addr as u16, MASKDWORD, data)?;
                io.delay_us(1).await;
            }
        }
    }
    for (addr, data) in select(&tables::AGCTAB, &condition) {
        // rtl_set_bbreg_with_dwmask.
        set_bb(io, addr as u16, MASKDWORD, data)?;
    }
    let cck_high_power = get_bb(io, RFPGA0_XA_HSSIPARAMETER2, 0x200)? != 0;
    let cap = u32::from(adapter.crystal_cap & 0x3f);
    set_bb(io, REG_MAC_PHY_CTRL, 0x00ff_f000, cap | (cap << 6))?;
    Ok(cck_high_power)
}

/// `_rtl8723be_config_rf_radio_a` (`maskforphyset` is 0, so the RF
/// register is the row address).
async fn config_rf_radio_a(io: &impl Io, addr: u32, data: u32) -> Result<(), Error> {
    if addr == 0xfe || addr == 0xffe {
        io.delay_us(50_000).await;
    } else {
        set_rf(io, Path::A, addr, RFREG_OFFSET_MASK, data).await?;
        io.delay_us(1).await;
    }
    Ok(())
}

/// `rtl8723be_phy_rf6052_config` for the 1T1R part (`num_total_rfpath` 1,
/// path A only).
pub async fn rf_config(io: &impl Io, adapter: &Adapter) -> Result<(), Error> {
    let condition = Condition::from_adapter(adapter);
    let regs = Path::A.regs();
    let saved = get_bb(io, regs.rfintfs, BRFSI_RFENV)?;
    set_bb(io, regs.rfintfe, BRFSI_RFENV << 16, 0x1)?;
    io.delay_us(1).await;
    set_bb(io, regs.rfintfo, BRFSI_RFENV, 0x1)?;
    io.delay_us(1).await;
    set_bb(io, regs.rfhssi_para2, B3WIREADDREAALENGTH, 0x0)?;
    io.delay_us(1).await;
    set_bb(io, regs.rfhssi_para2, B3WIREDATALENGTH, 0x0)?;
    io.delay_us(1).await;
    for (addr, data) in select(&tables::RADIOA, &condition) {
        config_rf_radio_a(io, addr, data).await?;
    }
    if adapter.oem == Oem::Hp {
        config_rf_radio_a(io, 0x52, 0x7e4bd).await?;
    }
    set_bb(io, regs.rfintfs, BRFSI_RFENV, saved)
}

/// `rtl8723be_hw_init` `rfreg_chnlval` reads after the RF configuration:
/// path A and path B `RF_CHNLBW`, then path A `&= 0xFFF03FF` with
/// BIT(10) | BIT(11) set.
pub async fn read_chnlval(io: &impl Io) -> Result<[u32; 2], Error> {
    let a = get_rf(io, Path::A, RF_CHNLBW, RFREG_OFFSET_MASK).await?;
    let b = get_rf(io, Path::B, RF_CHNLBW, RFREG_OFFSET_MASK).await?;
    Ok([(a & 0x0fff_03ff) | (1 << 10) | (1 << 11), b])
}
