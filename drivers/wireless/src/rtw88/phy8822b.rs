// SPDX-License-Identifier: GPL-2.0-or-later
//! Factory-selected inactive RTL8822BE ("B22") PHY tables.
//!
//! `rtw8822b.c::rtw8822b_phy_set_param` through `rtw_phy_load_tables`, the
//! crystal cap and the post-table `REG_RXPSEL` reset release. Tables are the
//! verbatim `rtw8822b_table.c` rows selected for PCIe by
//! `phy.c::rtw_parse_tbl_phy_cond`. TRX mode, `rtw_phy_init`, RFE/power-track/
//! beamforming init, channel programming and calibration are separate
//! continuations; MAC TX/RX and TXPAUSE remain closed.
use super::{
    efuse8822b::Factory8822b,
    firmware_transport::{Error, Io},
    hardware::Features,
};
#[path = "phy/rtl8822b_tables.rs"]
mod tables;

const REG_SYS_FUNC_EN: u16 = 0x0002;
const BIT_FEN_BB: u8 = 0x03; // BIT_FEN_BB_GLB_RST | BIT_FEN_BB_RSTB
const REG_RF_CTRL: u16 = 0x001f;
const BIT_RF_ALL: u8 = 0x07; // BIT_RF_EN | BIT_RF_RSTB | BIT_RF_SDM_RSTB
const REG_WLRF1: u16 = 0x00ec;
const BIT_WLRF1_BBRF_EN: u32 = 7 << 24;
const REG_RXPSEL: u16 = 0x0808;
const BIT_RX_PSEL_RST: u32 = 3 << 28;
/// `rtw8822b_hw_spec.rf_sipi_addr`.
const RF_SIPI: [u16; 2] = [0x0c90, 0x0e90];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub cut: u8,
    pub rfe: u8,
    pub crystal: u8,
}
impl Info {
    pub(super) fn from_factory(
        factory: &Factory8822b,
        cut: u8,
        hardware: Features,
    ) -> Result<Self, Error> {
        // rtw_get_rfe_def: only rtw8822b_rfe_defs[2], [3], [5] exist. Erased
        // crystal/board fields are not replaced by invented defaults.
        if cut > 15
            || !matches!(factory.rfe(), 2 | 3 | 5)
            || factory.crystal() == 255
            || factory.board_option() == 255
            || !matches!(hardware.antennas, 0 | 2)
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            cut,
            rfe: factory.rfe(),
            crystal: factory.crystal() & 0x3f,
        })
    }
}
#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn tables_for_test(cut: u8, rfe: u8, kind: usize) -> Option<&'static [(u16, u32)]> {
    tables::select(cut, rfe, kind)
}
async fn update(io: &mut impl Io, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = io.read32(reg).await?;
    if value == u32::MAX {
        return Err(Error::Gone);
    }
    io.write32(reg, value & !clear | set).await
}
async fn update8(io: &mut impl Io, reg: u16, set: u8) -> Result<(), Error> {
    let value = io.read8(reg).await?;
    if value == 255 {
        return Err(Error::Gone);
    }
    io.write8(reg, value | set).await
}
/// `phy.c::rtw_phy_write_rf_reg_sipi` with the full `RFREG_MASK`.
pub(super) async fn rf_write(
    io: &mut impl Io,
    path: u8,
    address: u16,
    data: u32,
) -> Result<(), Error> {
    if path > 1 || data & !0xfffff != 0 {
        return Err(Error::Unsupported);
    }
    let word = ((u32::from(address & 0xff) << 20) | data) & 0x0fff_ffff;
    io.write32(RF_SIPI[usize::from(path)], word).await?;
    io.delay_us(13).await;
    Ok(())
}
/// One table through its Linux `do_cfg`: 0 `rtw_phy_cfg_mac`, 1
/// `rtw_phy_cfg_bb`, 2 `rtw_phy_cfg_agc`, 3/4 `rtw_phy_cfg_rf` path A/B.
pub(super) async fn apply_table(io: &mut impl Io, info: Info, kind: usize) -> Result<(), Error> {
    let rows = tables::select(info.cut, info.rfe, kind).ok_or(Error::Unsupported)?;
    for &(address, data) in rows {
        match kind {
            0 => io.write8(address, data as u8).await?,
            1 => match address {
                0xfe => io.delay_us(50000).await,
                0xfd => io.delay_us(5000).await,
                0xfc => io.delay_us(1000).await,
                0xfb => io.delay_us(50).await,
                0xfa => io.delay_us(5).await,
                0xf9 => io.delay_us(1).await,
                _ => io.write32(address, data).await?,
            },
            2 => io.write32(address, data).await?,
            3 | 4 => match address {
                0xffe => io.delay_us(50000).await,
                0xfe => io.delay_us(100).await,
                _ => {
                    rf_write(io, (kind - 3) as u8, address, data).await?;
                    io.delay_us(1).await;
                }
            },
            _ => return Err(Error::Unsupported),
        }
    }
    Ok(())
}
pub(super) async fn prepare(io: &mut impl Io, info: Info) -> Result<Info, Error> {
    // power on BB/RF domain
    update8(io, REG_SYS_FUNC_EN, BIT_FEN_BB).await?;
    update8(io, REG_RF_CTRL, BIT_RF_ALL).await?;
    update(io, REG_WLRF1, 0, BIT_WLRF1_BBRF_EN).await?;
    // pre init before header files config
    update(io, REG_RXPSEL, BIT_RX_PSEL_RST, 0).await?;
    // rtw_phy_load_tables: mac, bb, agc (no rfk_init_tbl on 8822B), RF A, B.
    for kind in 0..5 {
        apply_table(io, info, kind).await?;
    }
    let crystal = u32::from(info.crystal);
    update(io, 0x24, 0x7e00_0000, crystal << 25).await?;
    update(io, 0x28, 0x7e, crystal << 1).await?;
    // post init after header files config
    update(io, REG_RXPSEL, 0, BIT_RX_PSEL_RST).await?;
    Ok(info)
}
