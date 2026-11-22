// SPDX-License-Identifier: GPL-2.0-or-later
//! Transport-agnostic RTL8822B ("B22") PHY table programming
//! (`rtw8822b_phy_set_param` through `rtw_phy_load_tables`), generic over
//! [`RegIo`]. The builtin driver and the loadable `.ko` apply the identical
//! verbatim `rtw8822b_table.c` rows, the crystal cap, the `REG_RXPSEL` reset
//! release and the `radio::b22::finish_set_param` tail.
//!
//! The factory-derived table-selection inputs arrive as [`B22PhyParams`] (the
//! consuming crate validates the efuse and keeps the richer `Info`); MAC TX/RX
//! and TXPAUSE stay closed.
use crate::radio::b22::{self, B22Params, Init};
use crate::{ChipError as Error, RegIo as Io};
mod tables;
pub use tables::select;

const REG_SYS_FUNC_EN: u16 = 0x0002;
const BIT_FEN_BB: u8 = 0x03; // BIT_FEN_BB_GLB_RST | BIT_FEN_BB_RSTB
const REG_RF_CTRL: u16 = 0x001f;
const BIT_RF_ALL: u8 = 0x07; // BIT_RF_EN | BIT_RF_RSTB | BIT_RF_SDM_RSTB
const REG_WLRF1: u16 = 0x00ec;
const BIT_WLRF1_BBRF_EN: u32 = 7 << 24;
const REG_RXPSEL: u16 = 0x0808;
const BIT_RX_PSEL_RST: u32 = 3 << 28;

/// The factory-selected B22 PHY profile: `cut`/`rfe` pick the
/// `rtw8822b_table.c` rows (via [`select`]) and `crystal` is the 6-bit cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct B22PhyParams {
    pub cut: u8,
    pub rfe: u8,
    pub crystal: u8,
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
/// One table through its Linux `do_cfg`: 0 `rtw_phy_cfg_mac`, 1
/// `rtw_phy_cfg_bb`, 2 `rtw_phy_cfg_agc`, 3/4 `rtw_phy_cfg_rf` path A/B.
async fn apply_table(io: &mut impl Io, cut: u8, rfe: u8, kind: usize) -> Result<(), Error> {
    let rows = select(cut, rfe, kind).ok_or(Error::Unsupported)?;
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
                    b22::rf_write(io, (kind - 3) as u8, address, data).await?;
                    io.delay_us(1).await;
                }
            },
            _ => return Err(Error::Unsupported),
        }
    }
    Ok(())
}
/// `rtw8822b_phy_set_param`: power the BB/RF domain, load the five tables,
/// program the crystal cap, release RXPSEL and run `finish_set_param`
/// (TRX mode, PHY init, RFE, power-tracking, beamforming). Returns the derived
/// IGI / default OFDM swing [`Init`].
pub async fn prepare(io: &mut impl Io, params: B22PhyParams) -> Result<Init, Error> {
    // power on BB/RF domain
    update8(io, REG_SYS_FUNC_EN, BIT_FEN_BB).await?;
    update8(io, REG_RF_CTRL, BIT_RF_ALL).await?;
    update(io, REG_WLRF1, 0, BIT_WLRF1_BBRF_EN).await?;
    // pre init before header files config
    update(io, REG_RXPSEL, BIT_RX_PSEL_RST, 0).await?;
    // rtw_phy_load_tables: mac, bb, agc (no rfk_init_tbl on 8822B), RF A, B.
    for kind in 0..5 {
        apply_table(io, params.cut, params.rfe, kind).await?;
    }
    let crystal = u32::from(params.crystal);
    update(io, 0x24, 0x7e00_0000, crystal << 25).await?;
    update(io, 0x28, 0x7e, crystal << 1).await?;
    // post init after header files config
    update(io, REG_RXPSEL, 0, BIT_RX_PSEL_RST).await?;
    b22::finish_set_param(
        io,
        B22Params {
            cut: params.cut,
            rfe: params.rfe,
        },
    )
    .await
}
