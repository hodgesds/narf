// SPDX-License-Identifier: GPL-2.0-or-later
//! Transport-agnostic RTL8822C PHY table programming (`phy.c` and the frozen
//! `rtw8822c_table.c` selections), generic over [`RegIo`]. The builtin driver
//! and the loadable `.ko` apply the identical table byte stream — the inactive
//! projection: it loads the RFK-init instructions only, claiming no DACK/IQK
//! success and opening no station.
//!
//! The factory-derived table-selection inputs arrive as [`PhyParams`] (the
//! consuming crate validates the efuse and keeps the richer `Info`); this
//! module touches registers only.
use crate::{ChipError as Error, RegIo as Io};
mod tables;
pub use tables::select;

/// The factory-selected PHY profile the table programming needs: `cut`/`rfe`
/// pick the `rtw8822c_table.c` rows (via [`select`]), `paths` must be 2 (both
/// RF paths retained) and `crystal` is the 7-bit crystal trim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhyParams {
    pub cut: u8,
    pub rfe: u8,
    pub paths: u8,
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
async fn rf_write(io: &mut impl Io, path: u8, address: u16, data: u32) -> Result<(), Error> {
    if path > 1 || address > 255 || data & !0xfffff != 0 {
        return Err(Error::Unsupported);
    }
    // Linux rtw_phy_write_rf_reg_mix uses SIPI for RF0 and direct read/modify
    // for all other registers. Preserve unrelated direct-register high bits.
    if address == 0 {
        io.write32(if path == 0 { 0x1808 } else { 0x4108 }, data & 0xfffff)
            .await?;
        io.delay_us(13).await;
    } else {
        let reg = (if path == 0 { 0x3c00 } else { 0x4c00 }) + address * 4;
        update(io, reg, 0xfffff, data).await?;
        io.delay_us(1).await;
    }
    Ok(())
}
/// Apply one `rtw8822c_table.c` table `kind` (0=MAC, 1=BB, 2=AGC, 3=RF path B,
/// 4=RF path A) for the selected `params`. Addresses in the 0xf9..=0xfe /
/// 0xffe / 0xfe sentinel ranges are delays, not writes (`rtw_phy_cfg_*`).
pub async fn apply_table(io: &mut impl Io, params: PhyParams, kind: usize) -> Result<(), Error> {
    if params.paths != 2 {
        return Err(Error::Unsupported);
    }
    let rows = select(params.cut, params.rfe, kind).ok_or(Error::Unsupported)?;
    for &(address, data) in rows {
        match kind {
            0 | 2 => {
                let delay = match address {
                    0xfe => 50000,
                    0xfd => 5000,
                    0xfc => 1000,
                    0xfb => 50,
                    0xfa => 5,
                    0xf9 => 1,
                    _ => 0,
                };
                if delay == 0 {
                    io.write32(address, data).await?;
                } else {
                    io.delay_us(delay).await;
                }
            }
            1 => io.write32(address, data).await?,
            3 | 4 => match address {
                0xffe => io.delay_us(50000).await,
                0xfe => io.delay_us(100).await,
                _ => {
                    rf_write(io, if kind == 3 { 1 } else { 0 }, address, data).await?;
                    io.delay_us(1).await;
                }
            },
            _ => return Err(Error::Unsupported),
        }
    }
    Ok(())
}
async fn header(io: &mut impl Io, before: bool) -> Result<(), Error> {
    for reg in [0x180c, 0x410c] {
        update(io, reg, 0, 3).await?;
        update(io, reg, 0, 1 << 28).await?;
    }
    update(
        io,
        0x1c3c,
        if before { 3 } else { 0 },
        if before { 0 } else { 3 },
    )
    .await
}
/// `rtw_phy_setup_phy_cond` + the five table loads + RFK-init domains +
/// crystal trim, for the selected `params`.
pub async fn prepare(io: &mut impl Io, params: PhyParams) -> Result<(), Error> {
    update8(io, 2, 3).await?;
    update8(io, 0x1f, 7).await?;
    update(io, 0xec, 0, 7 << 24).await?;
    update(io, 0xa70, 0x3ff, 0x3ff).await?;
    header(io, true).await?;
    apply_table(io, params, 0).await?;
    apply_table(io, params, 1).await?;
    // Linux rtw_load_rfk_table enables these exact RFK-init domains before
    // the source calibration program. This loads its instructions only;
    // it does not claim DACK/IQK success or open the station.
    update(io, 0x1e24, 0, 1 << 17).await?;
    update(io, 0x1cd0, 0, 1 << 28).await?;
    update(io, 0x1cd0, 0, 1 << 29).await?;
    update(io, 0x1cd0, 0, 1 << 30).await?;
    update(io, 0x1cd0, 1 << 31, 0).await?;
    apply_table(io, params, 2).await?;
    apply_table(io, params, 3).await?;
    apply_table(io, params, 4).await?;
    let crystal = u32::from(params.crystal);
    update(io, 0x1040, 0xfffc00, (crystal | crystal << 7) << 10).await?;
    header(io, false).await?;
    Ok(())
}
