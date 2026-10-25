// SPDX-License-Identifier: GPL-2.0-or-later
//! Factory-selected inactive RTL8822CE PHY tables. Calibration/channel/power
//! and MAC packet activation remain separately owned continuations.
use super::{
    efuse::Factory,
    firmware_transport::{Error, Io},
    hardware::Features,
};
#[path = "phy/tables.rs"]
mod tables;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub cut: u8,
    pub rfe: u8,
    pub paths: u8,
    pub crystal: u8,
}
impl Info {
    pub(super) fn from_factory(
        factory: &Factory,
        cut: u8,
        hardware: Features,
    ) -> Result<Self, Error> {
        if cut > 6
            || factory.rfe() > 6
            || factory.crystal() == 255
            || factory.board_option() == 255
            || factory.thermal().contains(&255)
        {
            return Err(Error::Unsupported);
        }
        // This initial native profile retains both physical paths. Linux's
        // one-antenna narrowing also changes its table/physical-path loop;
        // that separate geometry is not inferred from2-path tests.
        let paths = match hardware.antennas {
            0 | 2 => 2,
            _ => return Err(Error::Unsupported),
        };
        Ok(Self {
            cut,
            rfe: factory.rfe(),
            paths,
            crystal: factory.crystal() & 127,
        })
    }
}
pub(super) fn bind_tables(hash: &mut narf_crypto::sha256::Sha256, info: Info) -> Result<(), Error> {
    for kind in 0..5 {
        let rows = tables::select(info.cut, info.rfe, kind).ok_or(Error::Unsupported)?;
        hash.update(&[kind as u8]);
        hash.update(&(rows.len() as u32).to_le_bytes());
        for (address, data) in rows {
            hash.update(&address.to_le_bytes());
            hash.update(&data.to_le_bytes());
        }
    }
    Ok(())
}
fn update(io: &mut impl Io, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = io.read32(reg)?;
    if value == u32::MAX {
        return Err(Error::Gone);
    }
    io.write32(reg, value & !clear | set)
}
fn update8(io: &mut impl Io, reg: u16, set: u8) -> Result<(), Error> {
    let value = io.read8(reg)?;
    if value == 255 {
        return Err(Error::Gone);
    }
    io.write8(reg, value | set)
}
async fn rf_write(io: &mut impl Io, path: u8, address: u16, data: u32) -> Result<(), Error> {
    if path > 1 || address > 255 || data & !0xfffff != 0 {
        return Err(Error::Unsupported);
    }
    // Linux rtw_phy_write_rf_reg_mix uses SIPI for RF0 and direct read/modify
    // for all other registers. Preserve unrelated direct-register high bits.
    if address == 0 {
        io.write32(if path == 0 { 0x1808 } else { 0x4108 }, data & 0xfffff)?;
        io.delay_us(13).await;
    } else {
        let reg = (if path == 0 { 0x3c00 } else { 0x4c00 }) + address * 4;
        update(io, reg, 0xfffff, data)?;
        io.delay_us(1).await;
    }
    Ok(())
}
pub(super) async fn apply_table(io: &mut impl Io, info: Info, kind: usize) -> Result<(), Error> {
    if info.paths != 2 {
        return Err(Error::Unsupported);
    }
    let rows = tables::select(info.cut, info.rfe, kind).ok_or(Error::Unsupported)?;
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
                    io.write32(address, data)?;
                } else {
                    io.delay_us(delay).await;
                }
            }
            1 => io.write32(address, data)?,
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
fn header(io: &mut impl Io, before: bool) -> Result<(), Error> {
    for reg in [0x180c, 0x410c] {
        update(io, reg, 0, 3)?;
        update(io, reg, 0, 1 << 28)?;
    }
    update(
        io,
        0x1c3c,
        if before { 3 } else { 0 },
        if before { 0 } else { 3 },
    )
}
pub(super) async fn prepare(io: &mut impl Io, info: Info) -> Result<Info, Error> {
    update8(io, 2, 3)?;
    update8(io, 0x1f, 7)?;
    update(io, 0xec, 0, 7 << 24)?;
    update(io, 0xa70, 0x3ff, 0x3ff)?;
    header(io, true)?;
    apply_table(io, info, 0).await?;
    apply_table(io, info, 1).await?;
    // Linux rtw_load_rfk_table enables these exact RFK-init domains before
    // the source calibration program. This loads its instructions only;
    // it does not claim DACK/IQK success or open the station.
    update(io, 0x1e24, 0, 1 << 17)?;
    update(io, 0x1cd0, 0, 1 << 28)?;
    update(io, 0x1cd0, 0, 1 << 29)?;
    update(io, 0x1cd0, 0, 1 << 30)?;
    update(io, 0x1cd0, 1 << 31, 0)?;
    apply_table(io, info, 2).await?;
    apply_table(io, info, 3).await?;
    apply_table(io, info, 4).await?;
    let crystal = u32::from(info.crystal);
    update(io, 0x1040, 0xfffc00, (crystal | crystal << 7) << 10)?;
    header(io, false)?;
    Ok(info)
}
