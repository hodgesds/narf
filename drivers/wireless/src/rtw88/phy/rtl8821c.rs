// SPDX-License-Identifier: GPL-2.0-or-later
//! Inactive C21 table prefix from rtw8821c_phy_set_param. No calibration.
use crate::rtw88::{
    efuse::Factory8821c,
    firmware_transport::{Error, Io},
    hardware::Features,
};
#[path = "rtl8821c_tables.rs"]
mod tables;

/// Host interface of `phy.c::rtw_phy_setup_phy_cond` (`cond.intf`:
/// `INTF_PCIE` BIT(0), `INTF_USB` BIT(1); SDIO is not supported here).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Interface {
    #[default]
    Pcie,
    Usb,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Info {
    pub cut: u8,
    pub package: u8,
    pub rfe: u8,
    pub crystal: u8,
    pub channel_filters: [u32; 3],
    pub interface: Interface,
}
/// `phy.c::rtw_parse_tbl_phy_cond` row selection for `info`.
///
/// The frozen selections in `rtl8821c_tables.rs` were taken with
/// `cond.intf = INTF_PCIE`. Re-deriving them from Linux 7.3-rc4
/// `rtw8821c_table.c` under `check_positive` with `cond.intf = INTF_USB`:
/// the only interface-qualified branch headers in `rtw8821c_mac`, `_bb`,
/// `_agc`, `_agc_btg_type2` and `_rf_a` are `INTF_SDIO` (in `_bb` and
/// `_rf_a`) or interface-agnostic (`intf` 0), so for every admitted cut
/// (0..=6), package (0, 1) and RFE (0, 2, 4, 6) the USB parse emits exactly
/// the PCIe rows (138/1669/386/128/586 rows). USB therefore selects the
/// same frozen tables; SDIO would not and stays refused.
pub(super) fn rows(info: Info, kind: usize) -> Option<&'static [(u16, u32)]> {
    match info.interface {
        Interface::Pcie | Interface::Usb => tables::select(info.cut, info.package, info.rfe, kind),
    }
}
impl Info {
    pub(super) fn from_factory(
        factory: &Factory8821c,
        cut: u8,
        hardware: Features,
    ) -> Result<Self, Error> {
        if cut > 6
            || !matches!(factory.rfe(), 0 | 2 | 4 | 6)
            || factory.crystal() == 255
            || !matches!(hardware.antennas, 0 | 1)
            || !matches!(hardware.streams, 0 | 1)
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            cut,
            package: factory.package(),
            rfe: factory.rfe(),
            crystal: factory.crystal() & 0x3f,
            channel_filters: [0; 3],
            interface: Interface::Pcie,
        })
    }
    /// The same board facts behind another host interface.
    pub(super) fn on(self, interface: Interface) -> Self {
        Self { interface, ..self }
    }
}
pub(super) fn bind_tables(hash: &mut narf_crypto::sha256::Sha256, info: Info) -> Result<(), Error> {
    // PCIe hashes stay byte-identical; USB binds its interface first.
    if info.interface == Interface::Usb {
        hash.update(b"intf-usb");
    }
    for kind in 0..5 {
        let rows = rows(info, kind).ok_or(Error::Unsupported)?;
        hash.update(&[kind as u8]);
        hash.update(&(rows.len() as u32).to_le_bytes());
        for (address, value) in rows {
            hash.update(&address.to_le_bytes());
            hash.update(&value.to_le_bytes());
        }
    }
    Ok(())
}
async fn update(io: &mut impl Io, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = io.read32(reg).await?;
    if value == u32::MAX {
        return Err(Error::Gone);
    }
    io.write32(reg, value & !clear | set).await
}
pub(super) async fn apply_table(io: &mut impl Io, info: Info, kind: usize) -> Result<(), Error> {
    let rows = rows(info, kind).ok_or(Error::Unsupported)?;
    for &(address, data) in rows {
        match kind {
            0 => io.write8(address, data as u8).await?,
            1 => {
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
            2 | 3 => io.write32(address, data).await?,
            4 => match address {
                0xffe => io.delay_us(50000).await,
                0xfe => io.delay_us(100).await,
                _ => {
                    if address > 255 || data > 0xfffff || address == 0 && data != 0x10000 {
                        return Err(Error::Unsupported);
                    }
                    // C21 uses SIPI for every RF register, with its own RF-A
                    // address. Full-mask table writes require no RF readback.
                    io.write32(0xc90, u32::from(address) << 20 | data).await?;
                    io.delay_us(13).await;
                    io.delay_us(1).await;
                }
            },
            _ => return Err(Error::Unsupported),
        }
    }
    Ok(())
}
pub(super) async fn prepare(io: &mut impl Io, mut info: Info) -> Result<Info, Error> {
    let val = io.read8(2).await?;
    if val == 255 {
        return Err(Error::Gone);
    }
    let val = val | 1 << 6;
    io.write8(2, val).await?;
    io.write8(2, val | 3).await?;
    io.write8(2, val & !3).await?;
    io.write8(2, val | 3).await?;
    io.write8(0x1f, 7).await?;
    io.delay_us(10).await;
    io.write8(0xef, 7).await?;
    io.delay_us(10).await;
    update(io, 0x808, 3 << 28, 0).await?;
    // MAC, BB, AGC, optional BTG AGC, RF-A; C21 has no rfk_init_tbl.
    // The source BB table includes its own instruction RAM contents. No
    // emitting calibration routine or MAC packet activation runs here.
    for kind in 0..5 {
        apply_table(io, info, kind).await?;
    }
    let crystal = u32::from(info.crystal);
    update(io, 0x24, 0x7e000000, crystal << 25).await?;
    update(io, 0x28, 0x7e, crystal << 1).await?;
    update(io, 0xa2c, (1 << 18) | (1 << 22), 0).await?;
    update(io, 0x808, 0, 3 << 28).await?;
    for (slot, reg) in info.channel_filters.iter_mut().zip([0xa24, 0xa28, 0xaac]) {
        *slot = io.read32(reg).await?;
        if *slot == u32::MAX {
            return Err(Error::Gone);
        }
    }
    Ok(info)
}
