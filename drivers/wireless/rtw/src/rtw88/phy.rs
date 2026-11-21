// SPDX-License-Identifier: GPL-2.0-or-later
//! Factory-selected inactive RTL8822CE PHY tables. The table byte stream lives
//! in `narf-drivers-wireless-rtl-chip` (`phy`, generic over `RegIo`), shared by
//! the builtin driver and the loadable `.ko`; this shim derives the factory
//! [`Info`], bridges the native `Io` to `RegIo`, and keeps the
//! calibration-identity table hash. Calibration/channel/power and MAC packet
//! activation remain separately owned continuations.
use super::chip_bridge::{from_chip, IoReg};
use super::{
    efuse::Factory,
    firmware_transport::{Error, Io},
    hardware::Features,
};
use narf_drivers_wireless_rtl_chip::phy::{self as chip_phy, PhyParams};

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
    fn params(self) -> PhyParams {
        PhyParams {
            cut: self.cut,
            rfe: self.rfe,
            paths: self.paths,
            crystal: self.crystal,
        }
    }
}
pub(super) fn bind_tables(hash: &mut narf_crypto::sha256::Sha256, info: Info) -> Result<(), Error> {
    for kind in 0..5 {
        let rows = chip_phy::select(info.cut, info.rfe, kind).ok_or(Error::Unsupported)?;
        hash.update(&[kind as u8]);
        hash.update(&(rows.len() as u32).to_le_bytes());
        for (address, data) in rows {
            hash.update(&address.to_le_bytes());
            hash.update(&data.to_le_bytes());
        }
    }
    Ok(())
}
pub(super) async fn apply_table(io: &mut impl Io, info: Info, kind: usize) -> Result<(), Error> {
    chip_phy::apply_table(&mut IoReg(io), info.params(), kind)
        .await
        .map_err(from_chip)
}
pub(super) async fn prepare(io: &mut impl Io, info: Info) -> Result<Info, Error> {
    chip_phy::prepare(&mut IoReg(io), info.params())
        .await
        .map_err(from_chip)?;
    Ok(info)
}
