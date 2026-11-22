// SPDX-License-Identifier: GPL-2.0-or-later
//! Factory-selected inactive RTL8822BE ("B22") PHY tables. The table byte
//! stream lives in `narf-drivers-wireless-rtl-chip` (`phy_b22`, generic over
//! `RegIo`), shared by the builtin driver and the loadable `.ko`; this shim
//! derives the factory [`Info`], bridges the native `Io`, and keeps the SIPI
//! RF write the native radio path uses. Channel programming and calibration
//! are separate continuations; MAC TX/RX and TXPAUSE remain closed.
use super::chip_bridge::bridge;
use super::{
    efuse8822b::Factory8822b,
    firmware_transport::{Error, Io},
    hardware::Features,
};
use narf_drivers_wireless_rtl_chip::phy_b22::{self as chip_phy_b22, B22PhyParams};

/// `rtw8822b_hw_spec.rf_sipi_addr`.
const RF_SIPI: [u16; 2] = [0x0c90, 0x0e90];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub cut: u8,
    pub rfe: u8,
    pub crystal: u8,
    /// `rtw_phy_init` IGI history and `rtw8822b_pwrtrack_init` default OFDM
    /// swing index, captured by the `phy_set_param` tail (0 before it).
    pub igi: u8,
    pub default_ofdm_index: u8,
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
            igi: 0,
            default_ofdm_index: 0,
        })
    }
}
/// The exact preselected rows the table programming applies for `info`.
pub(super) fn rows(info: Info, kind: usize) -> Option<&'static [(u16, u32)]> {
    chip_phy_b22::select(info.cut, info.rfe, kind)
}
#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn tables_for_test(cut: u8, rfe: u8, kind: usize) -> Option<&'static [(u16, u32)]> {
    chip_phy_b22::select(cut, rfe, kind)
}
/// `phy.c::rtw_phy_write_rf_reg_sipi` with the full `RFREG_MASK`; kept native
/// for the `radio8822b` channel/calibration path's SIPI writes.
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
/// `rtw8822b_phy_set_param` (`phy_b22::prepare`), returning the derived IGI /
/// default OFDM swing captured into `info`.
pub(super) async fn prepare(io: &mut impl Io, mut info: Info) -> Result<Info, Error> {
    let params = B22PhyParams {
        cut: info.cut,
        rfe: info.rfe,
        crystal: info.crystal,
    };
    let mut b = bridge(io);
    let init = chip_phy_b22::prepare(&mut b, params)
        .await
        .map_err(|e| b.err(e))?;
    info.igi = init.igi;
    info.default_ofdm_index = init.default_ofdm_index;
    Ok(info)
}
