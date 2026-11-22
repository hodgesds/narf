// SPDX-License-Identifier: GPL-2.0-or-later
//! One-shot fresh RTL8822C ADC/DAC DC calibration. The register sequence lives
//! in `narf-drivers-wireless-rtl-chip` (`radio::dack`, generic over `RegIo`),
//! shared by the builtin driver and the loadable `.ko`; this shim bridges the
//! native `Io` to `RegIo` and re-exports the result. No cached vector
//! restore/recovery is claimed: failed sampling/writes/convergence are terminal.
use super::chip_bridge::bridge;
use super::firmware_transport::{Error, Io};

pub(super) use narf_drivers_wireless_rtl_chip::radio::dack::Dack as Info;

pub(super) async fn calibrate(io: &mut impl Io) -> Result<Info, Error> {
    let mut b = bridge(io);
    let r = narf_drivers_wireless_rtl_chip::radio::dack::calibrate(&mut b).await;
    r.map_err(|e| b.err(e))
}
