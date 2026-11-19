// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Distinct N22W measured closed SCC WLAN-only calibration program. N22P
//! remains MAC1-off/partial. Neither scope grants packet/response admission.
use super::{
    be_qualification::Facts,
    calibration_policy::{Board, Calibration, Error},
    power,
};
const SCOPE: &[u8] = b"NARF RTL8922A N22W closed SCC ch1/20MHz WLAN-only calibration v1\0actual original checked FW/system/TRX/CH12/DMA/scheduler owner; original PCI/factory/CV/ACV/AID/signed selected NORMAL/tables/GET_FEATURE facts; all N22P source stages plus COMPLETE DM with synchronous source MAC1 AFE->isolation->FEN power window, positive common tuples BEFORE C1 access, C1 packet bits closed, exact UL RSSI target/PWR_TH writes/readbacks, FEN->isolation->AFE off/readback; current original PCI restrictive closure on uncertainty, no reset/reclaim receipt\0explicit source BTC_MODE_WL, never BT-disabled or supplied BT-version identity; exact NORMAL-selected BE init/CTRL/slots/TDMA/OFF-policy ABI, RFE/antenna paths, GNT/PLT/RF LUT/scoreboard/force-power-control; real requested DONE_ACK and RP receipts; source switch-band and WLRFK scoreboard/WONLY notifications; PRE/MCC/TXGAPK/IQK/TSSI/DPK/RXDCK channel RFK and complete enabled calibration/arbitration tones/state/transitions measured together; no ordinary HCI/IRQ/packet/station/AP/EHT opening; disabled DAG/SAR profile; exact current host EIRP plus antenna ceiling\0";
pub(super) fn identity(facts: &Facts<'_>) -> Result<[u8; 32], Error> {
    if facts.factory.factory.rfe_type == 0 {
        return Err(Error::Identity);
    }
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(SCOPE);
    hash.update(&super::be_qualification::identity(facts)?);
    super::be_coex::Protocol::from_version(facts.features.version()).ok_or(Error::Identity)?;
    for (name, bytes) in [
        (
            "be-wlan-scope",
            include_bytes!("be_wlan_qualification.rs").as_slice(),
        ),
        ("be-mac1", include_bytes!("be_mac1.rs").as_slice()),
        ("be-coex", include_bytes!("be_coex.rs").as_slice()),
        (
            "be-channel-rfk",
            include_bytes!("rfk/be_channel.rs").as_slice(),
        ),
    ] {
        hash.update(&(name.len() as u32).to_le_bytes());
        hash.update(name.as_bytes());
        hash.update(&(bytes.len() as u32).to_le_bytes());
        hash.update(bytes);
    }
    Ok(hash.finalize())
}
pub(super) struct WlanOnly {
    calibration: Calibration,
}
impl WlanOnly {
    pub(super) fn load(facts: &Facts<'_>) -> Result<Option<Self>, Error> {
        if facts.factory.factory.rfe_type == 0
            || super::be_coex::Protocol::from_version(facts.features.version()).is_none()
        {
            return Ok(None);
        }
        let board = Board::new_wlan_be(facts)?;
        match Calibration::load_wlan_be(board) {
            Ok(calibration) => {
                calibration.current()?;
                Ok(Some(Self { calibration }))
            }
            Err(Error::Firmware(narf_firmware::FirmwareError::NotFound)) => Ok(None),
            Err(error) => Err(error),
        }
    }
    pub(super) fn with_current<T, E: From<power::Error>>(
        &self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.calibration.with_current_result(operation)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "be_wlan_qualification_tests.rs"]
pub(super) mod tests;
