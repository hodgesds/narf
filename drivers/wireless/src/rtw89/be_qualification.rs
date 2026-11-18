// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! NARF-local N22P-v1 measured permission for the closed partial BE program.
//! The96-byte envelope uses calibration_policy's exact channel1/20MHz and
//! current regulatory ceiling checks. It cannot be used as N22A-v1 or as a
//! full-radio/ordinary packet/response grant. Its identity explicitly covers
//! calibration tones/transitions, actual inputs and the MAC1-off omission.
use super::{
    be_mailbox::Receipt,
    calibration_policy::{Board, Calibration, Error},
    efuse_be::checked::Snapshot,
    mac::ChipId,
    mac_pre_init_8922a::HalChipVer,
    power,
    radio_assets::Assets,
    rfk::be_features::Features,
};

pub(super) struct Facts<'a> {
    pub(super) device: narf_bus::DeviceId,
    pub(super) factory: &'a Snapshot,
    pub(super) chip: HalChipVer,
    pub(super) assets: &'a Assets,
    pub(super) features: Features,
    pub(super) phycap: &'a Receipt,
}
/// pci.c::check_pci_ssid_quirks and rtw8922ae.c's sole8922A row. DELL
/// is assigned custid metadata after this match, not a DMI prerequisite.
pub(super) const fn thermal_threshold(device: narf_bus::DeviceId) -> u8 {
    if device.vendor == 0x10ec
        && device.device == 0x8922
        && device.subsystem_vendor == 0x10ec
        && device.subsystem_id == 0xa891
    {
        0xb4 // rtw8922a_chip_info.thermal_th[1], THERMAL_PROT_120C
    } else {
        0
    }
}
const SCOPE: &[u8] = b"NARF RTL8922A N22P partial cold SCC ch1/20MHz v1\0MAC0 AFE/FEN on+ISO off; MAC1 AFE/FEN off+ISO on+BB1 held; CMAC0 TXEN/RXEN closed; CH12 only; no WPDMA/ordinary IRQ/net/response grant\0actual BB/gain/RF-v2 A+B+RF-page upload; DM partial omits only MAC1 UL_PWR_RSSI_TARGET_LMT+PWR_TH; BE NCTL; rfk_init software-zero state; OFDM/CCK references zero; factory bias trims; actual GET_FEATURE paths; SCC path/reset bracket; source channel MAC/BB/gain/RF/context+power WW/no-DAG/no-SAR/no-DA-limit; init-late PRE/MCC DACK RXDCK calibration tones/transitions allowed only within measured peak+antenna/current host ceiling; channel-RFK coex hooks refuse; no BE BTC producer; no full radio/station/AP/EHT admission\0thermal source debug-disabled: real PCI thermal threshold or typed disabled fallback; factory thermal is never a live sample\0";

/// Length delimiters and names make this conservative source snapshot
/// canonical: even a source-comment change requires a new measurement.
/// Selected firmware bytes/tables and every dynamic input are bound below.
pub(super) fn identity(facts: &Facts<'_>) -> Result<[u8; 32], Error> {
    let factory = &facts.factory.factory;
    if facts.device.vendor != 0x10ec
        || !matches!(facts.device.device, 0x8922 | 0x892b)
        || facts.chip.cv > 14
        || factory.cv.is_some_and(|cv| cv != facts.chip.cv)
        || factory.rfe_type == 255
        || !super::efuse::mac_is_valid(factory.mac)
        || facts.assets.chip() != ChipId::Rtl8922A
        || !facts.assets.matches_be_identity(facts.chip)
        || facts.assets.firmware_version() != facts.features.version()
        || !facts.features.supports_device(facts.device.device)
        || !facts
            .phycap
            .matches_source(facts.features, facts.device.device)
        || facts.factory.rf.len() != 0x240
        || facts.factory.hci.len() != 0x4800
    {
        return Err(Error::Identity);
    }
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(SCOPE);
    for value in [
        facts.device.vendor,
        facts.device.device,
        facts.device.subsystem_vendor,
        facts.device.subsystem_id,
        facts.chip.aid,
    ] {
        hash.update(&value.to_le_bytes());
    }
    hash.update(&[
        facts.chip.cv,
        facts.chip.acv,
        facts.chip.cid.raw(),
        factory.rfe_type,
        factory.xtal_cap,
        thermal_threshold(facts.device),
    ]);
    hash.update(&factory.mac);
    for bytes in [
        facts.factory.rf.as_slice(),
        facts.factory.hci.as_slice(),
        &factory.phycap,
    ] {
        hash.update(&(bytes.len() as u32).to_le_bytes());
        hash.update(bytes);
    }
    facts
        .assets
        .bind(&mut hash, factory.rfe_type, facts.chip.cv)
        .map_err(|_| Error::Identity)?;
    facts.phycap.bind(&mut hash);
    macro_rules! source {
        ($($name:literal),+ $(,)?) => {$({
            let name = $name.as_bytes();
            let bytes = include_bytes!($name);
            hash.update(&(name.len() as u32).to_le_bytes());
            hash.update(name);
            hash.update(&(bytes.len() as u32).to_le_bytes());
            hash.update(bytes);
        })+};
    }
    source!(
        "be_qualification.rs",
        "native_radio_be.rs",
        "native_radio_be_io.rs",
        "radio_init.rs",
        "radio_be.rs",
        "radio_gain_be.rs",
        "radio_gain_be_registers.rs",
        "rf_access_be.rs",
        "phy_operating_be.rs",
        "phy_operating_be_program.rs",
        "be_path.rs",
        "channel_be.rs",
        "radio_power_be.rs",
        "factory_be.rs",
        "rfk/be_features.rs",
        "rfk/be_notify.rs",
        "rfk/be_late.rs",
        "rfk/be_rfk.rs",
        "rfk/be_tssi.rs",
        "rfk/c_tssi.rs",
        "be_control.rs",
        "be_scheduler.rs",
        "be_mailbox.rs",
        "checked_fwdl_8922a.rs",
        "prepared_checked_8922a.rs",
        "radio_power_c.rs",
        "radio_table.rs",
        "efuse_be.rs",
        "txpower_8922a.rs",
        "operating_channel_c.rs",
        "fwcmd_8922a.rs",
        "radio_assets.rs",
        "bootstrap_8922a.rs",
        "cold_8922a.rs",
        "calibration_policy.rs"
    );
    Ok(hash.finalize())
}
/// This type deliberately exposes no Calibration, Board or full readiness
/// receipt. Only the original retained partial native owner consumes it.
pub(super) struct Partial {
    calibration: Calibration,
}
/// Internal source scopes remain distinct: N22P never gains N22W effects.
#[derive(Clone, Copy)]
pub(super) enum Grant<'a> {
    Partial(&'a Partial),
    Wlan(&'a super::be_wlan_qualification::WlanOnly),
    Packet(
        &'a super::be_packet_qualification::Ordinary,
        &'a super::native_radio_be::Radio,
    ),
}
impl Grant<'_> {
    pub(super) fn packet_response(self) -> Option<super::be_packet_qualification::Response> {
        match self {
            Self::Packet(grant, _) => Some(grant.response()),
            _ => None,
        }
    }
    pub(super) fn wlan(self) -> bool {
        matches!(self, Self::Wlan(_))
    }
    pub(super) fn with_current<T, E: From<power::Error>>(
        self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        match self {
            Self::Partial(grant) => grant.with_current(operation),
            Self::Wlan(grant) => grant.with_current(operation),
            Self::Packet(grant, radio) => {
                radio.with_packet_preflight(|| grant.with_current(operation))
            }
        }
    }
}
impl Partial {
    pub(super) fn load(facts: &Facts<'_>) -> Result<Self, Error> {
        let board = Board::new_partial_be(facts)?;
        let calibration = Calibration::load_partial_be(board)?;
        calibration.current()?;
        Ok(Self { calibration })
    }
    pub(super) fn current(&self) -> Result<(), Error> {
        self.calibration.current()
    }
    pub(super) fn with_current<T, E: From<power::Error>>(
        &self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.calibration.with_current_result(operation)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "be_qualification_tests.rs"]
pub(super) mod tests;
