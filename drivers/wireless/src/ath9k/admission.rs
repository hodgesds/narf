// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9287 (`0x002d`/`0x002e`) signed board admission record `N87A` v1, the
//! AR9280 (`0x0029`/`0x002a`) dual-band record `N80A` v1 and the AR5008-PHY
//! three-chain records `N54A` v1 (AR5416 `0x0023` / AR5418 `0x0024`) and
//! `N60A` v1 (AR9160 `0x0027`), and the AR9300 (`0x0030`) record `N93A`
//! v1.
//!
//! The AR9287 software path (map decode, INI/board values, open-loop
//! transmit power, two-chain calibration, async-FIFO MAC clock, descriptor
//! chain selection) mirrors Linux, but no AR9287 board has been measured in
//! this tree. A device therefore stays unadmitted unless a signed record,
//! issued for this exact function, factory map and preparation, supplies the
//! measured radiated envelope (antenna gain and conducted ceiling). This
//! module defines that format only: no record or board value is supplied or
//! inferred, and an unprovisioned device is never calibrated or opened.
//! The AR9280 record has the same layout with magic `N80A`; its channel
//! byte is the IEEE channel number (2.4 GHz 1..13 or 5 GHz 36..165, the two
//! sets are disjoint) and it binds the closed-loop def plan of that channel.
//! The AR5416/AR5418 (`N54A`) and AR9160 (`N60A`) records keep that layout
//! and channel byte; their chain-mask bytes are the effective
//! (`fixup_chainmask`, CB71) masks up to 0x7 and their identity binds the
//! AR5008 preparation, the radio revision and the three-chain closed-loop
//! def plan.
//! The AR9300 (`N93A`) record keeps the layout; its channel byte is the
//! IEEE channel (2.4 GHz 1..14 or 5 GHz 36..165), its chain-mask bytes the
//! effective masks up to 0x7, and its identity binds the restored
//! `ar9300_eeprom`, the AR9003 preparation and the AR9300 transmit-power
//! plan of that channel. The AR9580 (`0x0033`) record `N95A` v1 is the
//! same format under its own magic, label and file name
//! (`ath9k/ar9580-admit-v1-ch<N>-<mac>.bin`); its identity binds the
//! `ar9580_1p0` INI preparation.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{
    chips::{Chip, Revision, MAP_9287},
    identity::{BringUpError, Identity},
    phy::{
        ar9280,
        ar9287::{power, Prepared},
    },
};
#[cfg(feature = "kernel-test")]
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;

/// Record length; bytes 64.. are reserved zero.
const LENGTH: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub device: u16,
    pub frequency_mhz: u16,
    pub filename: String,
}

/// Pre-calibration facts a record binds: PCI function, silicon revision,
/// factory map, preparation and the factory open-loop power plan at the
/// 40 half-dB maximum.
#[derive(Clone, Debug)]
pub(super) struct Facts {
    request: Request,
    /// `max_t(u8, antennaGainCh[0], antennaGainCh[1])`.
    factory_antenna: u8,
    rx_chainmask: u8,
    tx_chainmask: u8,
    /// Record magic (`N87A` / `N80A`) and the record's channel byte.
    magic: [u8; 4],
    channel: u8,
}
impl Facts {
    pub(super) fn new(
        id: &narf_bus::DeviceId,
        revision: &Revision,
        identity: &Identity,
        prepared: &Prepared,
        image: &[u8],
        frequency: u16,
    ) -> Result<Self, BringUpError> {
        if id.vendor != 0x168c
            || !matches!(id.device, 0x002d | 0x002e)
            || Chip::for_device(id.device) != Some(Chip::Ar9287)
            || revision.chip != Chip::Ar9287
            || revision.mac_rev < 1
            || image.len() != MAP_9287.bytes()
            || prepared.geometry.is_wide()
            || !(2412..=2472).contains(&frequency)
            || (frequency - 2412) % 5 != 0
        {
            return Err(BringUpError::BadIdentity);
        }
        let plan = power::plan(image, frequency, 40)?;
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(b"NARF AR9287 N87A two-chain open-loop legacy20 board admission v1");
        h.update(b"eeprom_9287 map at word 128; ar9002 AR9287 1.1+ INI modes/rxgain/txgain/common column 4; set_board_values; open-loop set_txpower; non-AR9285 init_cal AGC/NF/IQ; async FIFO on 1.3+; ChainSel = txchainmask");
        for v in [
            id.vendor,
            id.device,
            id.subsystem_vendor,
            id.subsystem_id,
            identity.eeprom_version,
            prepared.ini_writes,
            frequency,
        ] {
            h.update(&v.to_le_bytes());
        }
        h.update(&revision.mac_version.to_le_bytes());
        h.update(&[
            revision.mac_rev,
            identity.rx_chainmask,
            identity.tx_chainmask,
        ]);
        h.update(&identity.mac);
        h.update(image);
        for (register, value) in plan.registers {
            h.update(&register.to_le_bytes());
            h.update(&value.to_le_bytes());
        }
        h.update(&[
            plan.olpc[0].unwrap_or(0),
            plan.olpc[1].unwrap_or(0),
            plan.init_pdadc,
        ]);
        let mac = identity.mac;
        Ok(Self {
            request: Request {
                identity: h.finalize(),
                mac,
                device: id.device,
                frequency_mhz: frequency,
                filename: format!(
                    "ath9k/ar9287-admit-v1-ch{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                    (frequency - 2407) / 5,
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5]
                ),
            },
            factory_antenna: image[96 + 12].max(image[96 + 13]),
            rx_chainmask: identity.rx_chainmask,
            tx_chainmask: identity.tx_chainmask,
            magic: *b"N87A",
            channel: ((frequency - 2407) / 5) as u8,
        })
    }
    /// AR9280 facts for one 20 MHz channel in either band: the PCI
    /// function, revision, def map, the `phy::ar9280::prepare` result for
    /// `frequency` and the closed-loop def plan at the 40 half-dB maximum
    /// (`overlap` is the live `AR_PHY_TPCRG5` overlap Linux reads below
    /// minor 2, else ignored).
    pub(super) fn new_ar9280(
        id: &narf_bus::DeviceId,
        revision: &Revision,
        identity: &Identity,
        prepared: &ar9280::Prepared,
        image: &[u8],
        frequency: u16,
        overlap: u8,
    ) -> Result<Self, BringUpError> {
        let channel = if let Some(channel) = ar9280::channel_5ghz(frequency) {
            channel
        } else if (2412..=2472).contains(&frequency) && (frequency - 2412) % 5 == 0 {
            ((frequency - 2407) / 5) as u8
        } else {
            return Err(BringUpError::BadIdentity);
        };
        if id.vendor != 0x168c
            || !matches!(id.device, ar9280::DEVID_PCI | ar9280::DEVID_PCIE)
            || Chip::for_device(id.device) != Some(Chip::Ar9280)
            || revision.chip != Chip::Ar9280
            || image.len() != super::chips::MAP_DEF.bytes()
            || prepared.tune.is_wide()
            || prepared.tune.center() != frequency
            || prepared.tune.is_5ghz() != (channel >= 36)
            || !(1..=3).contains(&identity.rx_chainmask)
            || !(1..=3).contains(&identity.tx_chainmask)
        {
            return Err(BringUpError::BadIdentity);
        }
        let plan = ar9280::power::plan(identity, image, prepared.tune, 40, overlap)?;
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(
            b"NARF AR9280 N80A two-chain closed-loop def legacy20 dual-band board admission v1",
        );
        h.update(b"eeprom_def map at word 64; ar9002 AR9280_2 INI modes column 1 (5G) / 4 (2G), rxgain/txgain by type, common, 5G fast clock; set_board_values; closed-loop def set_txpower; AR9280 init_cal OFF_PWDADC AGC/NF/IQ; ChainSel = txchainmask");
        for v in [
            id.vendor,
            id.device,
            id.subsystem_vendor,
            id.subsystem_id,
            identity.eeprom_version,
            prepared.ini_writes,
            frequency,
        ] {
            h.update(&v.to_le_bytes());
        }
        h.update(&revision.mac_version.to_le_bytes());
        h.update(&[
            revision.mac_rev,
            identity.rx_chainmask,
            identity.tx_chainmask,
            u8::from(prepared.tune.is_5ghz()),
        ]);
        h.update(&identity.mac);
        h.update(image);
        for gain in plan.gains {
            h.update(&gain.to_le_bytes());
        }
        h.update(&[plan.count as u8, plan.max_power]);
        for chain in plan.chains.iter().flatten() {
            h.update(&chain.tpcrg5.to_le_bytes());
            for word in chain.pdadc {
                h.update(&word.to_le_bytes());
            }
        }
        for (register, value) in &plan.registers[..plan.register_count] {
            h.update(&register.to_le_bytes());
            h.update(&value.to_le_bytes());
        }
        let modal = if prepared.tune.is_5ghz() {
            ar9280::MODAL_5G
        } else {
            ar9280::MODAL_2G
        };
        let mac = identity.mac;
        Ok(Self {
            request: Request {
                identity: h.finalize(),
                mac,
                device: id.device,
                frequency_mhz: frequency,
                filename: format!(
                    "ath9k/ar9280-admit-v1-ch{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                    channel, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                ),
            },
            // EEP_ANTENNA_GAIN_2G/5G: max over the three antennaGainCh.
            factory_antenna: image[modal + 16..modal + 19]
                .iter()
                .copied()
                .max()
                .unwrap_or(0),
            rx_chainmask: identity.rx_chainmask,
            tx_chainmask: identity.tx_chainmask,
            magic: *b"N80A",
            channel,
        })
    }
    /// AR5416/AR5418/AR9160 facts for one 20 MHz channel in either band:
    /// the PCI function, `AR_SREV` and `ar9002_hw_rf_claim` radio revision,
    /// the effective three-chain masks, the exact def map, the
    /// `phy::ar5008::prepare` row count at `frequency` and the
    /// `ath9k_hw_def_set_txpower` plan for the chip at the 40 half-dB
    /// maximum (`overlap` as for [`Self::new_ar9280`]).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_ar5008(
        id: &narf_bus::DeviceId,
        revision: &Revision,
        radio: u8,
        identity: &Identity,
        prepared: &super::phy::ar5008::Prepared,
        image: &[u8],
        frequency: u16,
        overlap: u8,
    ) -> Result<Self, BringUpError> {
        use super::phy::ar5008::{DEVID_AR5416_PCI, DEVID_AR5416_PCIE, DEVID_AR9160_PCI};
        let channel = if let Some(channel) = ar9280::channel_5ghz(frequency) {
            channel
        } else if (2412..=2472).contains(&frequency) && (frequency - 2412) % 5 == 0 {
            ((frequency - 2407) / 5) as u8
        } else {
            return Err(BringUpError::BadIdentity);
        };
        let (chip, magic, name) = match id.device {
            DEVID_AR5416_PCI | DEVID_AR5416_PCIE => (Chip::Ar5416, *b"N54A", "ar5416"),
            DEVID_AR9160_PCI => (Chip::Ar9160, *b"N60A", "ar9160"),
            _ => return Err(BringUpError::BadIdentity),
        };
        if id.vendor != 0x168c
            || Chip::for_device(id.device) != Some(chip)
            || revision.chip != chip
            || image.len() != super::chips::MAP_DEF.bytes()
            || prepared.tune.is_wide()
            || prepared.tune.center() != frequency
            || prepared.tune.is_5ghz() != (channel >= 36)
            || !(1..=7).contains(&identity.rx_chainmask)
            || !(1..=7).contains(&identity.tx_chainmask)
        {
            return Err(BringUpError::BadIdentity);
        }
        let plan = ar9280::power::plan_chip(identity, image, prepared.tune, 40, overlap, chip)?;
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(&magic);
        h.update(
            b"NARF AR5008-PHY three-chain closed-loop def legacy20 dual-band board admission v1",
        );
        h.update(b"eeprom_def map at word 64; ar5008/ar9001 INI modes column 1 (5G) / 4 (2G), ADDAC (def set_addac), common, BB_RfGain, analog banks with Bank 6 swizzle and AR5416 force bias; non-AR9280 set_board_values; three-chain closed-loop def set_txpower; ar9002 init_cal plain AGC, AR5008 NF, AR9160 multi-sample IQ; ChainSel = txchainmask");
        for v in [
            id.vendor,
            id.device,
            id.subsystem_vendor,
            id.subsystem_id,
            identity.eeprom_version,
            prepared.ini_writes,
            frequency,
        ] {
            h.update(&v.to_le_bytes());
        }
        h.update(&revision.mac_version.to_le_bytes());
        h.update(&[
            revision.mac_rev,
            radio,
            identity.rx_chainmask,
            identity.tx_chainmask,
            u8::from(prepared.tune.is_5ghz()),
        ]);
        h.update(&identity.mac);
        h.update(image);
        for gain in plan.gains {
            h.update(&gain.to_le_bytes());
        }
        h.update(&[plan.count as u8, plan.max_power]);
        for chain in plan.chains.iter().flatten() {
            h.update(&chain.tpcrg5.to_le_bytes());
            for word in chain.pdadc {
                h.update(&word.to_le_bytes());
            }
        }
        for (register, value) in &plan.registers[..plan.register_count] {
            h.update(&register.to_le_bytes());
            h.update(&value.to_le_bytes());
        }
        let modal = if prepared.tune.is_5ghz() {
            ar9280::MODAL_5G
        } else {
            ar9280::MODAL_2G
        };
        let mac = identity.mac;
        Ok(Self {
            request: Request {
                identity: h.finalize(),
                mac,
                device: id.device,
                frequency_mhz: frequency,
                filename: format!(
                    "ath9k/{}-admit-v1-ch{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                    name, channel, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                ),
            },
            factory_antenna: image[modal + 16..modal + 19]
                .iter()
                .copied()
                .max()
                .unwrap_or(0),
            rx_chainmask: identity.rx_chainmask,
            tx_chainmask: identity.tx_chainmask,
            magic,
            channel,
        })
    }
    /// AR9003 facts — AR9300 (`0x0030`, record `N93A`) or AR9580
    /// (`0x0033`, record `N95A`, the same layout) — for one 20 MHz channel in a band the
    /// map's `opFlags` enables: the PCI function, `AR_SREV` revision and
    /// host mode, the restored 1088-byte `ar9300_eeprom` (template and
    /// version bytes included), the effective (`fixup_chainmask`) masks up
    /// to 0x7, `ar9003::phy::prepare`'s retained facts at `frequency`
    /// (modes index, `TX_CL_CAL`, APM selfgen mask, gain-array rows) and
    /// the `ath9k_hw_ar9300_set_txpower` plan at the 40 half-dB maximum
    /// for `ctl` (`ath9k_regd_get_ctl`). The channel byte is the IEEE
    /// channel (2.4 GHz 1..14, 5 GHz 36..165); the factory antenna gain is
    /// the band's `antennaGain` (a negative value counts as zero).
    pub(super) fn new_ar9003(
        id: &narf_bus::DeviceId,
        revision: &super::ar9003::Revision,
        identity: &super::ar9003::eeprom::Identity,
        prepared: &super::ar9003::phy::Prepared,
        image: &super::ar9003::power::Image,
        frequency: u16,
        ctl: u16,
    ) -> Result<Self, BringUpError> {
        use super::ar9003::{eeprom, phy, power, Chip};
        if !phy::channel_supported(identity, frequency) {
            return Err(BringUpError::BadIdentity);
        }
        let five = frequency >= 4800;
        let channel = if five {
            ((frequency - 5000) / 5) as u8
        } else if frequency == 2484 {
            14
        } else {
            ((frequency - 2407) / 5) as u8
        };
        if id.vendor != 0x168c
            || Chip::for_device(id.device) != Some(revision.chip)
            || prepared.frequency != frequency
            || prepared.modes_index != if five { 1 } else { 4 }
            || !(1..=7).contains(&identity.rx_chainmask)
            || !(1..=7).contains(&identity.tx_chainmask)
        {
            return Err(BringUpError::BadIdentity);
        }
        let plan = power::plan(image, frequency, ctl, 40, identity.tx_chainmask)?;
        // Each part has its own magic, domain label and file name, so an
        // AR9300 record can never admit an AR9580 or the reverse.
        let (magic, label, recipe, file): (&[u8; 4], &[u8], &[u8], &str) = match revision.chip {
            Chip::Ar9300 => (
                b"N93A",
                b"NARF AR9300 N93A three-chain ar9300_eeprom legacy20 dual-band board admission v1",
                b"ar9300_eeprom_restore_internal image; ar9003_2p2 INI modes column 1 (5G) / 4 (2G), rx/tx gain by txrxgain, 5G fast clock, Japan 2484 CCK FIR; ar9003_hw_override_ini; set_board_values; ath9k_hw_ar9300_set_txpower (PAPRD/TPC off) with calibration_apply; ar9003_hw_init_cal_pcoem AGC/CLC/peak/IQ/NF; ar9003 EDMA",
                "ar9300",
            ),
            Chip::Ar9580 => (
                b"N95A",
                b"NARF AR9580 N95A three-chain ar9300_eeprom legacy20 dual-band board admission v1",
                b"ar9300_eeprom_restore_internal image; ar9580_1p0 INI modes column 1 (5G) / 4 (2G), rx/tx gain by txrxgain, 5G fast clock, Japan 2484 CCK FIR; ar9003_hw_override_ini; set_board_values; ath9k_hw_ar9300_set_txpower (PAPRD/TPC off) with calibration_apply; ar9003_hw_init_cal_pcoem AGC/CLC/peak/IQ/NF; ar9003 EDMA",
                "ar9580",
            ),
        };
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(magic);
        h.update(label);
        h.update(recipe);
        for v in [
            id.vendor,
            id.device,
            id.subsystem_vendor,
            id.subsystem_id,
            frequency,
            ctl,
            prepared.ini_writes,
            identity.regulatory_domains[0],
            identity.regulatory_domains[1],
        ] {
            h.update(&v.to_le_bytes());
        }
        h.update(&revision.chip.mac_version().to_le_bytes());
        h.update(&[
            revision.mac_rev,
            u8::from(revision.pcie),
            identity.eeprom_version,
            identity.template_version,
            identity.op_flags,
            identity.rx_chainmask,
            identity.tx_chainmask,
            identity.tx_gain,
            identity.rx_gain,
            u8::from(prepared.carrier_leak_cal),
            prepared.selfgen_mask,
        ]);
        h.update(&identity.mac);
        h.update(image);
        h.update(&plan.targets);
        h.update(&[plan.max_power_level, plan.tx_chainmask]);
        for values in [
            plan.correction,
            plan.temperature,
            plan.voltage,
            plan.nf_cal,
            plan.nf_power,
        ] {
            for value in values {
                h.update(&value.to_le_bytes());
            }
        }
        h.update(&plan.temp_slope.to_le_bytes());
        let gain = image[eeprom::modal_base(five) + eeprom::modal::ANTENNA_GAIN] as i8;
        let mac = identity.mac;
        Ok(Self {
            request: Request {
                identity: h.finalize(),
                mac,
                device: id.device,
                frequency_mhz: frequency,
                filename: format!(
                    "ath9k/{}-admit-v1-ch{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                    file, channel, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                ),
            },
            factory_antenna: gain.max(0) as u8,
            rx_chainmask: identity.rx_chainmask,
            tx_chainmask: identity.tx_chainmask,
            magic: *magic,
            channel,
        })
    }
    pub(super) fn request(&self) -> Request {
        self.request.clone()
    }
}

/// A verified record. Holding it proves a prior signed grant; `invoke`
/// re-proves the record capability is current before each use.
pub(super) struct Grant {
    facts: Facts,
    cap: Cap<FirmwareBlob, Read>,
    /// Measured antenna gain, half-dBi, at least the factory value.
    pub antenna: u8,
    /// Qualified ceiling in the host-limit unit Linux passes to
    /// `set_txpower` as `powerLimit` (half-dBm, `<= 40`).
    pub ceiling: u8,
}

pub(super) enum Source {
    /// The trusted firmware loader's record for `Facts::request().filename`.
    /// Only the AR9287, AR9280, AR5008 and AR9300 owners construct it.
    Registered,
    #[cfg(feature = "kernel-test")]
    Verified {
        bytes: Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
impl Source {
    /// Load the record named by `facts`; a missing, unsigned or mismatched
    /// record leaves the device unadmitted.
    pub(super) fn load(self, facts: Facts) -> Result<Arc<Grant>, BringUpError> {
        struct Decode(Facts);
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, BringUpError>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let v = narf_firmware::view_of(cap).map_err(|_| BringUpError::Policy)?;
                    Grant::decode(v.bytes, v.signer, *cap, self.0)
                })())
            }
        }
        let grant = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|c| c.derive::<Read>().ok())
                    .ok_or(BringUpError::Policy)?;
                let cap = narf_firmware::open(&facts.request.filename, &loader)
                    .map_err(|_| BringUpError::Policy)?;
                cap.invoke(Decode(facts))
                    .map_err(|_| BringUpError::Policy)??
            }
            #[cfg(feature = "kernel-test")]
            Self::Verified { bytes, signer, cap } => Grant::decode(&bytes, signer, cap, facts)?,
        };
        Ok(Arc::new(grant))
    }
}
impl Grant {
    fn decode(
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        facts: Facts,
    ) -> Result<Self, BringUpError> {
        cap.invoke(NoopOp).map_err(|_| BringUpError::Policy)?;
        let r = &facts.request;
        let [device_lo, device_hi] = r.device.to_le_bytes();
        if signer.is_none()
            || b.len() != LENGTH
            || b[..4] != facts.magic
            || b[4..8] != [1, 0, LENGTH as u8, 0]
            || b[8..12] != (LENGTH as u32).to_le_bytes()
            || b[12..16] != [0x8c, 0x16, device_lo, device_hi]
            || b[16..48] != r.identity
            || b[48..54] != r.mac
            || b[54..58] != [facts.channel, 20, facts.rx_chainmask, facts.tx_chainmask]
            || b[60..] != [0; LENGTH - 60]
        {
            return Err(BringUpError::Policy);
        }
        let (antenna, ceiling) = (b[58], b[59]);
        if antenna > 128 || antenna < facts.factory_antenna || ceiling > 40 {
            return Err(BringUpError::Policy);
        }
        Ok(Self {
            facts,
            cap,
            antenna,
            ceiling,
        })
    }
    pub(super) fn request(&self) -> Request {
        self.facts.request()
    }
    /// Transmit-power ceiling for `ath9k_hw_ar9287_set_txpower`: the host's
    /// current limit and the measured conducted ceiling, after removing the
    /// measured (not merely factory) antenna gain from the host EIRP limit.
    pub(super) fn ceiling(&self, host_eirp_half_dbm: u8) -> u8 {
        host_eirp_half_dbm
            .saturating_sub(self.antenna.saturating_sub(self.facts.factory_antenna))
            .min(self.ceiling)
    }
    /// Run `operation` only while the record capability is still current.
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, BringUpError>,
    ) -> Result<T, BringUpError> {
        self.cap.invoke(NoopOp).map_err(|_| BringUpError::Policy)?;
        operation()
    }
}

#[cfg(feature = "kernel-test")]
mod tests;
