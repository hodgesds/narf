// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9287 (`0x002d`/`0x002e`) signed board admission record `N87A` v1 and
//! the AR9280 (`0x0029`/`0x002a`) dual-band record `N80A` v1.
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
    /// Only the AR9287 and AR9280 owners (`ar9287_owner`, `ar9280_owner`)
    /// construct it.
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
