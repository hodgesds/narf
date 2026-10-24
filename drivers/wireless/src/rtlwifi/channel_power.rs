// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained 8188EE legacy20 channel/factory gains. Linux hw.c/phy.c/rf.c.
//! A reporting index-to-dBm estimate cannot mint transmit permission: actual
//! per-board signed upper envelopes qualify every final conducted gain.
use super::{efuse::Factory, radio};
use alloc::{format, vec::Vec};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
const HEADER: usize = 96;
const ROW: usize = 260;
const UNKNOWN: i16 = i16::MAX;
// Linux rtlwifi/regd.c::RTL819x_2GHZ_CH01_11 is shared by every
// retained EE channel-plan mapping, including its world fallback. Host
// policy and board measurements may lower this ceiling, never raise it.
const FACTORY_EIRP_QDBM: i16 = 20 * 4;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Firmware(FirmwareError),
    Authority,
    Unsigned,
    Format,
    Identity,
    Policy,
    FactoryPower,
    NoMeasuredGain,
    Allocation,
}
struct Curve {
    channel: u8,
    cck: [i16; 64],
    ofdm: [i16; 64],
}
pub struct Calibration {
    factory: Factory,
    identity: [u8; 32],
    antenna: i16,
    qualified: i16,
    curves: Vec<Curve>,
}
impl core::fmt::Debug for Calibration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188eeCalibration")
            .field("mac", &self.factory.mac)
            .field("channels", &self.curves.len())
            .finish_non_exhaustive()
    }
}
/// Exact legacy20 gain/geometry grant. Private fields prevent unverified
/// bytes or another device's calibration from admitting packet transmit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permission {
    identity: [u8; 32],
    channel: u8,
    cck: [u8; 4],
    ofdm: [u8; 8],
    eirp: i16,
}
impl Permission {
    pub fn channel(&self) -> u8 {
        self.channel
    }
    pub fn eirp_limit_qdbm(&self) -> i16 {
        self.eirp
    }
    pub(super) fn check(&self, identity: [u8; 32]) -> Result<(), Error> {
        if self.identity == identity {
            Ok(())
        } else {
            Err(Error::Identity)
        }
    }
    pub(super) fn gains(&self) -> ([u8; 4], [u8; 8]) {
        (self.cck, self.ofdm)
    }
}
fn half(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn signed(bytes: &[u8], at: usize) -> i16 {
    i16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
struct ReadCalibration<'a>(&'a Factory);
impl CapOp<FirmwareBlob, Read> for ReadCalibration<'_> {
    type Output = Result<Calibration, Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok(narf_firmware::view_of(cap)
            .map_err(Error::Firmware)
            .and_then(|view| Calibration::from_verified(view.bytes, view.signer, self.0)))
    }
}
impl Calibration {
    pub fn load_registered(factory: &Factory) -> Result<Self, Error> {
        let name = format!(
            "rtlwifi/rtl8188ee-cal-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            factory.mac[0],
            factory.mac[1],
            factory.mac[2],
            factory.mac[3],
            factory.mac[4],
            factory.mac[5]
        );
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let cap = narf_firmware::open(&name, &authority).map_err(Error::Firmware)?;
        cap.invoke(ReadCalibration(factory))
            .map_err(|_| Error::Authority)?
    }
    fn from_verified(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        factory: &Factory,
    ) -> Result<Self, Error> {
        if signer.is_none() {
            return Err(Error::Unsigned);
        }
        let identity = radio::factory_identity(factory);
        radio::Profile::from_factory(factory).map_err(|_| Error::Identity)?;
        if bytes.len() < HEADER
            || bytes.len() > HEADER + 11 * ROW
            || &bytes[..4] != b"NEPC"
            || half(bytes, 4) != 1
            || half(bytes, 6) != HEADER as u16
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize != bytes.len()
            || half(bytes, 12) != 0x10ec
            || half(bytes, 14) != 0x8179
            || bytes[54..56] != [0; 2]
            || half(bytes, 62) != 1
            || bytes[64..HEADER] != [0; 32]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != identity || bytes[48..54] != factory.mac {
            return Err(Error::Identity);
        }
        let antenna = signed(bytes, 56);
        let qualified = signed(bytes, 58);
        let count = usize::from(half(bytes, 60));
        if !(0..=128).contains(&antenna)
            || !(-512..=256).contains(&qualified)
            || count == 0
            || count > 11
            || bytes.len() != HEADER + count * ROW
        {
            return Err(Error::Format);
        }
        let mut curves = Vec::new();
        curves
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        let mut previous = 0;
        for row in bytes[HEADER..].chunks_exact(ROW) {
            if !(1..=11).contains(&row[0]) || row[0] <= previous || row[1..4] != [0; 3] {
                return Err(Error::Format);
            }
            previous = row[0];
            let cck = core::array::from_fn(|index| signed(row, 4 + index * 2));
            let ofdm = core::array::from_fn(|index| signed(row, 132 + index * 2));
            if cck
                .iter()
                .chain(&ofdm)
                .any(|value| *value != UNKNOWN && !(-512..=256).contains(value))
            {
                return Err(Error::Format);
            }
            curves.push(Curve {
                channel: row[0],
                cck,
                ofdm,
            });
        }
        Ok(Self {
            factory: factory.clone(),
            identity,
            antenna,
            qualified,
            curves,
        })
    }
    pub fn permission(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        channel: u8,
    ) -> Result<Permission, Error> {
        if !(1..=11).contains(&channel) || !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Policy);
        }
        let center = 2407 + u32::from(channel) * 5;
        let lower = center - 10;
        let upper = center + 10;
        let mut limit = None;
        for rule in &domain.rules {
            if rule.freq_start_mhz < upper && rule.freq_end_mhz > lower {
                if rule.freq_start_mhz > lower
                    || rule.freq_end_mhz < upper
                    || rule.max_bandwidth_mhz < 20
                    || !rule.flags.is_empty()
                {
                    return Err(Error::Policy);
                }
                let ceiling = i16::from(rule.max_power_dbm) * 4;
                limit = Some(limit.map_or(ceiling, |old: i16| old.min(ceiling)));
            }
        }
        let eirp = limit
            .ok_or(Error::Policy)?
            .min(self.qualified)
            .min(FACTORY_EIRP_QDBM);
        let curve = self
            .curves
            .iter()
            .find(|curve| curve.channel == channel)
            .ok_or(Error::NoMeasuredGain)?;
        let (factory_cck, factory_ofdm) = factory_gains(&self.factory, channel)?;
        let select = |bounds: &[i16; 64], maximum: u8| -> Result<u8, Error> {
            (0..=maximum)
                .rev()
                .find(|index| {
                    bounds[usize::from(*index)] != UNKNOWN
                        && i32::from(bounds[usize::from(*index)]) + i32::from(self.antenna)
                            <= i32::from(eirp)
                })
                .ok_or(Error::NoMeasuredGain)
        };
        let mut cck = [0; 4];
        let mut ofdm = [0; 8];
        for (gain, maximum) in cck.iter_mut().zip(factory_cck) {
            *gain = select(&curve.cck, maximum)?;
        }
        for (gain, maximum) in ofdm.iter_mut().zip(factory_ofdm) {
            *gain = select(&curve.ofdm, maximum)?;
        }
        Ok(Permission {
            identity: self.identity,
            channel,
            cck,
            ofdm,
            eirp,
        })
    }
}

/// Exact pathA factory/PG selection, without Linux scan turbo or thermal
/// boosts. Negative signed differences never wrap into a larger gain.
fn factory_gains(factory: &Factory, channel: u8) -> Result<([u8; 4], [u8; 8]), Error> {
    if !(1..=11).contains(&channel) {
        return Err(Error::Policy);
    }
    let group = match channel {
        1..=2 => 0,
        3..=5 => 1,
        6..=8 => 2,
        _ => 3,
    };
    let map = &factory.logical;
    let cck_base = map[0x10 + group];
    let ofdm_base = map[0x16 + group];
    let difference = map[0x1b] & 15;
    if map[0x11] == 255 || cck_base > 63 || ofdm_base > 63 || map[0x1b] == 255 {
        return Err(Error::FactoryPower);
    }
    let delta = if difference & 8 != 0 {
        i16::from(difference) - 16
    } else {
        i16::from(difference)
    };
    let ofdm_base = i16::from(ofdm_base) + delta;
    if !(0..=63).contains(&ofdm_base) {
        return Err(Error::FactoryPower);
    }
    let regulatory = if map[0xc1] == 255 { 0 } else { map[0xc1] & 7 };
    let pg = if regulatory == 1 { group } else { 0 };
    let rows = &radio::power_groups()[pg * 8..pg * 8 + 8];
    let mut cck = [cck_base; 4];
    if regulatory == 0 {
        let offsets = rows[2][2].wrapping_add(rows[3][2] << 8).to_le_bytes();
        for (gain, offset) in cck.iter_mut().zip(offsets) {
            *gain = gain.saturating_add(offset).min(63);
        }
    }
    let mut ofdm = [ofdm_base as u8; 8];
    if !matches!(regulatory, 2 | 3) {
        for (gains, row) in ofdm.chunks_exact_mut(4).zip(&rows[..2]) {
            for (gain, offset) in gains.iter_mut().zip(row[2].to_le_bytes()) {
                *gain = gain.saturating_add(offset & 127).min(63);
            }
        }
    }
    Ok((cck, ofdm))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "channel_power_tests.rs"]
pub(super) mod tests;
