// SPDX-License-Identifier: GPL-2.0-or-later
//! Signed per-board RTL8821AE 2.4 GHz 20 MHz power envelope.
//!
//! The Linux index ([`super::txpower`]) is an upper bound only: a reporting
//! index-to-dBm estimate cannot mint transmit permission. Every programmed
//! TXAGC index must also be covered by a signed, per-board measured conducted
//! output curve (`rtlwifi/rtl8821ae-cal-v1-<mac>.bin`, format `NAPC`) so that
//! measured output plus antenna gain stays under the host regulatory ceiling,
//! the board qualification ceiling and the shared `regd.c` channel 1-11 EIRP.
//! An unprovisioned board (no signed envelope, no factory power, no curve for
//! the channel) is not admitted.
//!
//! `NAPC` v1 layout (little endian): magic, version 1, header 96, total
//! length, vendor `0x10ec`, device `0x8821`, 32-byte factory identity
//! (SHA-256 of MAC + logical map), MAC, 2 zero bytes, antenna gain and
//! qualified EIRP (quarter dBm), row count (1..=11), bandwidth 20, 32 zero
//! bytes; then per channel: channel, 3 zero bytes and three 64-entry `i16`
//! measured-output curves (CCK, OFDM, HT/VHT 1SS) indexed by TXAGC value,
//! `i16::MAX` meaning "not measured".

use super::txpower::{self, ByRate, Factory as FactoryPower};
use crate::rtlwifi::channel_power::{domain_ceiling, Error};
use crate::rtlwifi::efuse::Factory;
use alloc::{format, vec::Vec};
use narf_capabilities::{Cap, NoopOp, Read};
use narf_firmware::FirmwareBlob;

const HEADER: usize = 96;
const ROW: usize = 4 + 3 * 64 * 2;
const UNKNOWN: i16 = i16::MAX;
/// `EEPROM` offset of the 2.4 GHz BB swing selector (`phy_get_tx_swing_8812A`).
pub const EEPROM_SWING_2G: usize = 0xc6;

struct Curve {
    channel: u8,
    /// CCK, OFDM, 1SS (HT MCS0-7 and VHT 1SS share the HT curve).
    output: [[i16; 64]; 3],
}

pub struct Calibration {
    identity: [u8; 32],
    power: FactoryPower,
    swing: u32,
    antenna: i16,
    qualified: i16,
    by_rate: ByRate,
    curves: Vec<Curve>,
    authority: Option<Cap<FirmwareBlob, Read>>,
}

impl core::fmt::Debug for Calibration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8821aeCalibration")
            .field("channels", &self.curves.len())
            .finish_non_exhaustive()
    }
}

/// Exact admitted 2.4 GHz 20 MHz operating point for one board/channel.
/// Private fields: only [`Calibration::permission`] can mint one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permission {
    identity: [u8; 32],
    channel: u8,
    /// Admitted TXAGC per full-order rate index (`0..48`; non-station rates 0).
    index: [u8; 48],
    swing: u32,
    eirp: i16,
}

impl Permission {
    pub fn channel(&self) -> u8 {
        self.channel
    }
    pub fn eirp_limit_qdbm(&self) -> i16 {
        self.eirp
    }
    /// Admitted TXAGC index for a full-order rate.
    pub fn index(&self, rate: u8) -> u8 {
        self.index.get(usize::from(rate)).copied().unwrap_or(0)
    }
    /// `phy_get_tx_swing_8812A(BAND_ON_2_4G)` for this board.
    pub fn swing(&self) -> u32 {
        self.swing
    }
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

fn half(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn signed(bytes: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// `phy_get_tx_swing_8812A(BAND_ON_2_4G)` for an autoloaded map: Linux reads
/// `0xC6` (`0xff` ⇒ 0), decodes path A then path B, and the path-B decode
/// (`[3:2]`) decides the returned value.
pub fn tx_swing_2g(logical: &[u8]) -> Result<u32, Error> {
    let raw = *logical.get(EEPROM_SWING_2G).ok_or(Error::FactoryPower)?;
    let swing = if raw == 0xff { 0 } else { raw };
    Ok(match (swing & 0xc) >> 2 {
        0 => 0x200,
        1 => 0x16a,
        2 => 0x101,
        _ => 0x0b6,
    })
}

impl Calibration {
    fn current(&self) -> Result<(), Error> {
        if let Some(cap) = &self.authority {
            return cap.invoke(NoopOp).map_err(|_| Error::Authority);
        }
        #[cfg(any(test, feature = "kernel-test"))]
        return Ok(()); // Inert verified-metadata fixtures cannot reach PCI.
        #[cfg(not(any(test, feature = "kernel-test")))]
        Err(Error::Authority)
    }

    /// Run `operation` inside the signed envelope's current firmware-asset
    /// authority (as `channel_power::Calibration::with_current`): a revoked
    /// or replaced calibration never reaches the hardware operation.
    pub(crate) fn with_current<T>(
        &self,
        operation: impl FnOnce() -> Result<T, crate::rtlwifi::prepare::Error>,
    ) -> Result<T, crate::rtlwifi::prepare::Error> {
        use narf_capabilities::{CapError, CapOp};
        struct Invoke<F>(F);
        impl<T, F: FnOnce() -> Result<T, crate::rtlwifi::prepare::Error>> CapOp<FirmwareBlob, Read>
            for Invoke<F>
        {
            type Output = Result<T, crate::rtlwifi::prepare::Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        if let Some(cap) = &self.authority {
            return cap
                .invoke(Invoke(operation))
                .map_err(|_| crate::rtlwifi::prepare::Error::Power(Error::Authority))?;
        }
        #[cfg(any(test, feature = "kernel-test"))]
        return operation();
        #[cfg(not(any(test, feature = "kernel-test")))]
        Err(crate::rtlwifi::prepare::Error::Power(Error::Authority))
    }

    pub fn load_registered(factory: &Factory) -> Result<Self, Error> {
        let m = factory.mac;
        let name = format!(
            "rtlwifi/rtl8821ae-cal-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let asset = crate::firmware_asset::load(&authority, &name, HEADER + 11 * ROW, true)
            .map_err(Error::Firmware)?;
        let mut calibration = Self::from_verified(&asset.bytes, asset.signer, factory)?;
        calibration.authority = Some(asset.cap);
        Ok(calibration)
    }

    pub(crate) fn from_verified(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        factory: &Factory,
    ) -> Result<Self, Error> {
        if signer.is_none() {
            return Err(Error::Unsigned);
        }
        let identity = crate::rtlwifi::radio::factory_identity(factory);
        let power =
            FactoryPower::from_logical(&factory.logical).map_err(|_| Error::FactoryPower)?;
        let swing = tx_swing_2g(&factory.logical)?;
        if bytes.len() < HEADER
            || bytes.len() > HEADER + 11 * ROW
            || &bytes[..4] != b"NAPC"
            || half(bytes, 4) != 1
            || half(bytes, 6) != HEADER as u16
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize != bytes.len()
            || half(bytes, 12) != 0x10ec
            || half(bytes, 14) != 0x8821
            || bytes[54..56] != [0; 2]
            || half(bytes, 62) != 20
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
            let output: [[i16; 64]; 3] = core::array::from_fn(|curve| {
                core::array::from_fn(|index| signed(row, 4 + (curve * 64 + index) * 2))
            });
            if output
                .iter()
                .flatten()
                .any(|v| *v != UNKNOWN && !(-512..=256).contains(v))
            {
                return Err(Error::Format);
            }
            curves.push(Curve {
                channel: row[0],
                output,
            });
        }
        Ok(Self {
            identity,
            power,
            swing,
            antenna,
            qualified,
            by_rate: ByRate::from_table(),
            curves,
            authority: None,
        })
    }

    /// Linux index for every station rate, each lowered to the highest
    /// measured index whose output plus antenna gain fits the ceiling.
    pub fn permission(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        channel: u8,
    ) -> Result<Permission, Error> {
        self.current()?;
        let eirp = domain_ceiling(domain, channel)?.min(self.qualified);
        let curve = self
            .curves
            .iter()
            .find(|c| c.channel == channel)
            .ok_or(Error::NoMeasuredGain)?;
        let mut index = [0u8; 48];
        for rate in txpower::station_rates() {
            let linux = self
                .by_rate
                .index(&self.power, rate, channel)
                .map_err(|_| Error::FactoryPower)?;
            let bounds = &curve.output[match rate {
                0..=3 => 0,
                4..=11 => 1,
                _ => 2,
            }];
            index[usize::from(rate)] = (0..=linux)
                .rev()
                .find(|i| {
                    let out = bounds[usize::from(*i)];
                    out != UNKNOWN && i32::from(out) + i32::from(self.antenna) <= i32::from(eirp)
                })
                .ok_or(Error::NoMeasuredGain)?;
        }
        Ok(Permission {
            identity: self.identity,
            channel,
            index,
            swing: self.swing,
            eirp,
        })
    }
}
