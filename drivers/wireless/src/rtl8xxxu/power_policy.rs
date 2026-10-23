// SPDX-License-Identifier: GPL-2.0-or-later
//! Signed, per-device RTL8188EU conducted-power qualification.
//!
//! Linux 8188e.c selects rtl8188f_set_tx_power, which programs raw factory
//! gain indices. It supplies no RTL8188EU dBm curve. Never infer one from
//! another chip/bus or interpret an EEPROM index as a regulatory power limit.
//! This format carries measured conservative upper envelopes, not a default
//! curve. Signature verification and signer trust belong to narf_firmware.
use super::device_init::Factory;
use alloc::{format, vec::Vec};
use narf_firmware::FirmwareError;

const HEADER: usize = 64;
const ROW: usize = 260;
const UNKNOWN: i16 = i16::MAX;
const MAX_ROWS: usize = 13;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Firmware(FirmwareError),
    Unsigned,
    Format,
    Identity,
    Allocation,
    Policy,
    NoMeasuredGain,
}
struct Curve {
    channel: u8,
    cck: [i16; 64],
    ofdm: [i16; 64],
}
/// A registry-verified measurement artifact. Construction is restricted to
/// the signed registry path; a byte parser alone cannot mint TX permission.
pub struct Calibration {
    factory: Factory,
    vid: u16,
    pid: u16,
    antenna_qdbi: i16,
    qualified_eirp_qdbm: i16,
    curves: Vec<Curve>,
    signer: [u8; 32],
    digest: [u8; 32],
}
impl core::fmt::Debug for Calibration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188euPowerCalibration")
            .field("factory", &self.factory)
            .field("vid", &self.vid)
            .field("pid", &self.pid)
            .field("channels", &self.curves.len())
            .field("signer", &self.signer)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}
/// The exact checked gain pair for a fixed legacy 20MHz channel. All fields
/// are private: neither raw signed bytes nor a regulatory rule mint a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permission {
    factory: Factory,
    vid: u16,
    pid: u16,
    channel: u8,
    cck: u8,
    ofdm: u8,
    eirp_limit_qdbm: i16,
}
impl Permission {
    pub fn channel(&self) -> u8 {
        self.channel
    }
    pub fn eirp_limit_qdbm(&self) -> i16 {
        self.eirp_limit_qdbm
    }
    pub(super) fn gains(
        &self,
        factory: Factory,
        vid: u16,
        pid: u16,
        channel: u8,
    ) -> Result<(u8, u8), Error> {
        if self.factory != factory || self.vid != vid || self.pid != pid || self.channel != channel
        {
            return Err(Error::Identity);
        }
        Ok((self.cck, self.ofdm))
    }
}
fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn signed(bytes: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn factory_bytes(factory: Factory, vid: u16, pid: u16) -> [u8; 29] {
    let mut bytes = [0; 29];
    bytes[..2].copy_from_slice(&vid.to_le_bytes());
    bytes[2..4].copy_from_slice(&pid.to_le_bytes());
    bytes[4..6].copy_from_slice(&0x8188u16.to_le_bytes());
    bytes[6] = factory.cut;
    bytes[7] = 1; // RTL8188EU, USB, 1T1R, legacy20, no power tracking.
    bytes[8..14].copy_from_slice(&factory.mac);
    bytes[14..20].copy_from_slice(&factory.cck_power);
    bytes[20..25].copy_from_slice(&factory.ht40_power);
    bytes[25..29].copy_from_slice(&[
        factory.crystal_cap,
        factory.channel_plan,
        factory.thermal,
        factory.board_option,
    ]);
    bytes
}
impl Calibration {
    pub fn load_registered(factory: Factory, vid: u16, pid: u16) -> Result<Self, Error> {
        let name = format!(
            "rtl8xxxu/rtl8188eu-cal-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            factory.mac[0],
            factory.mac[1],
            factory.mac[2],
            factory.mac[3],
            factory.mac[4],
            factory.mac[5]
        );
        let loader = narf_firmware::trusted_loader_authority()
            .ok_or(Error::Firmware(FirmwareError::AuthorityRevoked))?;
        let auth = loader
            .derive()
            .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))?;
        let cap = narf_firmware::open(&name, &auth).map_err(Error::Firmware)?;
        let view = narf_firmware::view_of(&cap).map_err(Error::Firmware)?;
        // Even development firmware profiles may accept unsigned blobs. An
        // RF power qualification always requires an authenticated signer.
        Self::from_verified(view.bytes, view.signer, view.sha256, factory, vid, pid)
    }
    /// Called only after narf_firmware authenticated the current cap view.
    /// It is deliberately private; the kernel-test child exercises this same
    /// parser with verified-metadata fixtures, never a public trust bypass.
    fn from_verified(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        digest: [u8; 32],
        factory: Factory,
        vid: u16,
        pid: u16,
    ) -> Result<Self, Error> {
        let signer = signer.ok_or(Error::Unsigned)?;
        if bytes.len() < HEADER || bytes.len() > HEADER + MAX_ROWS * ROW
            || &bytes[..4] != b"N8PC" || le16(bytes, 4) != 1 || le16(bytes, 6) != HEADER as u16
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize != bytes.len()
            || bytes[41] != 1 // Complete board operating-envelope qualification, see specification.
            || bytes[48..64] != [0; 16]
        {
            return Err(Error::Format);
        }
        if bytes[12..41] != factory_bytes(factory, vid, pid)
            || factory.mac == [0; 6]
            || factory.mac[0] & 1 != 0
            || factory
                .cck_power
                .iter()
                .chain(&factory.ht40_power)
                .any(|&gain| gain > 63)
        {
            return Err(Error::Identity);
        }
        let antenna_qdbi = signed(bytes, 42);
        let qualified_eirp_qdbm = signed(bytes, 44);
        let count = usize::from(le16(bytes, 46));
        // Do not credit cable loss or a negative antenna gain. These are
        // conservative upper bounds, in quarter-dB units; no rounding down.
        if !(0..=128).contains(&antenna_qdbi)
            || !(-512..=256).contains(&qualified_eirp_qdbm)
            || count == 0
            || count > MAX_ROWS
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
            if !(1..=13).contains(&row[0]) || row[0] <= previous || row[1..4] != [0; 3] {
                return Err(Error::Format);
            }
            previous = row[0];
            let cck = core::array::from_fn(|i| signed(row, 4 + i * 2));
            let ofdm = core::array::from_fn(|i| signed(row, 132 + i * 2));
            if cck
                .iter()
                .chain(&ofdm)
                .any(|&bound| bound != UNKNOWN && !(-512..=256).contains(&bound))
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
            factory,
            vid,
            pid,
            antenna_qdbi,
            qualified_eirp_qdbm,
            curves,
            signer,
            digest,
        })
    }
    pub fn permission(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        channel: u8,
    ) -> Result<Permission, Error> {
        if channel != 1 || !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Policy);
        }
        let mut ceiling = None;
        for rule in &domain.rules {
            if rule.freq_start_mhz < 2422 && rule.freq_end_mhz > 2402 {
                // A broad permissive rule must not override a narrower
                // overlapping restriction. Unsupported flags fail closed.
                if rule.freq_start_mhz > 2402
                    || rule.freq_end_mhz < 2422
                    || rule.max_bandwidth_mhz < 20
                    || !rule.flags.is_empty()
                {
                    return Err(Error::Policy);
                }
                let limit = i16::from(rule.max_power_dbm) * 4;
                ceiling = Some(ceiling.map_or(limit, |old: i16| old.min(limit)));
            }
        }
        let eirp_limit_qdbm = ceiling.ok_or(Error::Policy)?.min(self.qualified_eirp_qdbm);
        let curve = self
            .curves
            .iter()
            .find(|c| c.channel == channel)
            .ok_or(Error::NoMeasuredGain)?;
        let select = |bounds: &[i16; 64], factory_max: u8| {
            (0..=factory_max)
                .rev()
                .find(|&index| {
                    let bound = bounds[usize::from(index)];
                    bound != UNKNOWN
                        && i32::from(bound) + i32::from(self.antenna_qdbi)
                            <= i32::from(eirp_limit_qdbm)
                })
                .ok_or(Error::NoMeasuredGain)
        };
        let cck = select(&curve.cck, self.factory.cck_power[0])?;
        let ofdm = select(&curve.ofdm, self.factory.ht40_power[0])?;
        Ok(Permission {
            factory: self.factory,
            vid: self.vid,
            pid: self.pid,
            channel,
            cck,
            ofdm,
            eirp_limit_qdbm,
        })
    }
}

#[cfg(feature = "kernel-test")]
#[path = "power_policy_tests.rs"]
mod tests;
