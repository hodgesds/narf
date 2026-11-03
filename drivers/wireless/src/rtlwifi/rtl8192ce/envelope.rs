// SPDX-License-Identifier: GPL-2.0-or-later
//! Signed per-board RTL8192CE (2T2R) / RTL8188CE (1T1R) power envelope
//! (2.4 GHz, 20/40 MHz).
//!
//! The Linux TXAGC bytes ([`super::txpower::linux_indices`],
//! `rtl92c_phy_set_txpower_level` over the factory map) are an upper bound
//! only: they cannot mint transmit permission. Every TXAGC index this owner
//! programs must also be covered by a signed, per-board measured
//! conducted-output curve (`rtlwifi/rtl8192ce-cal-v1-<mac>.bin`, format
//! `N92C`) so that the transmission stays under the host regulatory
//! ceiling, the board qualification ceiling and the `regd.c`
//! `RTL819x_2GHZ_CH01_11` EIRP (2402-2472 MHz, 20 dBm). An unprovisioned
//! board (no signed envelope, no factory power, no row for the operating
//! point) is not admitted.
//!
//! `N92C` v1 layout (little endian): magic, version 1, header 96, total
//! length, vendor `0x10ec`, device (the probed `rtl92ce_pci_ids` entry),
//! 32-byte factory identity (SHA-256 of MAC + logical map,
//! [`crate::rtlwifi::radio::factory_identity`]), MAC, RF type (1 =
//! `RF_1T1R`, 2 = `RF_2T2R`; must match the measured chip version), one
//! zero byte, antenna gain and qualified EIRP (quarter dBm), row count
//! (1..=[`ROWS`]), 34 zero bytes; then per row: primary channel, band 0
//! (2.4 GHz), bandwidth (20/40), secondary offset (0 none, 1 above, 2
//! below — 40 MHz only), then 64-entry `i16` measured conducted-output
//! curves (quarter dBm) indexed by that path's TXAGC value, `i16::MAX`
//! meaning "not measured": per family (CCK, OFDM, HT MCS0-7 and, on
//! `RF_2T2R` only, HT MCS8-15) path A then (on `RF_2T2R` only) path B —
//! 3 curves per row for 1T1R, 8 for 2T2R. Rows are strictly ordered by
//! (bandwidth, offset, channel) in the same plan as the RTL8192EE `N92E`
//! envelope (20 MHz 1..=11, 40 MHz above 1..=7, below 5..=11).
//!
//! Admission: for each station rate of the RF type and each transmitting
//! path, the highest measured index not above that path's Linux byte whose
//! output plus the antenna gain — plus [`TWO_CHAIN_QDBM`] on `RF_2T2R`,
//! where both chains are assumed to transmit every rate — fits the
//! ceiling. A rate is admitted only when every transmitting path has such
//! an index; every CCK and OFDM rate must be admitted. On `RF_1T1R` path B
//! does not transmit: its TXAGC bytes are written 0 (Linux programs them
//! from the shared map regardless). The format only carries measurements:
//! nothing here supplies any board's values.

use super::channel::{ChannelType, Operating as Channel};
use super::phy::PgStore;
use super::tables;
use super::txpower::{self, Efuse, RATES};
use super::version::RfType;
use crate::rtlwifi::channel_power::Error;
use crate::rtlwifi::efuse::Factory;
pub use crate::rtlwifi::rtl8192ee::envelope::{Operating, Width};
use alloc::{format, vec::Vec};
use narf_capabilities::{Cap, NoopOp, Read};
use narf_firmware::FirmwareBlob;

pub const MAGIC: [u8; 4] = *b"N92C";
const HEADER: usize = 96;
/// 11 (20 MHz) + 7 (40 MHz above) + 7 (40 MHz below).
pub const ROWS: usize = 25;
const UNKNOWN: i16 = i16::MAX;
/// Bound (quarter dBm) on the sum of two chains each at most the per-path
/// output: `10 * log10(2)` = 3.0103 dB, rounded up to 13 quarter dB.
pub const TWO_CHAIN_QDBM: i32 = 13;
/// Every CCK and OFDM rate must be admitted.
const LEGACY: u32 = 0xfff;

/// Header RF-type code.
const fn rf_code(rf: RfType) -> u8 {
    match rf {
        RfType::T1R1 => 1,
        RfType::T2R2 => 2,
    }
}

/// Rate families carried for `rf` (CCK, OFDM, MCS0-7[, MCS8-15]).
const fn families(rf: RfType) -> usize {
    match rf {
        RfType::T1R1 => 3,
        RfType::T2R2 => 4,
    }
}

const fn row_len(rf: RfType) -> usize {
    4 + families(rf) * rf.paths() * 64 * 2
}

fn family(rate: u8) -> usize {
    match rate {
        0..=3 => 0,
        4..=11 => 1,
        12..=19 => 2,
        _ => 3,
    }
}

/// The CE `rtl_op_config` channel state of an envelope operating point.
pub fn channel_of(op: Operating) -> Option<Channel> {
    op.center_mhz()?;
    let kind = match op.width {
        Width::W20 => ChannelType::Ht20,
        Width::W40Above => ChannelType::Ht40Plus,
        Width::W40Below => ChannelType::Ht40Minus,
    };
    Channel::new(op.channel, kind).ok()
}

struct Curve {
    op: Operating,
    /// `[family][path]`, family CCK/OFDM/MCS0-7/MCS8-15 (absent families
    /// and paths are all [`UNKNOWN`]).
    output: [[[i16; 64]; 2]; 4],
}

pub struct Calibration {
    identity: [u8; 32],
    device: u16,
    rf: RfType,
    power: Efuse,
    pwrgroup_cnt: u8,
    antenna: i16,
    qualified: i16,
    curves: Vec<Curve>,
    authority: Option<Cap<FirmwareBlob, Read>>,
}

impl core::fmt::Debug for Calibration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8192ceCalibration")
            .field("rf", &self.rf)
            .field("rows", &self.curves.len())
            .finish_non_exhaustive()
    }
}

/// Exact admitted operating point for one board. Private fields: only
/// [`Calibration::permission_for`] can mint one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permission {
    identity: [u8; 32],
    rf: RfType,
    op: Operating,
    /// Admitted TXAGC per path and full-order rate (unadmitted rates and
    /// the non-transmitting 1T1R path B are 0).
    index: [[u8; RATES]; 2],
    /// Rates (bit = full-order rate) admitted on every transmitting path.
    admitted: u32,
    eirp: i16,
}

impl Permission {
    pub fn channel(&self) -> u8 {
        self.op.channel
    }
    pub fn operating(&self) -> Operating {
        self.op
    }
    pub fn rf_type(&self) -> RfType {
        self.rf
    }
    pub fn eirp_limit_qdbm(&self) -> i16 {
        self.eirp
    }
    /// Admitted TXAGC index of `rate` (full order) on `path` (0 = A, 1 = B).
    pub fn index(&self, path: usize, rate: u8) -> u8 {
        self.index
            .get(path)
            .and_then(|p| p.get(usize::from(rate)))
            .copied()
            .unwrap_or(0)
    }
    /// Whether `rate` (full order) has a measured admitted index on every
    /// transmitting path: the only rates a forced descriptor rate or a
    /// firmware RA mask may name.
    pub fn admits(&self, rate: u8) -> bool {
        usize::from(rate) < RATES && self.admitted & (1 << rate) != 0
    }
    /// Bit set of [`Self::admits`] (full-order rates, as `h2c::mask_rates`).
    pub fn admitted_rates(&self) -> u64 {
        u64::from(self.admitted)
    }
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    /// `[path][rate]` TXAGC indices for [`super::txpower::set_indices`].
    pub fn indices(&self) -> &[[u8; RATES]; 2] {
        &self.index
    }
}

fn half(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn signed(bytes: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([bytes[at], bytes[at + 1]])
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
    /// authority (as the RTL8192EE `N92E` envelope): a revoked or replaced
    /// calibration never reaches the hardware operation.
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

    /// Load `rtlwifi/rtl8192ce-cal-v1-<mac>.bin` (signed firmware asset) for
    /// the probed `device` and the measured chip RF type.
    pub fn load_registered(factory: &Factory, device: u16, rf: RfType) -> Result<Self, Error> {
        let m = factory.mac;
        let name = format!(
            "rtlwifi/rtl8192ce-cal-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let asset = crate::firmware_asset::load(
            &authority,
            &name,
            HEADER + ROWS * row_len(RfType::T2R2),
            true,
        )
        .map_err(Error::Firmware)?;
        let mut calibration = Self::from_verified(&asset.bytes, asset.signer, factory, device, rf)?;
        calibration.authority = Some(asset.cap);
        Ok(calibration)
    }

    pub(crate) fn from_verified(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        factory: &Factory,
        device: u16,
        rf: RfType,
    ) -> Result<Self, Error> {
        if signer.is_none() {
            return Err(Error::Unsigned);
        }
        if !super::is_8192ce(device) {
            return Err(Error::Identity);
        }
        let identity = crate::rtlwifi::radio::factory_identity(factory);
        let hwinfo = factory
            .logical
            .get(..super::adapter::HWSET_MAX_SIZE)
            .ok_or(Error::FactoryPower)?;
        let power = Efuse::from_hwinfo(hwinfo).map_err(|_| Error::FactoryPower)?;
        let pwrgroup_cnt = PgStore::from_pg(&tables::PHY_REG_PG)
            .map_err(|_| Error::FactoryPower)?
            .pwrgroup_cnt;
        let row = row_len(rf);
        if bytes.len() < HEADER
            || bytes.len() > HEADER + ROWS * row
            || bytes[..4] != MAGIC
            || half(bytes, 4) != 1
            || half(bytes, 6) != HEADER as u16
            || u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize
                != bytes.len()
            || half(bytes, 12) != 0x10ec
            || bytes[55] != 0
            || bytes[62..HEADER] != [0; 34]
        {
            return Err(Error::Format);
        }
        if half(bytes, 14) != device
            || bytes[54] != rf_code(rf)
            || bytes[16..48] != identity
            || bytes[48..54] != factory.mac
        {
            return Err(Error::Identity);
        }
        let antenna = signed(bytes, 56);
        let qualified = signed(bytes, 58);
        let count = usize::from(half(bytes, 60));
        if !(0..=128).contains(&antenna)
            || !(-512..=256).contains(&qualified)
            || count == 0
            || count > ROWS
            || bytes.len() != HEADER + count * row
        {
            return Err(Error::Format);
        }
        let mut curves = Vec::new();
        curves
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        let mut previous: Option<Operating> = None;
        let paths = rf.paths();
        for r in bytes[HEADER..].chunks_exact(row) {
            if r[1] != 0 {
                return Err(Error::Format);
            }
            let width = match (r[2], r[3]) {
                (20, 0) => Width::W20,
                (40, 1) => Width::W40Above,
                (40, 2) => Width::W40Below,
                _ => return Err(Error::Format),
            };
            let op = Operating {
                width,
                channel: r[0],
            };
            if op.center_mhz().is_none() || previous.is_some_and(|p| p >= op) {
                return Err(Error::Format);
            }
            previous = Some(op);
            let mut output = [[[UNKNOWN; 64]; 2]; 4];
            for (f, fam) in output.iter_mut().enumerate().take(families(rf)) {
                for (path, curve) in fam.iter_mut().enumerate().take(paths) {
                    for (i, v) in curve.iter_mut().enumerate() {
                        *v = signed(r, 4 + ((f * paths + path) * 64 + i) * 2);
                        if *v != UNKNOWN && !(-512..=256).contains(v) {
                            return Err(Error::Format);
                        }
                    }
                }
            }
            curves.push(Curve { op, output });
        }
        Ok(Self {
            identity,
            device,
            rf,
            power,
            pwrgroup_cnt,
            antenna,
            qualified,
            curves,
            authority: None,
        })
    }

    pub fn rf_type(&self) -> RfType {
        self.rf
    }

    pub fn device(&self) -> u16 {
        self.device
    }

    /// Every operating point the envelope carries a measured row for (no
    /// policy; [`Self::permission_for`] still decides admission).
    pub fn operating_points(&self) -> impl Iterator<Item = Operating> + '_ {
        self.curves.iter().map(|c| c.op)
    }

    /// 20 MHz [`Self::permission_for`] on `channel`.
    pub fn permission(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        channel: u8,
    ) -> Result<Permission, Error> {
        self.permission_for(domain, Operating::twenty(channel))
    }

    /// The Linux TXAGC byte of every station rate on each transmitting path
    /// at `op`'s wide channel and width (`rtl92c_phy_sw_chnl` sets the power
    /// at `rtlphy->current_channel` / `current_chan_bw`), each lowered to the
    /// highest measured index that fits the ceiling.
    pub fn permission_for(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        op: Operating,
    ) -> Result<Permission, Error> {
        self.current()?;
        let eirp =
            crate::rtlwifi::rtl8192ee::envelope::span_ceiling(domain, op)?.min(self.qualified);
        let curve = self
            .curves
            .iter()
            .find(|c| c.op == op)
            .ok_or(Error::NoMeasuredGain)?;
        let channel = channel_of(op).ok_or(Error::Policy)?;
        let linux = txpower::linux_indices(
            &self.power,
            self.rf,
            self.pwrgroup_cnt,
            channel.wide,
            channel.bw40,
        )
        .map_err(|_| Error::FactoryPower)?;
        let chains = match self.rf {
            RfType::T1R1 => 0,
            RfType::T2R2 => TWO_CHAIN_QDBM,
        };
        let paths = self.rf.paths();
        let mut index = [[0u8; RATES]; 2];
        let mut admitted = 0u32;
        for rate in txpower::rates(self.rf) {
            let r = usize::from(rate);
            let mut fits = [None; 2];
            for (path, fit) in fits.iter_mut().enumerate().take(paths) {
                let bounds = &curve.output[family(rate)][path];
                *fit = (0..=linux[path][r]).rev().find(|i| {
                    let out = bounds[usize::from(*i)];
                    out != UNKNOWN
                        && i32::from(out) + chains + i32::from(self.antenna) <= i32::from(eirp)
                });
            }
            if fits[..paths].iter().all(Option::is_some) {
                for (path, fit) in fits.iter().enumerate().take(paths) {
                    index[path][r] = fit.unwrap_or(0);
                }
                admitted |= 1 << rate;
            }
        }
        if admitted & LEGACY != LEGACY {
            return Err(Error::NoMeasuredGain);
        }
        Ok(Permission {
            identity: self.identity,
            rf: self.rf,
            op,
            index,
            admitted,
            eirp,
        })
    }
}
