// SPDX-License-Identifier: GPL-2.0-or-later
//! Signed per-board RTL8192EE power envelope (2.4 GHz, 20/40 MHz, 2T2R).
//!
//! The Linux index ([`super::txpower::index`], `_rtl92ee_get_txpower_index`)
//! is an upper bound only: it cannot mint transmit permission. Every TXAGC
//! index this owner programs must also be covered by a signed, per-board
//! measured conducted-output curve (`rtlwifi/rtl8192ee-cal-v1-<mac>.bin`,
//! format `N92E`) so that the transmission stays under the host regulatory
//! ceiling, the board qualification ceiling and the `regd.c`
//! `RTL819x_2GHZ_CH01_11` EIRP (2402-2472 MHz, 20 dBm). An unprovisioned
//! board (no signed envelope, no factory power, no row for the operating
//! point) is not admitted.
//!
//! `N92E` v1 layout (little endian): magic, version 1, header 96, total
//! length, vendor `0x10ec`, device `0x818b`, 32-byte factory identity
//! (SHA-256 of MAC + logical map, [`crate::rtlwifi::radio::factory_identity`]),
//! MAC, 2 zero bytes, antenna gain and qualified EIRP (quarter dBm), row
//! count (1..=[`ROWS`]), 34 zero bytes; then per row: primary channel,
//! band 0 (2.4 GHz), bandwidth (20/40), secondary offset (0 none, 1 above,
//! 2 below — 40 MHz only), then eight 64-entry `i16` measured conducted
//! output curves (quarter dBm), path A then path B for each of CCK, OFDM,
//! HT MCS0-7 and HT MCS8-15, indexed by that path's TXAGC value, `i16::MAX`
//! meaning "not measured". Rows are strictly ordered by (bandwidth, offset,
//! channel): channels 1..=11 at 20 MHz, 40 MHz above for 1..=7 and below
//! for 5..=11 (`rtl_op_config` wide channel 3..=9 / 3..=9).
//!
//! Admission (both chains are assumed to transmit every rate): for each
//! station rate and each path the highest measured index not above that
//! path's Linux index whose output plus [`TWO_CHAIN_QDBM`] (the 3.01 dB bound
//! of two equal incoherent chains, rounded up) plus the antenna gain fits the
//! ceiling. A rate is admitted only when both paths have such an index;
//! every CCK and OFDM rate must be admitted. The antenna gain is the board's
//! combined (directional) two-chain gain as qualified with the envelope.
//! The format only carries measurements: nothing here supplies any board's
//! values.

use super::channel::{ChannelType, Operating as Channel};
use super::phy::ByRate;
use super::tables;
use super::txpower::{self, Efuse, Width as PowerWidth};
use crate::rtlwifi::channel_power::{domain_ceiling, Error};
use crate::rtlwifi::efuse::Factory;
use alloc::{format, vec::Vec};
use narf_capabilities::{Cap, NoopOp, Read};
use narf_firmware::FirmwareBlob;

pub const MAGIC: [u8; 4] = *b"N92E";
pub const DEVICE: u16 = 0x818b;
const HEADER: usize = 96;
/// Curves per row: (CCK, OFDM, MCS0-7, MCS8-15) × (path A, path B).
const CURVES: usize = 8;
const ROW: usize = 4 + CURVES * 64 * 2;
/// 11 (20 MHz) + 7 (40 MHz above) + 7 (40 MHz below).
pub const ROWS: usize = 25;
const UNKNOWN: i16 = i16::MAX;
/// Station rates in full order: CCK 0..=3, OFDM 4..=11, MCS0-15 12..=27.
pub const RATES: usize = 28;
/// Bound (quarter dBm) on the sum of two chains each at most the per-path
/// output: `10 * log10(2)` = 3.0103 dB, rounded up to 13 quarter dB.
pub const TWO_CHAIN_QDBM: i32 = 13;
/// Every CCK and OFDM rate must be admitted.
const LEGACY: u32 = 0xfff;

/// Envelope bandwidth / secondary offset of one row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Width {
    W20,
    W40Above,
    W40Below,
}

impl Width {
    fn key(self) -> (u8, u8) {
        match self {
            Self::W20 => (20, 0),
            Self::W40Above => (40, 1),
            Self::W40Below => (40, 2),
        }
    }
    fn from_key(bw: u8, offset: u8) -> Option<Self> {
        Some(match (bw, offset) {
            (20, 0) => Self::W20,
            (40, 1) => Self::W40Above,
            (40, 2) => Self::W40Below,
            _ => return None,
        })
    }
    pub fn mhz(self) -> u32 {
        match self {
            Self::W20 => 20,
            _ => 40,
        }
    }
}

/// One 2.4 GHz operating point (primary channel and width).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Operating {
    pub width: Width,
    pub channel: u8,
}

impl Operating {
    pub const fn twenty(channel: u8) -> Self {
        Self {
            width: Width::W20,
            channel,
        }
    }

    /// Center frequency (MHz) of the whole channel, or `None` outside the
    /// envelope plan (20 MHz 1..=11, 40 MHz above 1..=7, below 5..=11).
    pub fn center_mhz(&self) -> Option<u32> {
        let ch = self.channel;
        let primary = 2407 + u32::from(ch) * 5;
        match self.width {
            Width::W20 if (1..=11).contains(&ch) => Some(primary),
            Width::W40Above if (1..=7).contains(&ch) => Some(primary + 10),
            Width::W40Below if (5..=11).contains(&ch) => Some(primary - 10),
            _ => None,
        }
    }

    /// The `rtl_op_config` channel state (`rtl8192ee/channel.rs`): HT40+ is
    /// a 40 MHz secondary above the primary.
    pub fn channel(&self) -> Option<Channel> {
        self.center_mhz()?;
        let kind = match self.width {
            Width::W20 => ChannelType::Ht20,
            Width::W40Above => ChannelType::Ht40Plus,
            Width::W40Below => ChannelType::Ht40Minus,
        };
        Channel::new(self.channel, kind).ok()
    }
}

struct Curve {
    op: Operating,
    /// `[family][path]`, family CCK/OFDM/MCS0-7/MCS8-15.
    output: [[[i16; 64]; 2]; 4],
}

pub struct Calibration {
    identity: [u8; 32],
    power: Efuse,
    by_rate: ByRate,
    antenna: i16,
    qualified: i16,
    curves: Vec<Curve>,
    authority: Option<Cap<FirmwareBlob, Read>>,
}

impl core::fmt::Debug for Calibration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8192eeCalibration")
            .field("rows", &self.curves.len())
            .finish_non_exhaustive()
    }
}

/// Exact admitted operating point for one board. Private fields: only
/// [`Calibration::permission_for`] can mint one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permission {
    identity: [u8; 32],
    op: Operating,
    /// Admitted TXAGC per path and full-order rate (unadmitted rates 0).
    index: [[u8; RATES]; 2],
    /// Rates (bit = full-order rate) admitted on both paths.
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
    /// Whether `rate` (full order) has a measured admitted index on both
    /// paths: the only rates a forced descriptor rate or a firmware RA mask
    /// may name.
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

fn family(rate: u8) -> usize {
    match rate {
        0..=3 => 0,
        4..=11 => 1,
        12..=19 => 2,
        _ => 3,
    }
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
    /// authority (as the RTL8821AE `NAPC` envelope): a revoked or replaced
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

    /// Load `rtlwifi/rtl8192ee-cal-v1-<mac>.bin` (signed firmware asset).
    pub fn load_registered(factory: &Factory) -> Result<Self, Error> {
        let m = factory.mac;
        let name = format!(
            "rtlwifi/rtl8192ee-cal-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let asset = crate::firmware_asset::load(&authority, &name, HEADER + ROWS * ROW, true)
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
        let power = Efuse::from_logical(&factory.logical).map_err(|_| Error::FactoryPower)?;
        if bytes.len() < HEADER
            || bytes.len() > HEADER + ROWS * ROW
            || bytes[..4] != MAGIC
            || half(bytes, 4) != 1
            || half(bytes, 6) != HEADER as u16
            || u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize
                != bytes.len()
            || half(bytes, 12) != 0x10ec
            || half(bytes, 14) != DEVICE
            || bytes[54..56] != [0; 2]
            || bytes[62..HEADER] != [0; 34]
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
            || count > ROWS
            || bytes.len() != HEADER + count * ROW
        {
            return Err(Error::Format);
        }
        let mut curves = Vec::new();
        curves
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        let mut previous: Option<Operating> = None;
        for row in bytes[HEADER..].chunks_exact(ROW) {
            if row[1] != 0 {
                return Err(Error::Format);
            }
            let width = Width::from_key(row[2], row[3]).ok_or(Error::Format)?;
            let op = Operating {
                width,
                channel: row[0],
            };
            if op.center_mhz().is_none() || previous.is_some_and(|p| p >= op) {
                return Err(Error::Format);
            }
            previous = Some(op);
            let output: [[[i16; 64]; 2]; 4] = core::array::from_fn(|f| {
                core::array::from_fn(|path| {
                    core::array::from_fn(|i| signed(row, 4 + ((f * 2 + path) * 64 + i) * 2))
                })
            });
            if output
                .iter()
                .flatten()
                .flatten()
                .any(|v| *v != UNKNOWN && !(-512..=256).contains(v))
            {
                return Err(Error::Format);
            }
            curves.push(Curve { op, output });
        }
        Ok(Self {
            identity,
            power,
            by_rate: ByRate::from_pg(tables::PHY_REG_PG),
            antenna,
            qualified,
            curves,
            authority: None,
        })
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

    /// The Linux index of every station rate on each path at `op`'s wide
    /// channel and width (`rtl92ee_phy_set_txpower_level` runs at
    /// `rtlphy->current_channel` / `current_chan_bw`), each lowered to the
    /// highest measured index that fits the ceiling.
    pub fn permission_for(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        op: Operating,
    ) -> Result<Permission, Error> {
        self.current()?;
        let eirp = span_ceiling(domain, op)?.min(self.qualified);
        let curve = self
            .curves
            .iter()
            .find(|c| c.op == op)
            .ok_or(Error::NoMeasuredGain)?;
        let channel = op.channel().ok_or(Error::Policy)?;
        let bw = match op.width {
            Width::W20 => PowerWidth::W20,
            _ => PowerWidth::W40,
        };
        let mut index = [[0u8; RATES]; 2];
        let mut admitted = 0u32;
        for rate in txpower::rates() {
            let mut fits = [None; 2];
            for (path, fit) in fits.iter_mut().enumerate() {
                let linux =
                    txpower::index(&self.power, &self.by_rate, path, rate, bw, channel.wide);
                let bounds = &curve.output[family(rate)][path];
                *fit = (0..=linux).rev().find(|i| {
                    let out = bounds[usize::from(*i)];
                    out != UNKNOWN
                        && i32::from(out) + TWO_CHAIN_QDBM + i32::from(self.antenna)
                            <= i32::from(eirp)
                });
            }
            if let [Some(a), Some(b)] = fits {
                index[0][usize::from(rate)] = a;
                index[1][usize::from(rate)] = b;
                admitted |= 1 << rate;
            }
        }
        if admitted & LEGACY != LEGACY {
            return Err(Error::NoMeasuredGain);
        }
        Ok(Permission {
            identity: self.identity,
            op,
            index,
            admitted,
            eirp,
        })
    }
}

/// Host regulatory ceiling (quarter dBm) for the whole span of `op`, as the
/// RTL8821AE envelope: 20 MHz is [`domain_ceiling`]; 40 MHz needs every
/// overlapping rule to cover the full span, allow 40 MHz and carry no flag
/// (DFS / NO_IR / indoor refused), capped by `regd.c` `RTL819x_2GHZ_CH01_11`
/// (2402-2472 MHz, 20 dBm).
pub(crate) fn span_ceiling(
    domain: &narf_wireless::reg::RegulatoryDomain,
    op: Operating,
) -> Result<i16, Error> {
    if op.width == Width::W20 {
        return domain_ceiling(domain, op.channel);
    }
    let center = op.center_mhz().ok_or(Error::Policy)?;
    if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
        return Err(Error::Policy);
    }
    let (lower, upper) = (center - 20, center + 20);
    if lower < 2402 || upper > 2472 {
        return Err(Error::Policy);
    }
    let mut limit = None;
    for rule in &domain.rules {
        if rule.freq_start_mhz < upper && rule.freq_end_mhz > lower {
            if rule.freq_start_mhz > lower
                || rule.freq_end_mhz < upper
                || rule.max_bandwidth_mhz < 40
                || !rule.flags.is_empty()
            {
                return Err(Error::Policy);
            }
            let ceiling = i16::from(rule.max_power_dbm) * 4;
            limit = Some(limit.map_or(ceiling, |old: i16| old.min(ceiling)));
        }
    }
    Ok(limit.ok_or(Error::Policy)?.min(20 * 4))
}
