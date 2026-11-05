// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723AE signed per-board power envelopes (NAPC).
//!
//! This mirrors `rtl8821ae::envelope` (and `rtl8192ee::envelope`) for the
//! 8723AE: a signed companion file carries the board's measured TX power
//! curves, and only [`Calibration::permission_for`] can mint a
//! [`Permission`] the packet owner may transmit under. Private fields
//! and the signer requirement keep unverified bytes — or another board's
//! calibration — from ever admitting packet transmit.
//!
//! ## 8723AE adaptations (grounded, not invented)
//!
//! - Vendor `0x10ec`, device `0x8723` (`rtl8723ae/sw.c`
//!   `rtl8723e_pci_ids`); file names
//!   `rtlwifi/rtl8723ae-cal-v2-<mac>.bin` tried before v1, mirroring the
//!   8821AE loader.
//! - 2.4 GHz ONLY. The 8723AE is a 2.4 GHz 1T1R part (spec
//!   `rtlwifi.md` RTL8723AE section); any 5 GHz row is a [`Error::Format`]
//!   failure, and channels 12/13/14 are never admitted (fail-closed:
//!   the shared Linux `regd.c` channel 1-11 ceiling in
//!   `channel_power::domain_ceiling` covers 1..=11 only).
//! - Curves are CCK, OFDM and HT 1SS (MCS0-7). There is no VHT curve on
//!   this part; the 8821AE HT/VHT-shared third curve becomes HT-only.
//! - v1 rows: 11 legacy20 channels 1..=11. v2 rows: at most 25 —
//!   11 × 20 MHz + 7 × 40 MHz (offset above, primaries 1..=7) + 7 ×
//!   40 MHz (offset below, primaries 5..=11) — the 8821AE 2.4 GHz row
//!   plan with its 5 GHz rows removed. Rows are strictly ordered by
//!   (bandwidth, offset, channel): 20 MHz rows first, then 40-above,
//!   then 40-below.
//! - No BB swing: the 8821AE `0xc6`/`0xc7` selectors come from
//!   `phy_get_tx_swing_8812A`, an 8812A-specific source with no 8723AE
//!   grounding, so [`Permission`] carries no swing value and the packet
//!   owner never programs swing from the envelope.
//! - No factory per-rate TXAGC cap: no 8723AE `ByRate` table exists
//!   in-tree (the 8192EE `PHY_REG_PG` table is 8192EE-specific). Rate
//!   selection scans the full TXAGC index range `0..=63` for the
//!   highest measured index whose output plus antenna gain fits the
//!   ceiling; a factory-cap refinement is a documented remainder. The
//!   regulatory ceiling plus the qualified EIRP still bound every
//!   admitted index, and every index comes from a signed measured curve.
//! - Station rates are the 20 full-order rates CCK 0..3, OFDM 4..11,
//!   HT MCS0-7 12..19. Every one must be admitted or the operating
//!   point is not admitted ([`Error::NoMeasuredGain`]).

use crate::rtlwifi::channel_power::{domain_ceiling, Error};
use alloc::{format, vec::Vec};
use narf_capabilities::{Cap, NoopOp, Read};
use narf_firmware::FirmwareBlob;

/// NAPC header size.
const HEADER: usize = 96;
/// NAPC row size: channel/band/bandwidth/offset + three 64-entry `i16` curves.
const ROW: usize = 4 + 3 * 64 * 2;
/// Maximum NAPC v2 rows for 8723AE: 11 × 20 MHz + 7 + 7 × 40 MHz.
pub const V2_ROWS: usize = 25;
/// Maximum NAPC v1 rows: 11 legacy20 channels.
pub const V1_ROWS: usize = 11;
/// Unmeasured curve entry.
const UNKNOWN: i16 = i16::MAX;
/// PCI vendor ID (Realtek).
const VENDOR: u16 = 0x10ec;
/// PCI device ID (RTL8723AE).
const DEVICE: u16 = 0x8723;

/// 2.4 GHz operating width of a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Width {
    /// 20 MHz, no secondary offset.
    W20,
    /// 40 MHz, secondary channel above the primary.
    W40Above,
    /// 40 MHz, secondary channel below the primary.
    W40Below,
}

impl Width {
    /// Width in MHz, for the regulatory span check.
    const fn mhz(self) -> u32 {
        match self {
            Width::W20 => 20,
            Width::W40Above | Width::W40Below => 40,
        }
    }

    /// Row key for strict ordering: 20 MHz rows sort before 40 MHz rows.
    const fn key(self) -> (u8, u8) {
        match self {
            Width::W20 => (20, 0),
            Width::W40Above => (40, 1),
            Width::W40Below => (40, 2),
        }
    }

    /// Decode a v2 row's (bandwidth, offset) bytes. Bandwidth must be 20
    /// or 40; offset must be 0 (none, 20 MHz only), 1 (above) or 2
    /// (below, 40 MHz only).
    fn from_key(bandwidth: u8, offset: u8) -> Option<Self> {
        match (bandwidth, offset) {
            (20, 0) => Some(Width::W20),
            (40, 1) => Some(Width::W40Above),
            (40, 2) => Some(Width::W40Below),
            _ => None,
        }
    }
}

/// An admitted operating point: 2.4 GHz width + primary channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Operating {
    /// 20 MHz or 40 MHz width.
    pub width: Width,
    /// Primary channel (1..=11).
    pub channel: u8,
}

impl Operating {
    /// 20 MHz operating point on `channel`.
    pub const fn twenty(channel: u8) -> Self {
        Self {
            width: Width::W20,
            channel,
        }
    }

    /// Legacy20 alias (the v1 operating point).
    pub const fn legacy20(channel: u8) -> Self {
        Self::twenty(channel)
    }

    /// Centre frequency in MHz, or `None` outside the admitted plan:
    /// 20 MHz primaries 1..=11, 40-above primaries 1..=7, 40-below
    /// primaries 5..=11.
    pub fn center_mhz(self) -> Option<u32> {
        let primary = u32::from(self.channel);
        match self.width {
            Width::W20 if (1..=11).contains(&self.channel) => Some(2407 + primary * 5),
            Width::W40Above if (1..=7).contains(&self.channel) => Some(2407 + (primary + 2) * 5),
            Width::W40Below if (5..=11).contains(&self.channel) => Some(2407 + (primary - 2) * 5),
            _ => None,
        }
    }

    /// Wide (centre) channel number for the 40 MHz span, or `None` for
    /// 20 MHz points (which are their own centre).
    fn wide_channel(self) -> Option<u8> {
        match self.width {
            Width::W20 => Some(self.channel),
            Width::W40Above => self.channel.checked_add(2),
            Width::W40Below => self.channel.checked_sub(2),
        }
    }
}

/// Whether `channel` is a 2.4 GHz station channel (1..=11).
pub fn station_channel(channel: u8) -> bool {
    Operating::twenty(channel).center_mhz().is_some()
}

/// Primary centre frequency (MHz) of a [`station_channel`].
pub fn station_frequency_mhz(channel: u8) -> Option<u32> {
    Operating::twenty(channel).center_mhz()
}

/// The [`station_channel`] whose primary centre is `frequency` MHz.
pub fn station_channel_at(frequency: u32) -> Option<u8> {
    if frequency < 2407 || (frequency - 2407) % 5 != 0 {
        return None;
    }
    let channel = u8::try_from((frequency - 2407) / 5).ok()?;
    (station_frequency_mhz(channel) == Some(frequency)).then_some(channel)
}

/// Full-order station rates for 8723AE: CCK 0..3, OFDM 4..11, HT MCS0-7
/// 12..19. Bit `rate` of [`Permission::admitted_rates`] names a rate.
pub const STATION_RATES: [u8; 20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
];

/// Every station rate must be admitted (bits 0..19).
const LEGACY_MASK: u64 = 0xfffff;

struct Curve {
    op: Operating,
    /// CCK, OFDM, HT 1SS curves, indexed by TXAGC.
    output: [[i16; 64]; 3],
}

/// Signed per-board calibration for one 8723AE board.
pub struct Calibration {
    identity: [u8; 32],
    antenna: i16,
    qualified: i16,
    curves: Vec<Curve>,
    authority: Option<Cap<FirmwareBlob, Read>>,
}

impl core::fmt::Debug for Calibration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8723aeCalibration")
            .field("channels", &self.curves.len())
            .finish_non_exhaustive()
    }
}

/// Exact admitted operating point for one board. Private fields: only
/// [`Calibration::permission_for`] can mint one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permission {
    identity: [u8; 32],
    op: Operating,
    /// Admitted TXAGC per full-order rate index (`0..20`); non-station
    /// rates are 0.
    index: [u8; 20],
    /// Rates (bit = full-order rate) holding a measured admitted index.
    admitted: u64,
    /// Admitted EIRP ceiling (quarter dBm).
    eirp: i16,
}

impl Permission {
    /// The admitted primary channel.
    pub fn channel(&self) -> u8 {
        self.op.channel
    }

    /// The admitted width / primary channel.
    pub fn operating(&self) -> Operating {
        self.op
    }

    /// The admitted EIRP ceiling (quarter dBm).
    pub fn eirp_limit_qdbm(&self) -> i16 {
        self.eirp
    }

    /// Admitted TXAGC index for a full-order rate (0 for unadmitted or
    /// non-station rates).
    pub fn index(&self, rate: u8) -> u8 {
        self.index.get(usize::from(rate)).copied().unwrap_or(0)
    }

    /// Whether `rate` (full order) has a measured, admitted TXAGC index:
    /// the only rates a forced descriptor rate or a firmware RA mask
    /// may name.
    pub fn admits(&self, rate: u8) -> bool {
        rate < 64 && self.admitted & (1 << rate) != 0
    }

    /// Bit set of [`Self::admits`].
    pub fn admitted_rates(&self) -> u64 {
        self.admitted
    }

    /// The board identity this permission was minted for.
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

impl Calibration {
    /// Load the board's signed envelope from the trusted registry: v2
    /// first, v1 on `NotFound` — mirroring `rtl8821ae::envelope`.
    pub fn load_registered(factory: &crate::rtlwifi::efuse::Factory) -> Result<Self, Error> {
        let m = factory.mac;
        let name = |version: u8| {
            format!(
                "rtlwifi/rtl8723ae-cal-v{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                version, m[0], m[1], m[2], m[3], m[4], m[5]
            )
        };
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let asset =
            match crate::firmware_asset::load(&authority, &name(2), HEADER + V2_ROWS * ROW, true) {
                Err(narf_firmware::FirmwareError::NotFound) => {
                    crate::firmware_asset::load(&authority, &name(1), HEADER + V1_ROWS * ROW, true)
                }
                other => other,
            }
            .map_err(Error::Firmware)?;
        let mut calibration = Self::from_verified(&asset.bytes, asset.signer, factory)?;
        calibration.authority = Some(asset.cap);
        Ok(calibration)
    }

    /// Verify a candidate envelope against the board: signer present,
    /// NAPC magic, version 1..=2, header 96, total-length match, vendor
    /// `0x10ec`, device `0x8723`, reserved zero fields, identity
    /// (SHA-256 of MAC + logical map) and MAC match, antenna /
    /// qualified ranges, row count, exact length, strictly ordered
    /// rows with known centres, in-range curve values, and no 5 GHz
    /// row (any 5 GHz row is a format failure on this 2.4 GHz part).
    pub(crate) fn from_verified(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        factory: &crate::rtlwifi::efuse::Factory,
    ) -> Result<Self, Error> {
        if signer.is_none() {
            return Err(Error::Unsigned);
        }
        let identity = crate::rtlwifi::radio::factory_identity(factory);
        let version = if bytes.len() >= 6 { half(bytes, 4) } else { 0 };
        let rows = if version == 2 { V2_ROWS } else { V1_ROWS };
        if bytes.len() < HEADER
            || bytes.len() > HEADER + rows * ROW
            || &bytes[..4] != b"NAPC"
            || !(1..=2).contains(&version)
            || half(bytes, 6) != HEADER as u16
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize != bytes.len()
            || half(bytes, 12) != VENDOR
            || half(bytes, 14) != DEVICE
            || bytes[54..56] != [0; 2]
            || half(bytes, 62) != if version == 1 { 20 } else { 0 }
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
            || count > rows
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
            let op = if version == 1 {
                if row[1..4] != [0; 3] {
                    return Err(Error::Format);
                }
                Operating::legacy20(row[0])
            } else {
                // v2 row: primary channel, band, bandwidth, offset.
                // Band must be 0 (2.4 GHz); a 5 GHz row is a format
                // failure on this part.
                if row[1] != 0 {
                    return Err(Error::Format);
                }
                let width = Width::from_key(row[2], row[3]).ok_or(Error::Format)?;
                Operating {
                    width,
                    channel: row[0],
                }
            };
            let key = |o: &Operating| (o.width.key(), o.channel);
            if op.center_mhz().is_none() || previous.is_some_and(|p| key(&p) >= key(&op)) {
                return Err(Error::Format);
            }
            previous = Some(op);
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
            curves.push(Curve { op, output });
        }
        Ok(Self {
            identity,
            antenna,
            qualified,
            curves,
            authority: None,
        })
    }

    /// 20 MHz [`Self::permission_for`] on primary `channel`.
    pub fn permission(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        channel: u8,
    ) -> Result<Permission, Error> {
        self.permission_for(domain, Operating::twenty(channel))
    }

    /// Every operating point the envelope carries a measured row for (no
    /// policy; [`Self::permission_for`] still decides admission).
    pub fn operating_points(&self) -> impl Iterator<Item = Operating> + '_ {
        self.curves.iter().map(|c| c.op)
    }

    /// Whether the envelope carries a measured row for `op` (no policy).
    pub fn measures(&self, op: Operating) -> bool {
        self.curves.iter().any(|c| c.op == op)
    }

    /// The admitted TXAGC per station rate of `op`: the highest measured
    /// index whose output plus antenna gain fits the ceiling (domain
    /// ceiling for the span, capped by the qualified EIRP). A rate with
    /// no fitting measured index stays unadmitted (TXAGC 0, outside
    /// [`Permission::admitted_rates`]); every station rate (CCK + OFDM
    /// + HT MCS0-7) must be admitted or the point is not admitted.
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
        let mut index = [0u8; 20];
        let mut admitted = 0u64;
        for rate in STATION_RATES {
            let bounds = &curve.output[match rate {
                0..=3 => 0,
                4..=11 => 1,
                _ => 2,
            }];
            // No factory per-rate cap exists in-tree for 8723AE (see
            // the module docs): scan the full TXAGC range.
            if let Some(fit) = (0..=63u8).rev().find(|i| {
                let out = bounds[usize::from(*i)];
                out != UNKNOWN && i32::from(out) + i32::from(self.antenna) <= i32::from(eirp)
            }) {
                index[usize::from(rate)] = fit;
                admitted |= 1 << rate;
            }
        }
        if admitted & LEGACY_MASK != LEGACY_MASK {
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

    /// Loader-authority recency, mirroring `rtl8821ae::envelope`: a live
    /// authority must still invoke; inert verified-metadata fixtures
    /// pass under test / kernel-test configuration.
    fn current(&self) -> Result<(), Error> {
        if let Some(cap) = &self.authority {
            return cap.invoke(NoopOp).map_err(|_| Error::Authority);
        }
        #[cfg(any(test, feature = "kernel-test"))]
        return Ok(());
        #[cfg(not(any(test, feature = "kernel-test")))]
        Err(Error::Authority)
    }
}

/// Regulatory ceiling (quarter dBm) for an operating point: the shared
/// 2.4 GHz legacy20 ceiling for 20 MHz points; the spanning-rule
/// ceiling (mirroring `rtl8821ae::envelope::span_ceiling`) for 40 MHz.
fn span_ceiling(
    domain: &narf_wireless::reg::RegulatoryDomain,
    op: Operating,
) -> Result<i16, Error> {
    if op == Operating::legacy20(op.channel) {
        return domain_ceiling(domain, op.channel);
    }
    let center = op.center_mhz().ok_or(Error::Policy)?;
    if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
        return Err(Error::Policy);
    }
    let half = op.width.mhz() / 2;
    let (lower, upper) = (center - half, center + half);
    let mut limit = None;
    for rule in &domain.rules {
        if rule.freq_start_mhz < upper && rule.freq_end_mhz > lower {
            if rule.freq_start_mhz > lower
                || rule.freq_end_mhz < upper
                || rule.max_bandwidth_mhz < op.width.mhz()
                || !rule.flags.is_empty()
            {
                return Err(Error::Policy);
            }
            let ceiling = i16::from(rule.max_power_dbm) * 4;
            limit = Some(limit.map_or(ceiling, |old: i16| old.min(ceiling)));
        }
    }
    limit.ok_or(Error::Policy)
}
