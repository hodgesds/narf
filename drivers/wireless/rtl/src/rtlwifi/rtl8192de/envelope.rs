// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE signed per-board power envelopes (NAPC).
//!
//! This mirrors `rtl8723ae::envelope` (and `rtl8723be::envelope`) for
//! the 8192DE: a signed companion file carries the board's measured TX
//! power curves, and only [`Calibration::permission_for`] can mint a
//! [`Permission`] the packet owner may transmit under. Private fields
//! and the signer requirement keep unverified bytes — or another
//! board's calibration — from ever admitting packet transmit.
//!
//! ## 8192DE adaptations (grounded, not invented)
//!
//! - Vendor `0x10ec`, device `0x8193` (`rtl8192de` PCI device id);
//!   file names `rtlwifi/rtl8192de-cal-v2-<mac>.bin` tried before v1,
//!   mirroring the 8821AE loader. v3 (`rtl8192de-cal-v3-<mac>.bin`,
//!   tried first) carries four curves per row on both bands (step 5);
//!   v2/v1 files still load for 2.4 GHz-only boards.
//! - 2.4 GHz rows in v1/v2, both bands in v3. A 5 GHz row is a
//!   [`Error::Format`] failure in v2 (v2 is 2.4 GHz-only); in v3 the
//!   5 GHz row plan is `channel::CHANNEL_ALL` 5 GHz channels at
//!   20 MHz plus the +/-2 pairing at 40 MHz (154 rows total: 25 x
//!   2.4 GHz + 45 + 42 + 42). Channels 12/13/14 are never admitted
//!   (fail-closed: the shared Linux `regd.c` channel 1-11 ceiling in
//!   `channel_power::domain_ceiling` covers 1..=11 only, and the
//!   40 MHz spans of the admitted plan stay inside 2402-2472 MHz).
//!   5 GHz rows leave the CCK curve unmeasured (mirroring rtl8821ae).
//! - Curves are CCK, OFDM, HT 1SS (MCS0-7) and, in v3, HT 2SS
//!   (MCS8-15). The 8192DE is 2T2R in single mode, but the NAPC row
//!   carries one curve set per operating point (not per path, unlike
//!   rtl8192ce); 2SS admission is gated on the function's RF type by
//!   [`super::ht::two_stream`], not by the envelope. v1/v2 rows
//!   carry no 2SS curve, so MCS8-15 stay unadmitted there.
//! - v1 rows: 11 legacy20 channels 1..=11. v2 rows: at most 25 —
//!   11 × 20 MHz + 7 × 40 MHz (offset above, primaries 1..=7) + 7 ×
//!   40 MHz (offset below, primaries 5..=11) — the 8821AE 2.4 GHz row
//!   plan. v3 rows: at most 154 — the v2 plan plus the 5 GHz plan
//!   above. Rows are strictly ordered by (band, bandwidth, offset,
//!   channel): 20 MHz rows first, then 40-above, then 40-below,
//!   band 0 before band 1.
//! - No factory cap: unlike the 8723BE, the 8192DE envelope admits on
//!   measured curves alone — the step-4 DE factory table
//!   (`txpower::linux_indices`) is an upper bound the envelope does
//!   not (yet) apply, so there is no `grant_for` and no channel
//!   `Grant` here — mirroring the 8723AE, whose packet admission is
//!   firmware `Info` + envelope `Permission` alone. Capping envelope
//!   admission by the Linux indices is a later-step design decision,
//!   not part of this step.
//! - No BB swing: the 8821AE `0xc6`/`0xc7` selectors come from
//!   `phy_get_tx_swing_8812A`, an 8812A-specific source with no 8192DE
//!   grounding, so [`Permission`] carries no swing value and the packet
//!   owner never programs swing from the envelope.
//! - Station rates are the 28 full-order rates CCK 0..3, OFDM 4..11,
//!   HT MCS0-7 12..19, HT MCS8-15 20..27. Every 2.4 GHz legacy rate
//!   (CCK + OFDM + MCS0-7) — or every 5 GHz legacy rate (OFDM +
//!   MCS0-7; there is no CCK on 5 GHz) — must be admitted or the
//!   operating point is not admitted ([`Error::NoMeasuredGain`]).
//!   MCS8-15 are never required: a rate with no fitting measured
//!   index stays unadmitted instead of failing the whole permission
//!   (mirroring rtl8821ae partial admission).

use super::channel::CHANNEL_ALL;
use crate::rtlwifi::channel_power::{domain_ceiling, Error};
use alloc::{format, vec::Vec};
use narf_capabilities::{Cap, NoopOp, Read};
use narf_firmware::FirmwareBlob;

/// NAPC header size.
const HEADER: usize = 96;
/// NAPC v1/v2 row size: channel/band/bandwidth/offset + three 64-entry
/// `i16` curves.
const ROW: usize = 4 + 3 * 64 * 2;
/// NAPC v3 row size: channel/band/bandwidth/offset + four 64-entry
/// `i16` curves (CCK, OFDM, MCS0-7, MCS8-15).
const ROW_V3: usize = 4 + 4 * 64 * 2;
/// Maximum NAPC v2 rows for 8192DE 2.4 GHz: 11 × 20 MHz + 7 + 7 × 40 MHz.
pub const V2_ROWS: usize = 25;
/// Maximum NAPC v3 rows: the v2 2.4 GHz plan (25) plus the 5 GHz plan
/// (45 × 20 MHz + 42 × 40 MHz above + 42 × 40 MHz below = 129).
pub const V3_ROWS: usize = 154;
/// Maximum NAPC v1 rows: 11 legacy20 channels.
pub const V1_ROWS: usize = 11;
/// Unmeasured curve entry.
const UNKNOWN: i16 = i16::MAX;
/// PCI vendor ID (Realtek).
const VENDOR: u16 = 0x10ec;
/// PCI device ID (RTL8192DE).
const DEVICE: u16 = 0x8193;

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

    /// Whether this point is on 5 GHz. The DE plan has no channel
    /// numbers between the 2.4 GHz primaries (1..=14) and the 5 GHz
    /// primaries (36..=165), so the band is the channel number.
    pub const fn is_5ghz(self) -> bool {
        self.channel >= 36
    }

    /// Legacy20 alias (the v1 operating point).
    pub const fn legacy20(channel: u8) -> Self {
        Self::twenty(channel)
    }

    /// Centre frequency in MHz, or `None` outside the admitted plan:
    /// 20 MHz primaries 1..=11, 40-above primaries 1..=7, 40-below
    /// primaries 5..=11 on 2.4 GHz; on 5 GHz every
    /// [`CHANNEL_ALL`] 5 GHz channel at 20 MHz, and the +/-2 pairing
    /// at 40 MHz (mirroring `channel::Operating::new`, whose wide
    /// channel is the primary +/-2 and must itself be in the plan).
    pub fn center_mhz(self) -> Option<u32> {
        if self.is_5ghz() {
            if !CHANNEL_ALL.contains(&self.channel) {
                return None;
            }
            let primary = 5000 + u32::from(self.channel) * 5;
            return match self.width {
                Width::W20 => Some(primary),
                Width::W40Above if CHANNEL_ALL.contains(&(self.channel + 2)) => Some(primary + 10),
                Width::W40Below
                    if self.channel >= 2 && CHANNEL_ALL.contains(&(self.channel - 2)) =>
                {
                    Some(primary - 10)
                }
                _ => None,
            };
        }
        let primary = u32::from(self.channel);
        match self.width {
            Width::W20 if (1..=11).contains(&self.channel) => Some(2407 + primary * 5),
            Width::W40Above if (1..=7).contains(&self.channel) => Some(2407 + (primary + 2) * 5),
            Width::W40Below if (5..=11).contains(&self.channel) => Some(2407 + (primary - 2) * 5),
            _ => None,
        }
    }

    /// Whether this point is 40 MHz wide.
    pub const fn forty(self) -> bool {
        !matches!(self.width, Width::W20)
    }

    /// 40 MHz prime sub-carrier (`mac->cur_40_prime_sc`): 0 at
    /// 20 MHz, 1 (lower) for 40-above, 2 (upper) for 40-below.
    pub const fn prime_sc(self) -> u8 {
        match self.width {
            Width::W20 => 0,
            Width::W40Above => 1,
            Width::W40Below => 2,
        }
    }
}

/// Whether `channel` is a station channel (2.4 GHz 1..=11, or a 5 GHz
/// primary in the DE plan).
pub fn station_channel(channel: u8) -> bool {
    Operating::twenty(channel).center_mhz().is_some()
}

/// Primary centre frequency (MHz) of a [`station_channel`].
pub fn station_frequency_mhz(channel: u8) -> Option<u32> {
    Operating::twenty(channel).center_mhz()
}

/// The [`station_channel`] whose primary centre is `frequency` MHz.
pub fn station_channel_at(frequency: u32) -> Option<u8> {
    let base = if frequency >= 5000 { 5000 } else { 2407 };
    if frequency < base || (frequency - base) % 5 != 0 {
        return None;
    }
    let channel = u8::try_from((frequency - base) / 5).ok()?;
    (station_frequency_mhz(channel) == Some(frequency)).then_some(channel)
}

/// Full-order station rates for 8192DE: CCK 0..3, OFDM 4..11,
/// HT MCS0-7 12..19, HT MCS8-15 20..27. Bit `rate` of
/// [`Permission::admitted_rates`] names a rate. 2SS rates (MCS8-15)
/// are station rates only where a v3 row measures them (see
/// [`super::ht::two_stream`]); v1/v2 rows carry no 2SS curve.
pub const STATION_RATES: [u8; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27,
];

/// Every 2.4 GHz station legacy rate must be admitted (bits 0..19:
/// CCK + OFDM + HT MCS0-7).
const LEGACY_MASK: u64 = 0xfffff;
/// Every 5 GHz station legacy rate must be admitted (bits 4..19:
/// OFDM + HT MCS0-7; there is no CCK on 5 GHz).
const LEGACY_MASK_5G: u64 = 0xfff0;

struct Curve {
    op: Operating,
    /// CCK, OFDM, HT 1SS, HT 2SS curves, indexed by TXAGC. The 2SS
    /// curve is all [`UNKNOWN`] on v1/v2 rows, which carry no 2SS
    /// measurement.
    output: [[i16; 64]; 4],
}

/// Signed per-board calibration for one 8192DE board.
pub struct Calibration {
    identity: [u8; 32],
    antenna: i16,
    qualified: i16,
    curves: Vec<Curve>,
    authority: Option<Cap<FirmwareBlob, Read>>,
}

impl core::fmt::Debug for Calibration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8192deCalibration")
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
    /// Admitted TXAGC per full-order rate index (`0..28`); non-station
    /// rates are 0.
    index: [u8; 28],
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
    /// the only rates a forced descriptor rate may name.
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
    /// Load the board's signed envelope from the trusted registry: v3
    /// first, v2 then v1 on `NotFound` — mirroring
    /// `rtl8821ae::envelope`. v3 carries four curves per row on both
    /// bands; v2/v1 stay 2.4 GHz-only.
    pub fn load_registered(factory: &crate::rtlwifi::efuse::Factory) -> Result<Self, Error> {
        let m = factory.mac;
        let name = |version: u8| {
            format!(
                "rtlwifi/rtl8192de-cal-v{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                version, m[0], m[1], m[2], m[3], m[4], m[5]
            )
        };
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let asset = match crate::firmware_asset::load(
            &authority,
            &name(3),
            HEADER + V3_ROWS * ROW_V3,
            true,
        ) {
            Err(narf_firmware::FirmwareError::NotFound) => {
                match crate::firmware_asset::load(
                    &authority,
                    &name(2),
                    HEADER + V2_ROWS * ROW,
                    true,
                ) {
                    Err(narf_firmware::FirmwareError::NotFound) => crate::firmware_asset::load(
                        &authority,
                        &name(1),
                        HEADER + V1_ROWS * ROW,
                        true,
                    ),
                    other => other,
                }
            }
            other => other,
        }
        .map_err(Error::Firmware)?;
        let mut calibration = Self::from_verified(&asset.bytes, asset.signer, factory)?;
        calibration.authority = Some(asset.cap);
        Ok(calibration)
    }

    /// Verify a candidate envelope against the board: signer present,
    /// NAPC magic, version 1..=3, header 96, total-length match, vendor
    /// `0x10ec`, device `0x8193`, reserved zero fields, identity
    /// (SHA-256 of MAC + logical map) and MAC match, antenna /
    /// qualified ranges, row count, exact length, strictly ordered
    /// rows with known centres, in-range curve values, a 5 GHz row
    /// only in v3 and only with an unmeasured CCK curve (v2 is
    /// 2.4 GHz-only; v1 rows are legacy20).
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
        let (rows, row_len) = match version {
            3 => (V3_ROWS, ROW_V3),
            2 => (V2_ROWS, ROW),
            _ => (V1_ROWS, ROW),
        };
        if bytes.len() < HEADER
            || bytes.len() > HEADER + rows * row_len
            || &bytes[..4] != b"NAPC"
            || !(1..=3).contains(&version)
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
            || bytes.len() != HEADER + count * row_len
        {
            return Err(Error::Format);
        }
        let mut curves = Vec::new();
        curves
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        let mut previous: Option<Operating> = None;
        for row in bytes[HEADER..].chunks_exact(row_len) {
            let op = if version == 1 {
                if row[1..4] != [0; 3] {
                    return Err(Error::Format);
                }
                Operating::legacy20(row[0])
            } else if version == 2 {
                // v2 row: primary channel, band, bandwidth, offset.
                // Band must be 0 (2.4 GHz); a 5 GHz row is a format
                // failure in v2 (v2 is 2.4 GHz-only).
                if row[1] != 0 {
                    return Err(Error::Format);
                }
                let width = Width::from_key(row[2], row[3]).ok_or(Error::Format)?;
                Operating {
                    width,
                    channel: row[0],
                }
            } else {
                // v3 row: primary channel, band 0 (2.4 GHz) or 1
                // (5 GHz), bandwidth, offset.
                if row[1] > 1 {
                    return Err(Error::Format);
                }
                let width = Width::from_key(row[2], row[3]).ok_or(Error::Format)?;
                Operating {
                    width,
                    channel: row[0],
                }
            };
            let key = |o: &Operating| (u8::from(o.is_5ghz()), o.width.key(), o.channel);
            // v1/v2 are 2.4 GHz-only: a 5 GHz primary in either is a
            // format failure even with the band byte clear.
            if version != 3 && op.is_5ghz() {
                return Err(Error::Format);
            }
            if op.center_mhz().is_none() || previous.is_some_and(|p| key(&p) >= key(&op)) {
                return Err(Error::Format);
            }
            previous = Some(op);
            let families = if version == 3 { 4 } else { 3 };
            let mut output = [[UNKNOWN; 64]; 4];
            for (curve, out) in output.iter_mut().enumerate().take(families) {
                for (index, v) in out.iter_mut().enumerate() {
                    *v = signed(row, 4 + (curve * 64 + index) * 2);
                    if *v != UNKNOWN && !(-512..=256).contains(v) {
                        return Err(Error::Format);
                    }
                }
            }
            // 5 GHz rows carry no CCK measurement (mirroring
            // rtl8821ae): a measured CCK curve on a 5 GHz row is a
            // format failure.
            if op.is_5ghz() && output[0].iter().any(|v| *v != UNKNOWN) {
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
    /// [`Permission::admitted_rates`]); every legacy rate of the band
    /// (CCK + OFDM + HT MCS0-7 on 2.4 GHz, OFDM + HT MCS0-7 on
    /// 5 GHz) must be admitted or the point is not admitted.
    /// MCS8-15 are never required: they are admitted when the v3 2SS
    /// curve measures them (v1/v2 rows carry no 2SS curve).
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
        let mut index = [0u8; 28];
        let mut admitted = 0u64;
        for rate in STATION_RATES {
            let bounds = &curve.output[match rate {
                0..=3 => 0,
                4..=11 => 1,
                12..=19 => 2,
                _ => 3,
            }];
            if let Some(fit) = (0..=63u8).rev().find(|i| {
                let out = bounds[usize::from(*i)];
                out != UNKNOWN && i32::from(out) + i32::from(self.antenna) <= i32::from(eirp)
            }) {
                index[usize::from(rate)] = fit;
                admitted |= 1 << rate;
            }
        }
        let required = if op.is_5ghz() {
            LEGACY_MASK_5G
        } else {
            LEGACY_MASK
        };
        if admitted & required != required {
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

    /// Run `operation` inside the signed envelope's current firmware-asset
    /// authority (the RTL8192DE `N92D` envelope): a revoked or replaced
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
}

/// `regd.c` EIRP caps (quarter dBm) for a span fully inside one
/// regulatory block (mirroring `rtl8821ae::envelope::regd_cap`).
fn regd_cap(low: u32, high: u32) -> Option<i16> {
    [(2402, 2472, 20), (5140, 5360, 30), (5460, 5860, 30)]
        .into_iter()
        .find(|(lo, hi, _)| *lo <= low && high <= *hi)
        .map(|(_, _, dbm)| dbm * 4)
}

/// Regulatory ceiling (quarter dBm) for an operating point: the shared
/// 2.4 GHz legacy20 ceiling for 2.4 GHz 20 MHz points; the spanning-rule
/// ceiling (mirroring `rtl8821ae::envelope::span_ceiling`) for 40 MHz
/// and for every 5 GHz point, capped by [`regd_cap`]. `domain_ceiling`
/// is 2.4 GHz-only, so a 5 GHz 20 MHz point must not take the
/// legacy20 branch even though its shape matches.
fn span_ceiling(
    domain: &narf_wireless::reg::RegulatoryDomain,
    op: Operating,
) -> Result<i16, Error> {
    if !op.is_5ghz() && op == Operating::legacy20(op.channel) {
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
    let cap = regd_cap(lower, upper).ok_or(Error::Policy)?;
    Ok(limit.ok_or(Error::Policy)?.min(cap))
}
