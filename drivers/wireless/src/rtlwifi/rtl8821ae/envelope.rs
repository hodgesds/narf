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
//!
//! `NAPC` v2 (`rtl8821ae-cal-v2-<mac>.bin`, tried before v1) keeps the v1
//! header with version 2, a row count of 1..=[`V2_ROWS`] and the header
//! bandwidth field 0 (bandwidth is per row). Each row is the same 388 bytes:
//! primary channel, band (0 = 2.4 GHz, 1 = 5 GHz), bandwidth (20/40/80 MHz),
//! secondary offset (0 none, 1 above, 2 below — 40 MHz only), then the same
//! three curves. Rows are strictly ordered by (band, bandwidth, offset,
//! channel). 2.4 GHz rows cover channels 1..=11 at 20 MHz or 40 MHz (offset
//! above for 1..=7, below for 5..=11); 5 GHz rows cover the RTL8821AE
//! channel plan at 20 MHz, 40 MHz with the fixed pairing offset, or 80 MHz
//! inside an 80 MHz block, with the CCK curve wholly unmeasured. The format
//! only carries measurements: a band/bandwidth/channel without a row stays
//! unadmitted, and nothing here supplies any board's values.

use super::txpower::{self, ByRate, Factory as FactoryPower};
use crate::rtlwifi::channel_power::{domain_ceiling, Error};
use crate::rtlwifi::efuse::Factory;
use alloc::{format, vec::Vec};
use narf_capabilities::{Cap, NoopOp, Read};
use narf_firmware::FirmwareBlob;

const HEADER: usize = 96;
const ROW: usize = 4 + 3 * 64 * 2;
/// Maximum `NAPC` v2 rows: 2.4 GHz 11 × 20 MHz + 7 + 7 × 40 MHz, 5 GHz
/// 25 × 20 MHz + 24 × 40 MHz + 24 × 80 MHz.
pub const V2_ROWS: usize = 98;
const UNKNOWN: i16 = i16::MAX;
/// `EEPROM` offset of the 2.4 GHz BB swing selector (`phy_get_tx_swing_8812A`).
pub const EEPROM_SWING_2G: usize = 0xc6;

/// Band of an operating point (`BAND_ON_2_4G` / `BAND_ON_5G`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Band {
    B2g = 0,
    B5g = 1,
}

/// Channel width with the 40 MHz secondary offset (`nl80211_chan_width` +
/// `HT_CHANNEL_WIDTH_*` / `cur_40_prime_sc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Width {
    W20,
    W40Above,
    W40Below,
    W80,
}

impl Width {
    pub fn mhz(self) -> u32 {
        match self {
            Self::W20 => 20,
            Self::W40Above | Self::W40Below => 40,
            Self::W80 => 80,
        }
    }
    fn key(self) -> (u8, u8) {
        match self {
            Self::W20 => (20, 0),
            Self::W40Above => (40, 1),
            Self::W40Below => (40, 2),
            Self::W80 => (80, 0),
        }
    }
    fn from_key(bandwidth: u8, offset: u8) -> Option<Self> {
        Some(match (bandwidth, offset) {
            (20, 0) => Self::W20,
            (40, 1) => Self::W40Above,
            (40, 2) => Self::W40Below,
            (80, 0) => Self::W80,
            _ => return None,
        })
    }
}

/// One operating point a permission is minted for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Operating {
    pub band: Band,
    pub width: Width,
    /// Primary (control) channel.
    pub channel: u8,
}

/// RTL8821AE 5 GHz channel plan (`rtl8821ae` `channel5g`, without the
/// 4.9 GHz/J entries).
pub const CHANNELS_5G: [u8; 25] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
];

impl Operating {
    pub const fn legacy20(channel: u8) -> Self {
        Self {
            band: Band::B2g,
            width: Width::W20,
            channel,
        }
    }

    /// Center frequency (MHz) of the whole channel, or `None` if the
    /// primary channel/width/offset combination is outside the 8821AE plan.
    pub fn center_mhz(&self) -> Option<u32> {
        let ch = self.channel;
        match self.band {
            Band::B2g => {
                let primary = 2407 + u32::from(ch) * 5;
                match self.width {
                    Width::W20 if (1..=11).contains(&ch) => Some(primary),
                    Width::W40Above if (1..=7).contains(&ch) => Some(primary + 10),
                    Width::W40Below if (5..=11).contains(&ch) => Some(primary - 10),
                    _ => None,
                }
            }
            Band::B5g => {
                if !CHANNELS_5G.contains(&ch) {
                    return None;
                }
                let primary = 5000 + u32::from(ch) * 5;
                // 40 MHz pairs (36,40) .. (140,144) and (149,153), (157,161).
                let slot = if ch >= 149 {
                    (ch - 149) / 4
                } else {
                    (ch - 36) / 4
                };
                let above = slot % 2 == 0;
                match self.width {
                    Width::W20 => Some(primary),
                    Width::W40Above if above && ch != 165 => Some(primary + 10),
                    Width::W40Below if !above => Some(primary - 10),
                    Width::W80 if ch != 165 => Some(primary + 30 - u32::from(slot % 4) * 20),
                    _ => None,
                }
            }
        }
    }
}

struct Curve {
    op: Operating,
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

/// Exact admitted operating point (band, width, channel) for one board.
/// Private fields: only [`Calibration::permission`] can mint one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permission {
    identity: [u8; 32],
    op: Operating,
    /// Admitted TXAGC per full-order rate index (`0..48`; non-station rates 0).
    index: [u8; 48],
    /// Rates (bit = full-order rate) holding a measured admitted index.
    admitted: u64,
    swing: u32,
    eirp: i16,
}

impl Permission {
    pub fn channel(&self) -> u8 {
        self.op.channel
    }
    /// The admitted band / width / primary channel.
    pub fn operating(&self) -> Operating {
        self.op
    }
    pub fn eirp_limit_qdbm(&self) -> i16 {
        self.eirp
    }
    /// Admitted TXAGC index for a full-order rate.
    pub fn index(&self, rate: u8) -> u8 {
        self.index.get(usize::from(rate)).copied().unwrap_or(0)
    }
    /// Whether `rate` (full order) has a measured, admitted TXAGC index:
    /// the only rates a forced descriptor rate, an RTS rate or a firmware RA
    /// mask may name.
    pub fn admits(&self, rate: u8) -> bool {
        rate < 64 && self.admitted & (1 << rate) != 0
    }
    /// Bit set of [`Self::admits`].
    pub fn admitted_rates(&self) -> u64 {
        self.admitted
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

    /// Load `rtl8821ae-cal-v2-<mac>.bin`, or `-v1-` when no v2 file exists.
    pub fn load_registered(factory: &Factory) -> Result<Self, Error> {
        let m = factory.mac;
        let name = |version: u8| {
            format!(
                "rtlwifi/rtl8821ae-cal-v{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                version, m[0], m[1], m[2], m[3], m[4], m[5]
            )
        };
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let asset =
            match crate::firmware_asset::load(&authority, &name(2), HEADER + V2_ROWS * ROW, true) {
                Err(narf_firmware::FirmwareError::NotFound) => {
                    crate::firmware_asset::load(&authority, &name(1), HEADER + 11 * ROW, true)
                }
                other => other,
            }
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
        let version = if bytes.len() >= 6 { half(bytes, 4) } else { 0 };
        let rows = if version == 2 { V2_ROWS } else { 11 };
        if bytes.len() < HEADER
            || bytes.len() > HEADER + rows * ROW
            || &bytes[..4] != b"NAPC"
            || !(1..=2).contains(&version)
            || half(bytes, 6) != HEADER as u16
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize != bytes.len()
            || half(bytes, 12) != 0x10ec
            || half(bytes, 14) != 0x8821
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
                let band = match row[1] {
                    0 => Band::B2g,
                    1 => Band::B5g,
                    _ => return Err(Error::Format),
                };
                let width = Width::from_key(row[2], row[3]).ok_or(Error::Format)?;
                Operating {
                    band,
                    width,
                    channel: row[0],
                }
            };
            let key = |o: &Operating| (o.band, o.width.key(), o.channel);
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
                || (op.band == Band::B5g && output[0].iter().any(|v| *v != UNKNOWN))
            {
                return Err(Error::Format);
            }
            curves.push(Curve { op, output });
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

    /// 2.4 GHz 20 MHz [`Self::permission_for`] (the v1 operating point).
    pub fn permission(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        channel: u8,
    ) -> Result<Permission, Error> {
        self.permission_for(domain, Operating::legacy20(channel))
    }

    /// Whether the envelope carries a measured row for `op` (no policy).
    pub fn measures(&self, op: Operating) -> bool {
        self.curves.iter().any(|c| c.op == op)
    }

    /// Linux index for every station rate of `op`, each lowered to the
    /// highest measured index whose output plus antenna gain fits the
    /// ceiling. A rate with no fitting measured index stays unadmitted
    /// (TXAGC 0, outside [`Permission::admitted_rates`]); every legacy rate
    /// of the band (2.4 GHz CCK + OFDM, 5 GHz OFDM) must be admitted.
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
        // The Linux index exists for the 2.4 GHz 20 MHz point only so far;
        // other operating points stay unadmitted until their
        // `_rtl8821ae_get_txpower_index` arithmetic is composed.
        if op != Operating::legacy20(op.channel) {
            return Err(Error::FactoryPower);
        }
        let mut index = [0u8; 48];
        let mut admitted = 0u64;
        for rate in txpower::station_rates() {
            if op.band == Band::B5g && txpower::CCK.contains(&rate) {
                continue;
            }
            let linux = self
                .by_rate
                .index(&self.power, rate, op.channel)
                .map_err(|_| Error::FactoryPower)?;
            let bounds = &curve.output[match rate {
                0..=3 => 0,
                4..=11 => 1,
                _ => 2,
            }];
            if let Some(fit) = (0..=linux).rev().find(|i| {
                let out = bounds[usize::from(*i)];
                out != UNKNOWN && i32::from(out) + i32::from(self.antenna) <= i32::from(eirp)
            }) {
                index[usize::from(rate)] = fit;
                admitted |= 1 << rate;
            }
        }
        let legacy: u64 = match op.band {
            Band::B2g => 0xfff,
            Band::B5g => 0xff0,
        };
        if admitted & legacy != legacy {
            return Err(Error::NoMeasuredGain);
        }
        Ok(Permission {
            identity: self.identity,
            op,
            index,
            admitted,
            swing: self.swing,
            eirp,
        })
    }
}

/// `rtlwifi/regd.c` EIRP cap (quarter dBm) for a whole channel span:
/// `RTL819x_2GHZ_CH01_11` (2402-2472 MHz, 20 dBm), `RTL819x_5GHZ_5150_5350`
/// and `RTL819x_5GHZ_5470_5850` (30 dBm, ±10 MHz as written). A span not
/// wholly inside one of them is refused.
fn regd_cap(low: u32, high: u32) -> Option<i16> {
    [(2402, 2472, 20), (5140, 5360, 30), (5460, 5860, 30)]
        .into_iter()
        .find(|(lo, hi, _)| *lo <= low && high <= *hi)
        .map(|(_, _, dbm)| dbm * 4)
}

/// Host regulatory ceiling (quarter dBm) for the whole span of `op`, as
/// [`domain_ceiling`] for 2.4 GHz 20 MHz: every overlapping rule must cover
/// the full span, allow its bandwidth and carry no flag (DFS / NO_IR /
/// indoor rules are refused); capped by [`regd_cap`].
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
    let cap = regd_cap(lower, upper).ok_or(Error::Policy)?;
    Ok(limit.ok_or(Error::Policy)?.min(cap))
}
