// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2008-2009 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! Immutable EEPROM regulatory identity, following Linux ath/regd.c.
//! A country hint or CTL identifier alone never grants host transmit rights.
use super::wmi_runtime::beacon_hints::Receipt;
use super::wmi_runtime::Error;
pub use crate::qualcomm_regulatory::{Factory, FactoryError};
use alloc::sync::Arc;
#[cfg(any(test, feature = "kernel-test"))]
mod tests;

/// Bound, additional host power ceiling for the occupied station channel.
/// station profile. Factory CTL and calibration stay active in firmware.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Permission {
    pub factory: Factory,
    pub country: [u8; 2],
    pub frequency: u16,
    pub center: u16,
    pub secondary: Option<u16>,
    /// The occupied block is the 80 MHz segment containing the primary/
    /// secondary pair (VHT80, VDEV_START `band_center_freq1` = `center`).
    pub width80: bool,
    /// The second granted 80 MHz segment. More than 80 MHz from `center`
    /// it is a noncontiguous 80+80 segment that never fills the gap; exactly
    /// 80 MHz away it is the other half of a contiguous VHT160 channel
    /// (`center160`), whose whole 160 MHz block every overlapping host rule
    /// must allow (`RegulatoryDomain::allows_bandwidth`, AUTO_BW runs).
    pub center2: Option<u16>,
    pub half_dbm: u8,
    /// Occupied 20 MHz constituents under a host DFS rule, as
    /// `beacon_hints::bit` masks. Nonzero only for a station-client receipt
    /// whose radar witness heard the AP there; those rows carry
    /// `WMI_CHAN_FLAG_PASSIVE | WMI_CHAN_FLAG_DFS` (Linux mac.c
    /// `ath10k_update_channel_list`).
    pub radar: u32,
    /// Original native World-layer observation and exact policy/radio scope.
    /// None keeps every existing unhinted constructor conservative.
    pub(super) hint: Option<Arc<Receipt>>,
}
impl Permission {
    pub fn profile_frequency(frequency: u16) -> bool {
        (2412..=2462).contains(&frequency) && (frequency - 2412) % 5 == 0
            || matches!(
                frequency,
                5180 | 5200 | 5220 | 5240 | 5745 | 5765 | 5785 | 5805 | 5825
            )
    }
    /// The 5 GHz radar-inventory centers (UNII-2 ch52–64, UNII-2e ch100–144
    /// as far as the passive hardware inventory lists them). Admitted only
    /// for a station client under a radar `beacon_found` witness.
    pub fn dfs_frequency(frequency: u16) -> bool {
        matches!(frequency, 5260..=5320 | 5500..=5720) && frequency % 20 == 0
    }
    /// Station-client inventory: the non-DFS profile plus radar channels.
    /// AP, off-channel and active-probe paths keep `profile_frequency`.
    pub fn station_frequency(frequency: u16) -> bool {
        Self::profile_frequency(frequency) || Self::dfs_frequency(frequency)
    }
    pub fn from_domain(
        caps: &super::wmi_boot::Capabilities,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frequency: u16,
    ) -> Result<Self, Error> {
        Self::occupied(caps, domain, frequency, None)
    }
    /// The 80 MHz segment center for a profile primary (ch36-48, ch149-161,
    /// and the station-only radar segments ch52-64, ch100-112, ch116-128,
    /// ch132-144); cfg80211 chandef `center_freq1` for VHT80.
    pub fn center80(frequency: u16) -> Option<u16> {
        match frequency {
            5180..=5240 => Some(5210),
            5260..=5320 => Some(5290),
            5500..=5560 => Some(5530),
            5580..=5640 => Some(5610),
            5660..=5720 => Some(5690),
            5745..=5805 => Some(5775),
            _ => None,
        }
    }
    /// Contiguous VHT160 inside the station inventory: for a primary80
    /// segment center, the 160 MHz center and the other 80 MHz half
    /// (IEEE 802.11 VHT160 channels 50 = ch36-64 and 114 = ch100-128, as
    /// `cfg80211_chandef_valid` admits them). Channel 163 (ch149-177) stays
    /// out: ch165-177 are not in the factory/board inventory.
    pub fn center160(center80: u16) -> Option<(u16, u16)> {
        match center80 {
            5210 => Some((5250, 5290)),
            5290 => Some((5250, 5210)),
            5530 => Some((5570, 5610)),
            5610 => Some((5570, 5530)),
            _ => None,
        }
    }
    /// True when `center2` is the adjacent half of a contiguous VHT160
    /// channel rather than a separate 80+80 segment.
    pub fn contiguous160(&self) -> bool {
        self.center2
            .is_some_and(|c2| Self::center160(self.center).is_some_and(|(_, other)| other == c2))
    }
    pub fn occupied(
        caps: &super::wmi_boot::Capabilities,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frequency: u16,
        secondary: Option<u16>,
    ) -> Result<Self, Error> {
        Self::occupied_width(caps, domain, frequency, secondary, false)
    }
    /// Occupied-bandwidth/power receipt for 20, 40 or (`width80`, with the
    /// 40 MHz `secondary` naming the HT pair inside the segment) 80 MHz.
    /// Every overlapping host rule must permit the whole occupied block.
    pub fn occupied_width(
        caps: &super::wmi_boot::Capabilities,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frequency: u16,
        secondary: Option<u16>,
        width80: bool,
    ) -> Result<Self, Error> {
        Self::occupied_width_with_hint(caps, domain, frequency, secondary, width80, None)
    }
    pub(in crate::ath10k) fn occupied_width_with_hint(
        caps: &super::wmi_boot::Capabilities,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frequency: u16,
        secondary: Option<u16>,
        width80: bool,
        hint: Option<Arc<Receipt>>,
    ) -> Result<Self, Error> {
        // Keep the existing inventory: channels1..11 and these non-DFS5GHz
        // centers only. World5GHz additionally needs the original native
        // Beacon receipt below; a hint never extends the hardware inventory.
        if !Self::station_frequency(frequency)
            || !domain.country_code.iter().all(u8::is_ascii_uppercase)
        {
            return Err(Error::Unsupported);
        }
        let two_ghz = frequency < 3000;
        let (low_band, high_band) = if two_ghz {
            (caps.low_2ghz, caps.high_2ghz)
        } else {
            (caps.low_5ghz, caps.high_5ghz)
        };
        let segment = Self::center80(frequency)
            .filter(|_| width80)
            .map(|c| [c - 30, c + 30]);
        if !(low_band..=high_band).contains(&u32::from(frequency))
            || secondary.is_some_and(|s| !(low_band..=high_band).contains(&u32::from(s)))
            || segment.is_some_and(|s| {
                s.iter()
                    .any(|f| !(low_band..=high_band).contains(&u32::from(*f)))
            })
        {
            return Err(Error::Unsupported);
        }
        let factory = Factory::from_eeprom(caps.eeprom_domain).map_err(|_| Error::Unsupported)?;
        match hint {
            Some(hint) => Self::from_factory_width_with_hint(
                factory,
                domain,
                frequency,
                secondary,
                width80,
                Some(hint),
            ),
            None => Self::from_factory_width(factory, domain, frequency, secondary, width80),
        }
    }
    fn from_factory_width(
        factory: Factory,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frequency: u16,
        secondary: Option<u16>,
        width80: bool,
    ) -> Result<Self, Error> {
        Self::from_factory_width_with_hint(factory, domain, frequency, secondary, width80, None)
    }
    fn from_factory_width_with_hint(
        factory: Factory,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frequency: u16,
        secondary: Option<u16>,
        width80: bool,
        hint: Option<Arc<Receipt>>,
    ) -> Result<Self, Error> {
        let two_ghz = frequency < 3000;
        use narf_wireless::reg::RegFlags;
        if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Unsupported);
        }
        if secondary.is_some_and(|s| {
            if two_ghz {
                !Self::profile_frequency(s) || frequency.abs_diff(s) != 20
            } else {
                let low = frequency.min(s);
                !(matches!(
                    (low, frequency.max(s)),
                    (5180, 5200) | (5220, 5240) | (5745, 5765) | (5785, 5805)
                ) || Self::dfs_frequency(low)
                    && Self::dfs_frequency(low + 20)
                    && frequency.max(s) == low + 20
                    && (low - 5180) % 40 == 0)
            }
        }) {
            return Err(Error::Unsupported);
        }
        let center80 = Self::center80(frequency);
        if width80
            && (two_ghz
                || secondary.is_none()
                || center80.is_none()
                || center80 != secondary.and_then(Self::center80))
        {
            return Err(Error::Unsupported);
        }
        let center = match (width80, center80) {
            (true, Some(c)) => c,
            _ => secondary.map_or(frequency, |s| (frequency + s) / 2),
        };
        let width = if width80 {
            80
        } else if secondary.is_some() {
            40
        } else {
            20
        };
        let frequencies = if width80 {
            [center - 30, center - 10, center + 10, center + 30]
        } else {
            [
                frequency,
                secondary.unwrap_or(frequency),
                frequency,
                secondary.unwrap_or(frequency),
            ]
        };
        // Occupied constituents under any overlapping host DFS rule
        // (cfg80211 `IEEE80211_CHAN_RADAR`). Each needs the client's radar
        // `beacon_found` witness; nothing else admits a radar channel.
        let mut radar_frequencies = [0u16; 4];
        let mut radar_count = 0;
        let mut radar = 0u32;
        for f in frequencies {
            let (low, high) = (u32::from(f) - 10, u32::from(f) + 10);
            let dfs = domain.rules.iter().any(|r| {
                r.freq_start_mhz < high && low < r.freq_end_mhz && r.flags.contains(RegFlags::DFS)
            });
            if !dfs || radar_frequencies[..radar_count].contains(&f) {
                continue;
            }
            radar_frequencies[radar_count] = f;
            radar_count += 1;
            radar |= super::wmi_runtime::beacon_hints::bit(f).ok_or(Error::Unsupported)?;
        }
        let radar_frequencies = &radar_frequencies[..radar_count];
        if radar != 0
            && (two_ghz
                || !hint
                    .as_ref()
                    .is_some_and(|h| h.permits_radar(factory, domain, radar_frequencies)))
        {
            return Err(Error::Unsupported);
        }
        let hint = if !two_ghz && factory.country == 0 {
            // Only a typed original native observation can lift the factory
            // World NO_IR layer. No host rule is changed, and a primary
            // beacon cannot fill an unobserved wider occupied channel.
            Some(
                hint.and_then(|h| h.restrict(factory, domain, &frequencies))
                    .ok_or(Error::Unsupported)?,
            )
        } else {
            if !two_ghz && factory.alpha2 != domain.country_code {
                return Err(Error::Unsupported);
            }
            match hint {
                Some(h) if radar != 0 => Some(
                    h.restrict_radar(factory, domain, radar_frequencies)
                        .ok_or(Error::Unsupported)?,
                ),
                _ => None,
            }
        };
        // A host DFS rule (optionally also NO_IR, as wireless-regdb pairs
        // them for some countries) is admissible only under that witness.
        let radar_flags = if radar != 0 {
            RegFlags::DFS | RegFlags::NO_IR
        } else {
            RegFlags::empty()
        };
        let low = u32::from(center) - width / 2;
        let high = u32::from(center) + width / 2;
        let mut covering = false;
        let mut ceiling = None;
        for (index, r) in domain.rules.iter().enumerate() {
            if r.freq_end_mhz <= low || high <= r.freq_start_mhz {
                continue;
            }
            // Any stricter overlapping rule remains restrictive. A second
            // permissive rule cannot erase DFS, narrow bandwidth or power.
            // The usable bandwidth follows cfg80211 `reg_get_max_bandwidth`
            // (AUTO_BW runs, NO_160MHZ), as `handle_channel` applies it.
            if r.freq_start_mhz >= r.freq_end_mhz
                || domain.max_bandwidth(index) < width
                // An indoor-only rule additionally needs the current trusted
                // deployment's explicit installation fact. Neither an AP nor
                // a country hint supplies that fact. Every overlapping row
                // must agree; NO_IR without DFS and unknown restrictions
                // stay closed. NO_IR alongside DFS needs the radar witness.
                || r.flags.contains(RegFlags::INDOOR_ONLY)
                    != r.flags.contains(RegFlags::DEPLOYMENT_INDOOR)
                || r.flags.contains(RegFlags::NO_IR) && !r.flags.contains(RegFlags::DFS)
                || r.flags.bits()
                    & !(RegFlags::NO_P2P
                        | RegFlags::AUTO_BW
                        | RegFlags::NO_160MHZ
                        | RegFlags::INDOOR_ONLY
                        | RegFlags::DEPLOYMENT_INDOOR
                        | radar_flags)
                        .bits()
                    != 0
            {
                return Err(Error::Unsupported);
            }
            covering |= r.freq_start_mhz <= low && high <= r.freq_end_mhz;
            ceiling = Some(ceiling.map_or(r.max_power_dbm, |p: i8| p.min(r.max_power_dbm)));
        }
        if !covering {
            return Err(Error::Unsupported);
        }
        let ceiling = ceiling.ok_or(Error::Unsupported)?;
        // A negative ceiling cannot be represented by this unsigned WMI
        // channel profile. Keep it closed rather than rounding upward.
        if ceiling < 0 {
            return Err(Error::Unsupported);
        }
        let half_dbm = ceiling.min(if two_ghz { 20 } else { 30 }) as u8 * 2;
        Ok(Self {
            factory,
            country: domain.country_code,
            frequency,
            center,
            secondary,
            width80,
            center2: None,
            half_dbm,
            radar,
            hint,
        })
    }
    /// Recheck the chosen immutable factory/frequency receipt against the
    /// current host policy without querying or inventing hardware facts.
    pub fn check(&self, domain: &narf_wireless::reg::RegulatoryDomain) -> Result<(), Error> {
        let mut current = Self::from_factory_width_with_hint(
            self.factory,
            domain,
            self.frequency,
            self.secondary,
            self.width80,
            self.hint.clone(),
        )?;
        if let Some(second) = self.center2 {
            // 802.11 forbids adjacent 80+80 segments, so the distance alone
            // separates a contiguous160 half from a discontiguous segment.
            let contiguous = self.contiguous160();
            if !self.width80
                || !contiguous
                    && (!matches!(second, 5210 | 5775) || second.abs_diff(self.center) <= 80)
            {
                return Err(Error::Unsupported);
            }
            if contiguous {
                let full = u32::from(second.min(self.center)) + 40;
                if !domain.allows_bandwidth(full - 80, full + 80, 160) {
                    return Err(Error::Unsupported);
                }
            }
            let other = Self::from_factory_width_with_hint(
                self.factory,
                domain,
                second - 30,
                Some(second - 10),
                true,
                self.hint.clone(),
            )?;
            current.half_dbm = current.half_dbm.min(other.half_dbm);
            current.radar |= other.radar;
            current.center2 = Some(second);
            current.merge_hint(&other)?;
        }
        if &current != self {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    pub fn discontiguous(
        caps: &super::wmi_boot::Capabilities,
        domain: &narf_wireless::reg::RegulatoryDomain,
        primary: u16,
        secondary: u16,
        center2: u16,
    ) -> Result<Self, Error> {
        Self::discontiguous_with_hint(caps, domain, primary, secondary, center2, None)
    }
    pub(in crate::ath10k) fn discontiguous_with_hint(
        caps: &super::wmi_boot::Capabilities,
        domain: &narf_wireless::reg::RegulatoryDomain,
        primary: u16,
        secondary: u16,
        center2: u16,
        hint: Option<Arc<Receipt>>,
    ) -> Result<Self, Error> {
        let first = Self::occupied_width_with_hint(
            caps,
            domain,
            primary,
            Some(secondary),
            true,
            hint.clone(),
        )?;
        if !matches!(center2, 5210 | 5775) || center2.abs_diff(first.center) <= 80 {
            return Err(Error::Unsupported);
        }
        let other = Self::occupied_width_with_hint(
            caps,
            domain,
            center2 - 30,
            Some(center2 - 10),
            true,
            hint,
        )?;
        first.join(other, domain)
    }
    /// Bind a second 80 MHz receipt as `center2`: the lower power ceiling,
    /// both segments' radar constituents and witnesses, then the full
    /// current-policy recheck (geometry and the 160 MHz block for VHT160).
    fn join(
        mut self,
        other: Self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Self, Error> {
        self.center2 = Some(other.center);
        self.half_dbm = self.half_dbm.min(other.half_dbm);
        self.radar |= other.radar;
        self.merge_hint(&other)?;
        self.check(domain)?;
        Ok(self)
    }
    /// Contiguous VHT160 receipt (cfg80211 `NL80211_CHAN_WIDTH_160`): the
    /// primary80 segment (`primary`/`secondary` the HT40 pair inside it)
    /// plus its adjacent half (`center160`), each an ordinary 80 MHz
    /// receipt — so every radar 20 MHz constituent of either half needs the
    /// client's `beacon_found` witness — and the whole 160 MHz block must
    /// be allowed by every overlapping rule (`allows_bandwidth`).
    pub(in crate::ath10k) fn contiguous160_with_hint(
        caps: &super::wmi_boot::Capabilities,
        domain: &narf_wireless::reg::RegulatoryDomain,
        primary: u16,
        secondary: u16,
        hint: Option<Arc<Receipt>>,
    ) -> Result<Self, Error> {
        let first = Self::occupied_width_with_hint(
            caps,
            domain,
            primary,
            Some(secondary),
            true,
            hint.clone(),
        )?;
        let (_, center2) = Self::center160(first.center).ok_or(Error::Unsupported)?;
        let other = Self::occupied_width_with_hint(
            caps,
            domain,
            center2 - 30,
            Some(center2 - 10),
            true,
            hint,
        )?;
        first.join(other, domain)
    }
    /// Factory-level contiguous VHT160 entry for native observation tests.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn contiguous160_for_test(
        factory: Factory,
        domain: &narf_wireless::reg::RegulatoryDomain,
        primary: u16,
        secondary: u16,
        hint: Option<Arc<Receipt>>,
    ) -> Result<Self, Error> {
        let first = Self::from_factory_width_with_hint(
            factory,
            domain,
            primary,
            Some(secondary),
            true,
            hint.clone(),
        )?;
        let (_, center2) = Self::center160(first.center).ok_or(Error::Unsupported)?;
        let other = Self::from_factory_width_with_hint(
            factory,
            domain,
            center2 - 30,
            Some(center2 - 10),
            true,
            hint,
        )?;
        first.join(other, domain)
    }
    /// Factory-level entry for native observation tests that have no
    /// SERVICE_READY capability fixture.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn factory_with_hint_for_test(
        factory: Factory,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frequency: u16,
        secondary: Option<u16>,
        width80: bool,
        hint: Option<Arc<Receipt>>,
    ) -> Result<Self, Error> {
        Self::from_factory_width_with_hint(factory, domain, frequency, secondary, width80, hint)
    }
    /// The witness of a two-segment receipt. A segment carries one only
    /// when it needs it (radar constituents, or a World factory's NO_IR
    /// layer), so a segment without one contributes nothing: a VHT160 or
    /// 80+80 channel whose one half is radar keeps that half's witness.
    fn merge_hint(&mut self, other: &Self) -> Result<(), Error> {
        self.hint = match (&self.hint, &other.hint) {
            (None, None) => None,
            (Some(a), None) | (None, Some(a)) => Some(a.clone()),
            (Some(a), Some(b)) => Some(a.union(b).ok_or(Error::Unsupported)?),
        };
        Ok(())
    }
}
