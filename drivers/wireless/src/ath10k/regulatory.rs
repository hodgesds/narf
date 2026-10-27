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
use super::wmi_runtime::Error;
pub use crate::qualcomm_regulatory::{Factory, FactoryError};
#[cfg(any(test, feature = "kernel-test"))]
mod tests;

/// Bound, additional host power ceiling for the occupied station channel.
/// station profile. Factory CTL and calibration stay active in firmware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Permission {
    pub factory: Factory,
    pub country: [u8; 2],
    pub frequency: u16,
    pub center: u16,
    pub secondary: Option<u16>,
    pub half_dbm: u8,
}
impl Permission {
    pub fn profile_frequency(frequency: u16) -> bool {
        (2412..=2462).contains(&frequency) && (frequency - 2412) % 5 == 0
            || matches!(
                frequency,
                5180 | 5200 | 5220 | 5240 | 5745 | 5765 | 5785 | 5805 | 5825
            )
    }
    pub fn from_domain(
        caps: &super::wmi_boot::Capabilities,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frequency: u16,
    ) -> Result<Self, Error> {
        Self::occupied(caps, domain, frequency, None)
    }
    pub fn occupied(
        caps: &super::wmi_boot::Capabilities,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frequency: u16,
        secondary: Option<u16>,
    ) -> Result<Self, Error> {
        // Linux's strict initial custom world domain admits 1..11 to
        // initiate radiation; channels requiring beacon-hint/DFS state
        // are not promoted by this first station profile.
        if !Self::profile_frequency(frequency)
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
        if !(low_band..=high_band).contains(&u32::from(frequency))
            || secondary.is_some_and(|s| !(low_band..=high_band).contains(&u32::from(s)))
        {
            return Err(Error::Unsupported);
        }
        let factory = Factory::from_eeprom(caps.eeprom_domain).map_err(|_| Error::Unsupported)?;
        Self::from_factory(factory, domain, frequency, secondary)
    }
    fn from_factory(
        factory: Factory,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frequency: u16,
        secondary: Option<u16>,
    ) -> Result<Self, Error> {
        let two_ghz = frequency < 3000;
        use narf_wireless::reg::RegFlags;
        if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Unsupported);
        }
        // World 5GHz is NO_IR in Linux ath/regd.c. No beacon-hint or DFS
        // qualification is invented. The wider profile requires a resolved
        // fixed-country factory identity matching the authenticated host DB;
        // immutable factory pair/CTL and target calibration remain active.
        if !two_ghz && (factory.country == 0 || factory.alpha2 != domain.country_code) {
            return Err(Error::Unsupported);
        }
        if secondary.is_some_and(|s| {
            !matches!(
                (frequency.min(s), frequency.max(s)),
                (5180, 5200) | (5220, 5240) | (5745, 5765) | (5785, 5805)
            )
        }) {
            return Err(Error::Unsupported);
        }
        let center = secondary.map_or(frequency, |s| (frequency + s) / 2);
        let width = if secondary.is_some() { 40 } else { 20 };
        let low = u32::from(center) - width / 2;
        let high = u32::from(center) + width / 2;
        let mut covering = false;
        let mut ceiling = None;
        for r in &domain.rules {
            if r.freq_end_mhz <= low || high <= r.freq_start_mhz {
                continue;
            }
            // Any stricter overlapping rule remains restrictive. A second
            // permissive rule cannot erase DFS, narrow bandwidth or power.
            if r.freq_start_mhz >= r.freq_end_mhz
                || r.max_bandwidth_mhz < width
                // This STA profile has no DFS/indoor qualification. NO_P2P
                // does not restrict STA; unknown future restrictions are not
                // silently promoted by a second permissive overlapping row.
                || r.flags.bits() & !RegFlags::NO_P2P.bits() != 0
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
            half_dbm,
        })
    }
    /// Recheck the chosen immutable factory/frequency receipt against the
    /// current host policy without querying or inventing hardware facts.
    pub fn check(self, domain: &narf_wireless::reg::RegulatoryDomain) -> Result<(), Error> {
        if Self::from_factory(self.factory, domain, self.frequency, self.secondary)? != self {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}
