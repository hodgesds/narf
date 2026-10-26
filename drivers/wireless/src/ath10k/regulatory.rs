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

/// Bound, additional host power ceiling for the initial legacy 20 MHz
/// station profile. Factory CTL and calibration stay active in firmware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Permission {
    pub factory: Factory,
    pub country: [u8; 2],
    pub frequency: u16,
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
        use narf_wireless::reg::RegFlags;
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
        if !(low_band..=high_band).contains(&u32::from(frequency)) {
            return Err(Error::Unsupported);
        }
        let factory = Factory::from_eeprom(caps.eeprom_domain).map_err(|_| Error::Unsupported)?;
        // World 5GHz is NO_IR in Linux ath/regd.c. No beacon-hint or DFS
        // qualification is invented. The wider profile requires a resolved
        // fixed-country factory identity matching the authenticated host DB;
        // immutable factory pair/CTL and target calibration remain active.
        if !two_ghz && (factory.country == 0 || factory.alpha2 != domain.country_code) {
            return Err(Error::Unsupported);
        }
        let center = u32::from(frequency);
        let low = center - 10;
        let high = center + 10;
        let mut covering = false;
        let mut ceiling = None;
        for r in &domain.rules {
            if r.freq_end_mhz <= low || high <= r.freq_start_mhz {
                continue;
            }
            // Any stricter overlapping rule remains restrictive. A second
            // permissive rule cannot erase DFS, narrow bandwidth or power.
            if r.freq_start_mhz >= r.freq_end_mhz
                || r.max_bandwidth_mhz < 20
                || r.flags.intersects(RegFlags::DFS | RegFlags::NO_IR)
                || !two_ghz && r.flags.contains(RegFlags::INDOOR_ONLY)
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
            half_dbm,
        })
    }
}
