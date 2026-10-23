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
mod table;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Factory {
    /// Linux's sanitized current_rd, retaining its roaming bit.
    pub eeprom: u16,
    pub country: u16,
    pub pair: u16,
    pub ctl_5ghz: u16,
    pub ctl_2ghz: u16,
    pub alpha2: [u8; 2],
}
impl Factory {
    pub fn from_eeprom(value: u32) -> Result<Self, Error> {
        let raw = u16::try_from(value).map_err(|_| Error::Unsupported)?;
        // Linux sanitizes exactly 0x8000 before stripping the roaming bit.
        let eeprom = if raw == 0x8000 { 0x64 } else { raw };
        let domain = eeprom & !0x4000;
        let explicit = if domain & 0x8000 != 0 {
            Some(
                table::COUNTRIES
                    .iter()
                    .find(|c| c.0 == domain & !0x8000)
                    .ok_or(Error::Unsupported)?,
            )
        } else {
            if !table::PAIRS.iter().any(|p| p.0 == domain) {
                return Err(Error::Unsupported);
            }
            None
        };
        let country = explicit.map_or(0, |c| c.0);
        let country = if country == 0 && domain == 0 {
            840
        } else {
            country
        };
        let selected = if country == 0 {
            None
        } else {
            Some(
                table::COUNTRIES
                    .iter()
                    .find(|c| c.0 == country)
                    .ok_or(Error::Unsupported)?,
            )
        };
        let pair = selected.map_or(domain, |c| c.1);
        if pair == 0 {
            return Err(Error::Unsupported);
        }
        let &(_, ctl_5ghz, ctl_2ghz) = table::PAIRS
            .iter()
            .find(|p| p.0 == pair)
            .ok_or(Error::Unsupported)?;
        let alpha2 = selected
            .or_else(|| table::COUNTRIES.iter().find(|c| c.1 == pair))
            .map_or(*b"00", |c| c.2);
        Ok(Self {
            eeprom,
            country,
            pair,
            ctl_5ghz,
            ctl_2ghz,
            alpha2,
        })
    }
}
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
    pub fn from_domain(
        caps: &super::wmi_boot::Capabilities,
        domain: &narf_wireless::reg::RegulatoryDomain,
        frequency: u16,
    ) -> Result<Self, Error> {
        use narf_wireless::reg::RegFlags;
        // Linux's strict initial custom world domain admits 1..11 to
        // initiate radiation; channels requiring beacon-hint/DFS state
        // are not promoted by this first station profile.
        if !(2412..=2462).contains(&frequency)
            || (frequency - 2412) % 5 != 0
            || !domain.country_code.iter().all(u8::is_ascii_uppercase)
            || u32::from(frequency) < caps.low_2ghz
            || u32::from(frequency) > caps.high_2ghz
        {
            return Err(Error::Unsupported);
        }
        let factory = Factory::from_eeprom(caps.eeprom_domain)?;
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
                || r.flags.contains(RegFlags::DFS)
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
        let half_dbm = ceiling.min(20) as u8 * 2;
        Ok(Self {
            factory,
            country: domain.country_code,
            frequency,
            half_dbm,
        })
    }
}
