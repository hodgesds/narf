//! Actual occupied20MHz management emission and preserved home power rows.
//! This private plan is not a CNM/RF/current-admin grant. Native publication
//! separately retains the real started WDEV and matching channel receipt.
use crate::mt7921::{
    association::{LegacyRate, TxPermission},
    channel,
    firmware_transport::{Error, RadioInfo},
};
use alloc::{vec, vec::Vec};
use narf_wireless::reg::{RegFlags, RegulatoryDomain};
#[derive(Clone, Copy, Debug)]
pub(super) struct Plan {
    pub emit: TxPermission,
    pub home: Option<TxPermission>,
    pub frequency_mhz: u32,
    pub rate: LegacyRate,
}
impl Plan {
    pub fn prepare(
        info: RadioInfo,
        domain: &RegulatoryDomain,
        frequency_mhz: u32,
        home: Option<TxPermission>,
        no_cck: bool,
    ) -> Result<Self, Error> {
        let number = channel::from_frequency(frequency_mhz).ok_or(Error::UnsupportedFirmware)?;
        let band = channel::band(number).ok_or(Error::Bounds)?;
        if info.capabilities.phy.bands & band.capability() == 0 {
            return Err(Error::UnsupportedFirmware);
        }
        let mut emit = TxPermission::from_domain(domain, number).ok_or(Error::Authority)?;
        if let Some(home) = home {
            if !home.current(domain) || home.country != emit.country {
                return Err(Error::Authority);
            }
            if home.band() == emit.band() && home.channels().contains(&number) {
                // As in retained associated active scans, a20MHz row must
                // never raise a live40/80/160MHz occupied-channel ceiling.
                emit.power_dbm = emit.power_dbm.min(home.power_dbm);
            }
        }
        let rate = if band == channel::Band::Ghz2 && !no_cck {
            LegacyRate::ONE_MBPS
        } else {
            LegacyRate::SIX_MBPS
        };
        let plan = Self {
            emit,
            home,
            frequency_mhz,
            rate,
        };
        if !plan.current(domain) {
            return Err(Error::Authority);
        }
        plan.rows(info)?;
        Ok(plan)
    }
    pub fn current(self, domain: &RegulatoryDomain) -> bool {
        self.emit.current(domain)
            && !domain.rules.iter().any(|rule| {
                rule.freq_start_mhz < self.frequency_mhz + 10
                    && self.frequency_mhz - 10 < rule.freq_end_mhz
                    && rule.flags.contains(RegFlags::NO_P2P)
            })
            && self.home.is_none_or(|permission| {
                permission.current(domain) && permission.country == self.emit.country
            })
    }
    pub fn rows(self, info: RadioInfo) -> Result<Vec<Vec<u8>>, Error> {
        let mut rows = Vec::new();
        if let Some(home) = self.home {
            rows.push(
                home.rate_limits_for_paths(info.capabilities.phy.spatial_streams)
                    .ok_or(Error::Bounds)?,
            );
        }
        rows.push(
            self.emit
                .rate_limits_for_paths(info.capabilities.phy.spatial_streams)
                .ok_or(Error::Bounds)?,
        );
        // Stable order keeps the full home width before any overlapping
        // clipped management row; last_msg ends exactly this native batch.
        rows.sort_by_key(|row| row[5]);
        let count = rows.len();
        for (index, row) in rows.iter_mut().enumerate() {
            row[6] = u8::from(index + 1 == count);
        }
        Ok(rows)
    }
    pub fn domain(self, info: RadioInfo) -> Result<Vec<u8>, Error> {
        let emit_band = self.emit.band().ok_or(Error::Bounds)?;
        let mut domain = super::scan::occupied_domain(
            info,
            self.home.unwrap_or(self.emit),
            self.home.is_some_and(|p| p.six.is_some()),
        )?;
        let mut offset = 12;
        for band in [
            channel::Band::Ghz2,
            channel::Band::Ghz5,
            channel::Band::Ghz6,
        ] {
            let count = domain[7 + usize::from(band.scan_tag())];
            for _ in 0..count {
                let number = u16::from_le_bytes([domain[offset], domain[offset + 1]]);
                if band == emit_band
                    && channel::frequency_in(band, number as u8) == Some(self.frequency_mhz)
                {
                    domain[offset + 4..offset + 8].fill(0);
                }
                offset += 8;
            }
        }
        Ok(domain)
    }
    pub fn home_rows(self, info: RadioInfo) -> Result<Vec<Vec<u8>>, Error> {
        self.home.map_or_else(
            || Ok(Vec::new()),
            |home| {
                home.rate_limits_for_paths(info.capabilities.phy.spatial_streams)
                    .map(|row| vec![row])
                    .ok_or(Error::Bounds)
            },
        )
    }
}
