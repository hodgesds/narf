// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact AR9285 primary/extension/RF centers (Linux hw.c). Geometry is only
//! a source fact; full-program qualification and actual calibration grant RF.
use super::identity::BringUpError;
use narf_wireless::reg::{RegFlags, RegulatoryDomain};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Width {
    Twenty,
    FortyAbove,
    FortyBelow,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Geometry {
    primary: u8,
    width: Width,
}
impl Geometry {
    pub(super) fn new(primary: u8, width: Width) -> Result<Self, BringUpError> {
        if !(1..=13).contains(&primary)
            || width == Width::FortyAbove && primary > 9
            || width == Width::FortyBelow && primary < 5
        {
            return Err(BringUpError::Policy);
        }
        Ok(Self { primary, width })
    }
    pub(super) fn from_frequency(frequency: u16) -> Result<Self, BringUpError> {
        if !(2412..=2472).contains(&frequency) || (frequency - 2412) % 5 != 0 {
            return Err(BringUpError::Policy);
        }
        Self::new(((frequency - 2407) / 5) as u8, Width::Twenty)
    }
    pub(super) fn primary(self) -> u8 {
        self.primary
    }
    pub(super) fn is_wide(self) -> bool {
        self.width != Width::Twenty
    }
    pub(super) fn control(self) -> u16 {
        2407 + u16::from(self.primary) * 5
    }
    pub(super) fn center(self) -> u16 {
        match self.width {
            Width::Twenty => self.control(),
            Width::FortyAbove => self.control() + 10,
            Width::FortyBelow => self.control() - 10,
        }
    }
    pub(super) fn extension(self) -> u16 {
        match self.width {
            Width::Twenty => self.control(),
            Width::FortyAbove => self.control() + 20,
            Width::FortyBelow => self.control() - 20,
        }
    }
    pub(super) fn secondary(self) -> Option<u8> {
        match self.width {
            Width::Twenty => None,
            Width::FortyAbove => Some(self.primary + 4),
            Width::FortyBelow => Some(self.primary - 4),
        }
    }
    pub(super) fn twenty(self) -> Self {
        Self {
            width: Width::Twenty,
            ..self
        }
    }
    pub(super) fn span(self) -> (u32, u32) {
        let half = if self.is_wide() { 20 } else { 10 };
        (
            u32::from(self.center()) - half,
            u32::from(self.center()) + half,
        )
    }
    pub(super) fn turbo(self) -> u32 {
        // AR_PHY_FC_HT_EN|SHORT_GI_40|SINGLE_HT_LTF1|WALSH, preserving
        // DAC_FIFO separately. HT40+ sets PRI_CH; never infer from RF center.
        0x3c0
            | match self.width {
                Width::Twenty => 0,
                Width::FortyAbove => 0x14,
                Width::FortyBelow => 4,
            }
    }
    pub(super) fn ht_duration(self, short_gi: bool, air: usize, mcs: u8) -> Option<u32> {
        if mcs > 7 || air > 8191 || short_gi && !self.is_wide() {
            return None;
        }
        let bits = if self.is_wide() {
            [54, 108, 162, 216, 324, 432, 486, 540]
        } else {
            [26, 52, 78, 104, 156, 208, 234, 260]
        };
        let symbols = (u32::try_from(air).ok()? * 8 + 22).div_ceil(bits[usize::from(mcs)]);
        Some(
            36 + if short_gi {
                (symbols * 18).div_ceil(5)
            } else {
                symbols * 4
            },
        )
    }
    pub(super) fn body(self) -> [u8; 4] {
        [
            self.primary,
            if self.is_wide() { 40 } else { 20 },
            self.secondary().unwrap_or(0),
            match self.width {
                Width::Twenty => 0,
                Width::FortyAbove => 1,
                Width::FortyBelow => 3,
            },
        ]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Permission {
    pub(super) country: [u8; 2],
    pub(super) ceiling: u8,
    pub(super) geometry: Geometry,
}
impl Permission {
    pub(super) fn from_domain(
        domain: &RegulatoryDomain,
        geometry: Geometry,
    ) -> Result<Self, BringUpError> {
        if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(BringUpError::Policy);
        }
        let (lower, upper) = geometry.span();
        let mut covered = false;
        let mut ceiling = 20;
        for rule in &domain.rules {
            if rule.freq_start_mhz >= upper || rule.freq_end_mhz <= lower {
                continue;
            }
            if rule.max_bandwidth_mhz < if geometry.is_wide() { 40 } else { 20 }
                || rule.max_power_dbm < 0
                || rule
                    .flags
                    .intersects(RegFlags::DFS | RegFlags::INDOOR_ONLY | RegFlags::NO_IR)
            {
                return Err(BringUpError::Policy);
            }
            ceiling = ceiling.min(rule.max_power_dbm);
            covered |= rule.freq_start_mhz <= lower && rule.freq_end_mhz >= upper;
        }
        if !covered {
            return Err(BringUpError::Policy);
        }
        Ok(Self {
            country: domain.country_code,
            ceiling: ceiling as u8 * 2,
            geometry,
        })
    }
    pub(super) fn current_in(self, domain: &RegulatoryDomain) -> bool {
        Self::from_domain(domain, self.geometry)
            .is_ok_and(|p| p.country == self.country && p.ceiling >= self.ceiling)
    }
}
