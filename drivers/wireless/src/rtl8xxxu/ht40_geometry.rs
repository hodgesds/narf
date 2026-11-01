// SPDX-License-Identifier: GPL-2.0-or-later
//! Source HT40 facts, with no radio authority.
use super::Error;
use narf_wireless::reg::RegulatoryDomain;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtl8xxxu) enum PrimaryPosition {
    Lower,
    Upper,
}
/// A valid two-channel geometry is still only data. It proves neither a
/// signed emission envelope nor actual RF/BB programming or receive epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtl8xxxu) struct Geometry {
    primary: u8,
    secondary: u8,
    center: u8,
}
impl Geometry {
    pub(in crate::rtl8xxxu) fn new(primary: u8, secondary: u8) -> Result<Self, Error> {
        if !(1..=13).contains(&primary)
            || !(1..=13).contains(&secondary)
            || primary.abs_diff(secondary) != 4
        {
            return Err(Error::State);
        }
        Ok(Self {
            primary,
            secondary,
            center: ((u16::from(primary) + u16::from(secondary)) / 2) as u8,
        })
    }
    pub(in crate::rtl8xxxu) fn primary(self) -> u8 {
        self.primary
    }
    pub(in crate::rtl8xxxu) fn secondary(self) -> u8 {
        self.secondary
    }
    pub(in crate::rtl8xxxu) fn center(self) -> u8 {
        self.center
    }
    pub(in crate::rtl8xxxu) fn primary_position(self) -> PrimaryPosition {
        if self.primary < self.secondary {
            PrimaryPosition::Lower
        } else {
            PrimaryPosition::Upper
        }
    }
    /// rtl8xxxu_config passes PRIMARY to rtl8188f_set_tx_power, even though
    /// rtl8188eu_config_channel later programs the RF CENTER at primary±2.
    pub(in crate::rtl8xxxu) fn primary_factory_group(self) -> usize {
        match self.primary {
            1..=2 => 0,
            3..=5 => 1,
            6..=8 => 2,
            9..=11 => 3,
            12..=13 => 4,
            _ => unreachable!("Geometry constructor checks the source channel range"),
        }
    }
    pub(in crate::rtl8xxxu) fn occupied_mhz(self) -> (u32, u32) {
        let center = 2407 + u32::from(self.center) * 5;
        (center - 20, center + 20)
    }
    /// The complete occupied40MHz interval must be admitted by current host
    /// facts. A permissive broad rule never hides an overlapping restriction.
    /// This computes a ceiling only; it cannot qualify a measured RF program.
    pub(in crate::rtl8xxxu) fn ceiling(self, domain: &RegulatoryDomain) -> Result<i16, Error> {
        if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Policy);
        }
        let (lower, upper) = self.occupied_mhz();
        let mut ceiling = None;
        for rule in &domain.rules {
            if rule.freq_start_mhz < upper && rule.freq_end_mhz > lower {
                if rule.freq_start_mhz > lower
                    || rule.freq_end_mhz < upper
                    || rule.max_bandwidth_mhz < 40
                    || !rule.flags.is_empty()
                {
                    return Err(Error::Policy);
                }
                let limit = i16::from(rule.max_power_dbm) * 4;
                ceiling = Some(ceiling.map_or(limit, |old: i16| old.min(limit)));
            }
        }
        ceiling.ok_or(Error::Policy)
    }
    pub(in crate::rtl8xxxu) fn binding_bytes(self) -> [u8; 6] {
        [self.primary, 40, 1, 0, self.secondary, self.center]
    }
    /// REG_RESPONSE_RATE_SET0x440 RSR_RSC_BANDWIDTH_40M mask bits21/22.
    pub(in crate::rtl8xxxu) fn response_subchannel(self) -> u32 {
        match self.primary_position() {
            PrimaryPosition::Lower => 1 << 21,
            PrimaryPosition::Upper => 1 << 22,
        }
    }
    /// REG_CCK0_SYSTEM0xa00 CCK0_SIDEBAND bit4.
    pub(in crate::rtl8xxxu) fn cck_sideband(self) -> u32 {
        match self.primary_position() {
            PrimaryPosition::Lower => 0,
            PrimaryPosition::Upper => 1 << 4,
        }
    }
    /// REG_OFDM1_LSTF0xd00 PRIME_CH_LOW/HIGH bits10/11.
    pub(in crate::rtl8xxxu) fn ofdm_prime(self) -> u32 {
        match self.primary_position() {
            PrimaryPosition::Lower => 1 << 10,
            PrimaryPosition::Upper => 1 << 11,
        }
    }
    /// REG_FPGA0_POWER_SAVE0x818 UPPER/LOWER bits27/26. These source names
    /// describe the secondary and intentionally differ from primary position.
    pub(in crate::rtl8xxxu) fn fpga_secondary(self) -> u32 {
        match self.primary_position() {
            PrimaryPosition::Lower => 1 << 27,
            PrimaryPosition::Upper => 1 << 26,
        }
    }
    /// RF6052_MODE_AG0x18: channel mask0x3ff and BW mask0xc00.
    pub(in crate::rtl8xxxu) fn rf_mode(self, prior: u32) -> u32 {
        (prior & !0xfff) | u32::from(self.center) | 0x400
    }
    /// EU TXDESC32/v3 QoS DATA: BW bit25 plus actual primary offset20/21.
    /// The native transmitter still needs its complete live program.
    pub(in crate::rtl8xxxu) fn data_width_bits(self) -> u32 {
        (1 << 25)
            | match self.primary_position() {
                PrimaryPosition::Lower => 1 << 20,
                PrimaryPosition::Upper => 1 << 21,
            }
    }
}
