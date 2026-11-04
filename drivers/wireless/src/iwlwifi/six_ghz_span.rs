//! Native contiguous6GHz ownership, including both EHT320 rasters. Linux
//! iwl-nvm-parse.{h,c}, cfg80211 chan.c and mld/phy.c define these facts.
use super::native_band::{Band, Channel};
use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Span {
    pub primary: Channel,
    pub width: u8,
    pub center: u8,
}
impl Span {
    pub fn new(primary: u8, width: u8, center: u8) -> Option<Self> {
        let primary = Channel::six(primary)?;
        if width > 4 || width == 0 && center != primary.number {
            return None;
        }
        if width == 4 {
            if center % 32 != 31 {
                return None;
            }
        } else if width != 0 {
            let block = 4u16 << width;
            let expected = (u16::from(primary.number) - 1) / block * block + block / 2 - 1;
            if expected != u16::from(center) {
                return None;
            }
        }
        let span = Self {
            primary,
            width,
            center,
        };
        let low = i16::from(center) - 2 * ((1i16 << width) - 1);
        let high = i16::from(center) + 2 * ((1i16 << width) - 1);
        if low < 1
            || high > 253
            || !(0..1u8 << width).all(|i| Channel::six((low + 4 * i16::from(i)) as u8).is_some())
            || !span.channels().any(|channel| channel == primary)
        {
            return None;
        }
        Some(span)
    }
    pub fn channels(self) -> impl ExactSizeIterator<Item = Channel> {
        let low = u16::from(self.center) - 2 * ((1u16 << self.width) - 1);
        (0..1u8 << self.width).map(move |i| Channel {
            band: Band::Six,
            number: (low + 4 * u16::from(i)) as u8,
        })
    }
    pub fn mhz(self) -> u32 {
        20u32 << self.width
    }
    pub fn low(self) -> u16 {
        u16::from(self.center) - 2 * ((1u16 << self.width) - 1)
    }
    pub fn contains(self, used: Self) -> bool {
        self.primary == used.primary
            && used.width <= self.width
            && used.low() >= self.low()
            && used.low() + 4 * ((1u16 << used.width) - 1)
                <= self.low() + 4 * ((1u16 << self.width) - 1)
    }
    pub fn nvm_flags(self, local: super::ht_vht::Local) -> Option<u32> {
        let mask = self.channels().try_fold(0u64, |mask, channel| {
            Some(mask | (1u64 << (channel.index()? - 51)))
        })?;
        if local.six_channels[0] & mask != mask
            || (1..=3).contains(&self.width)
                && local.six_widths[usize::from(self.width - 1)] & mask != mask
        {
            return None;
        }
        // There is NO NVM_CHANNEL_320MHZ flag. cfg80211 checks NO_320
        // independently of NO_160; every actual constituent still exists.
        Some(
            1 | if local.six_channels[1] & mask == mask {
                1 << 13
            } else {
                0
            } | if local.six_channels[2] & mask == mask {
                1 << 14
            } else {
                0
            },
        )
    }
    pub fn rule(
        self,
        domain: &RegulatoryDomain,
        nvm_flags: u32,
        firmware: Option<&super::mld_regulatory::Mcc>,
    ) -> Option<RegRule> {
        if self.width == 0 {
            return super::six_ghz_station::rule(domain, self.primary, nvm_flags, firmware);
        }
        let mut flags = 0x6009u32;
        if let Some(mcc) = firmware {
            if !mcc.he_allowed
                || !mcc.widths.permits(self.width)
                || self.width == 4 && !mcc.eht_allowed
            {
                return None;
            }
            for channel in self.channels() {
                let actual = *mcc.channels.get(channel.index()?)?;
                if actual & 9 != 9
                    || actual & 16 != 0
                    || self.width < 4 && actual & (1 << (8 + self.width)) == 0
                {
                    return None;
                }
                flags &= actual;
            }
        }
        let frequency = 5950 + 5 * u32::from(self.center);
        let low = frequency - self.mhz() / 2;
        let high = frequency + self.mhz() / 2;
        let mut result = RegRule {
            freq_start_mhz: low,
            freq_end_mhz: high,
            max_bandwidth_mhz: self.mhz(),
            max_power_dbm: i8::MAX,
            flags: RegFlags::empty(),
        };
        let mut covered = false;
        for rule in domain
            .rules
            .iter()
            .filter(|rule| rule.freq_start_mhz < high && rule.freq_end_mhz > low)
        {
            if rule.freq_end_mhz <= rule.freq_start_mhz
                || rule.max_bandwidth_mhz < self.mhz()
                || rule.flags.contains(RegFlags::NO_IR)
            {
                return None;
            }
            covered |= rule.freq_start_mhz <= low && rule.freq_end_mhz >= high;
            result.max_power_dbm = result.max_power_dbm.min(rule.max_power_dbm);
            result.flags |= rule.flags;
        }
        if nvm_flags & flags & (1 << 13) == 0 {
            result.flags |= RegFlags::NO_6GHZ_VLP_CLIENT;
        }
        if nvm_flags & flags & (1 << 14) == 0 {
            result.flags |= RegFlags::NO_6GHZ_AFC_CLIENT;
        }
        covered.then_some(result)
    }
}
