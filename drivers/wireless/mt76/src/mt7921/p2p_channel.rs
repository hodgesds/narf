//! Receive-only ROC admission. Listening is independent of permission to
//! emit an active probe/action frame; NO_IR/DFS/indoor rules remain RX-only.
use crate::mt7921::{
    channel,
    firmware_transport::{Error, RadioInfo},
};
use narf_wireless::reg::{RegFlags, RegulatoryDomain};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Listen {
    pub frequency_mhz: u32,
    pub band: channel::Band,
    pub channel: u8,
    pub country: [u8; 2],
}
impl Listen {
    pub fn prepare(
        info: RadioInfo,
        domain: &RegulatoryDomain,
        frequency_mhz: u32,
    ) -> Result<Self, Error> {
        let (band, channel) = if let Some(channel) = channel::from_frequency(frequency_mhz) {
            (channel::band(channel).ok_or(Error::Bounds)?, channel)
        } else {
            (
                channel::Band::Ghz6,
                channel::channels_6ghz()
                    .find(|channel| {
                        channel::frequency_in(channel::Band::Ghz6, *channel) == Some(frequency_mhz)
                    })
                    .ok_or(Error::Bounds)?,
            )
        };
        let bit = match band {
            channel::Band::Ghz2 => 1,
            channel::Band::Ghz5 => 2,
            channel::Band::Ghz6 => 4,
        };
        if info.capabilities.phy.bands & bit == 0 {
            return Err(Error::UnsupportedFirmware);
        }
        let listen = Self {
            frequency_mhz,
            band,
            channel,
            country: domain.country_code,
        };
        listen.current(domain)?;
        Ok(listen)
    }
    pub fn current(self, domain: &RegulatoryDomain) -> Result<(), Error> {
        let low = self.frequency_mhz.checked_sub(10).ok_or(Error::Bounds)?;
        let high = self.frequency_mhz.checked_add(10).ok_or(Error::Bounds)?;
        if self.country != domain.country_code
            || !domain.rules.iter().any(|rule| {
                rule.freq_start_mhz <= low
                    && high <= rule.freq_end_mhz
                    && rule.max_bandwidth_mhz >= 20
            })
            || domain
                .rules
                .iter()
                .filter(|rule| rule.freq_start_mhz < high && low < rule.freq_end_mhz)
                .any(|rule| {
                    rule.max_bandwidth_mhz < 20
                        || rule.flags.intersects(RegFlags::NO_P2P)
                        || rule.flags.bits() & !RegFlags::all().bits() != 0
                })
        {
            return Err(Error::Authority);
        }
        // This admits listening only. A caller must obtain a separate
        // actual P2P/occupied-power permission before any host TX.
        Ok(())
    }
}
