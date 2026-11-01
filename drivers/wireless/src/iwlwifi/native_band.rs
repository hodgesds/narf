//! Native NVM/UMAC/RFH band identity. Channel numbers alone are ambiguous.
//! Linux iwl-nvm-parse.c and fw/api/{phy,rx,scan}.h: PHY bands 5=0,24=1,6=2.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Band {
    Five = 0,
    Two = 1,
    Six = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Channel {
    pub band: Band,
    pub number: u8,
}
impl Channel {
    pub fn legacy(number: u8) -> Option<Self> {
        super::station_api::channel_index(number).map(|_| Self {
            band: if number <= 14 { Band::Two } else { Band::Five },
            number,
        })
    }
    pub fn six(number: u8) -> Option<Self> {
        // Shared channel::Band currently admits through 233. The NVMv5
        // UNII-9 entries 237..253 remain unavailable, not aliased to 5GHz.
        (number <= 233 && number % 4 == 1).then_some(Self {
            band: Band::Six,
            number,
        })
    }
    pub fn from_frequency(number: u8, mhz: u32) -> Option<Self> {
        [Self::legacy(number), Self::six(number)]
            .into_iter()
            .flatten()
            .find(|channel| channel.frequency() == mhz)
    }
    pub fn frequency(self) -> u32 {
        match self.band {
            Band::Two if self.number == 14 => 2484,
            Band::Two => 2407 + 5 * u32::from(self.number),
            Band::Five => 5000 + 5 * u32::from(self.number),
            Band::Six => 5950 + 5 * u32::from(self.number),
        }
    }
    pub fn index(self) -> Option<usize> {
        match self.band {
            Band::Six => Self::six(self.number).map(|_| 51 + usize::from(self.number / 4)),
            _ => Self::legacy(self.number)
                .filter(|channel| channel.band == self.band)
                .and_then(|_| super::station_api::channel_index(self.number)),
        }
    }
    /// A copied6GHz descriptor always needs its actual band and the
    /// owner's retained band-in-RX contract. Older2.4/5GHz native profiles
    /// retain their existing numeric channel interpretation.
    pub fn received(number: u8, raw_band: u8, band_in_rx: bool) -> Option<Self> {
        match raw_band {
            2 if band_in_rx => Self::six(number),
            2 | 3 => None,
            _ => Self::legacy(number),
        }
    }
}
