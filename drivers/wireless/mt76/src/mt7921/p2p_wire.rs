//! CONNAC2 native CNM ROC wire protocol (next role-owner batch).
//! Linux mt7921/mcu.c::{mt7921_mcu_set_roc,mt7921_mcu_abort_roc} and
//! mt7921.h::mt7921_roc_grant_tlv. These observations grant no host RF rights.
use super::{channel, firmware_transport::Error};

pub(super) const MAX_DURATION_MS: u32 = 5000; // mt76/mac80211.c::mt76_phy_init
pub(super) const UNIFIED_ROC: u16 = 0x27;
pub(super) const CONNECTION_P2P_CLIENT: u32 = (1 << 17) | 1;
pub(super) const CONNECTION_P2P_GO: u32 = (1 << 17) | 2;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Join,
    Remain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Request {
    bss: u8,
    token: u8,
    channel: u8,
    band: u8,
    duration_ms: u32,
    kind: Kind,
}
impl Request {
    pub fn new(
        bss: u8,
        token: u8,
        frequency_mhz: u32,
        duration_ms: u32,
        kind: Kind,
    ) -> Result<Self, Error> {
        let (band, channel) = match channel::from_frequency(frequency_mhz) {
            Some(channel) => (channel::band(channel).ok_or(Error::Bounds)?, channel),
            None => (
                channel::Band::Ghz6,
                channel::channels_6ghz()
                    .find(|channel| {
                        channel::frequency_in(channel::Band::Ghz6, *channel) == Some(frequency_mhz)
                    })
                    .ok_or(Error::Bounds)?,
            ),
        };
        if bss >= 4 || token == 0 || !(1..=MAX_DURATION_MS).contains(&duration_ms) {
            return Err(Error::Bounds);
        }
        Ok(Self {
            bss,
            token,
            channel,
            band: match band {
                channel::Band::Ghz2 => 1,
                channel::Band::Ghz5 => 2,
                channel::Band::Ghz6 => 3,
            },
            duration_ms,
            kind,
        })
    }
    pub fn token(self) -> u8 {
        self.token
    }
    pub fn acquire(self) -> [u8; 28] {
        let mut out = [0; 28];
        out[6..8].copy_from_slice(&24u16.to_le_bytes());
        out[8] = self.bss;
        out[9] = self.token;
        out[10] = self.channel;
        out[12] = self.band;
        out[14] = self.channel;
        out[17] = self.channel;
        out[19] = u8::from(self.kind == Kind::Remain);
        out[20..24].copy_from_slice(&self.duration_ms.to_le_bytes());
        out[24] = 0xff;
        out
    }
    pub fn abort(self) -> [u8; 16] {
        let mut out = [0; 16];
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        out[6..8].copy_from_slice(&12u16.to_le_bytes());
        out[8] = self.bss;
        out[9] = self.token;
        out[10] = 0xff;
        out
    }
    /// Match the exact unsolicited ROC grant payload after the native
    /// event header. Neither request TX DMA nor abort progress is a grant.
    pub fn grant(self, payload: &[u8]) -> Result<u32, Error> {
        if payload.len() != 24 {
            return Err(Error::MalformedEvent);
        }
        let g = &payload[4..];
        if g[..4] != [0, 0, 20, 0]
            || g[4] != self.bss
            || g[5] != self.token
            || g[6] != 0
            || g[7] != self.channel
            || g[8] != 0
            || g[9] != self.band
            || g[10] != 0
            || g[11] != self.channel
            || g[12] != 0
            || g[13] != u8::from(self.kind == Kind::Remain)
            || !matches!(g[14], 0 | 0xff)
        {
            return Err(Error::MalformedEvent);
        }
        let duration = u32::from_le_bytes(g[16..20].try_into().unwrap());
        if duration == 0 || duration > self.duration_ms {
            return Err(Error::MalformedEvent);
        }
        Ok(duration)
    }
}
