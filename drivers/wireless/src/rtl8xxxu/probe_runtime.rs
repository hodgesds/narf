// SPDX-License-Identifier: GPL-2.0-or-later
//! Prepared software-scan Probe Requests, separate from peer management TX.
//! Linux mac80211/scan.c::ieee80211_send_scan_probe_req and util.c builder;
//! rtl8xxxu/core.c advertises max_scan_ssids=1.
use super::receive_runtime::Error;
use alloc::vec::Vec;

pub(super) const MAX_IE: usize = 2048;
// Conservative millisecond ceiling of mac80211 scan.c HZ/33 windows.
pub(super) const PROBE_DELAY_MS: u64 = 31;
pub(super) const CHANNEL_TIME_MS: u64 = 31;
/// Only this checked constructor can prepare broadcast management for the
/// private native emitter. It grants no radio or power authority.
pub(super) struct Prepared {
    own: [u8; 6],
    channel: u8,
    ht: bool,
    bytes: Vec<u8>,
}
impl Prepared {
    pub(super) fn new(
        own: [u8; 6],
        channel: u8,
        ssid: &[u8],
        sequence: u16,
        ht: bool,
        extra: &[u8],
    ) -> Result<Self, Error> {
        if own == [0; 6]
            || own[0] & 1 != 0
            || !(1..=13).contains(&channel)
            || ssid.len() > 32
            || sequence > 4095
            || ht && channel != 1
            || extra.len() > MAX_IE
        {
            return Err(Error::State);
        }
        let mut at = extra;
        while !at.is_empty() {
            let head = at.get(..2).ok_or(Error::State)?;
            let length = 2 + usize::from(head[1]);
            if at.len() < length || matches!(head[0], 0 | 1 | 3 | 45 | 50 | 61 | 191 | 192 | 255) {
                return Err(Error::State);
            }
            at = &at[length..];
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(100 + ssid.len() + extra.len())
            .map_err(|_| Error::State)?;
        bytes.extend_from_slice(&[0x40, 0, 0, 0]);
        bytes.extend_from_slice(&[255; 6]);
        bytes.extend_from_slice(&own);
        bytes.extend_from_slice(&[255; 6]);
        bytes.extend_from_slice(&(sequence << 4).to_le_bytes());
        bytes.extend_from_slice(&[0, ssid.len() as u8]);
        bytes.extend_from_slice(ssid);
        bytes.extend_from_slice(&[1, 8, 2, 4, 11, 22, 12, 18, 24, 36]);
        bytes.extend_from_slice(&[50, 4, 48, 72, 96, 108]);
        bytes.extend_from_slice(&[3, 1, channel]);
        if ht {
            bytes.extend_from_slice(&[45, 26]);
            bytes.extend_from_slice(
                &narf_wireless::association::phy::LocalHt::siso20(false, false).capability_body(),
            );
        }
        bytes.extend_from_slice(extra);
        Ok(Self {
            own,
            channel,
            ht,
            bytes,
        })
    }
    pub(super) fn matches(&self, own: [u8; 6], channel: u8, ht: bool) -> bool {
        self.own == own && self.channel == channel && self.ht == ht
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn timing(&self, requested_ms: u64, mandatory: bool) -> Result<(u64, u64), Error> {
        // mac80211/util.c::ieee80211_frame_duration: long-preamble CCK1,
        // 10us SIFS +144us preamble +48us PLCP +8*(MPDU+FCS) at1Mbps.
        // This is a minimum emission envelope, not ACK/CCA/drain evidence.
        let airtime_us = 202 + 8 * (self.bytes.len() as u64 + 4);
        let minimum_post = CHANNEL_TIME_MS.max(airtime_us.div_ceil(1000));
        let minimum = PROBE_DELAY_MS + minimum_post;
        if mandatory && requested_ms < minimum {
            return Err(Error::State);
        }
        Ok((PROBE_DELAY_MS, requested_ms.max(minimum) - PROBE_DELAY_MS))
    }
}
