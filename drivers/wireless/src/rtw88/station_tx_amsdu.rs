// SPDX-License-Identifier: GPL-2.0-or-later
//! 5GHz TX A-MSDU producer: mac80211 `tx.c::ieee80211_amsdu_aggregate`
//! (`TX_AMSDU`, `SUPPORTS_AMSDU_IN_AMPDU` set by `main.c::rtw_register_hw`
//! for C21/C22 `amsdu_in_ampdu`) gated by
//! `mac80211.c::rtw_ops_can_aggregate_in_amsdu`, which declines on 2.4GHz.
//! Aggregation never grants PHY, BA, key or queue authority: every frame is
//! still admitted by the current profile, BA owner and native queue credit.
use super::*;
use narf_wireless::amsdu::Limit;

/// Ethernet frames considered for one aggregate (the interface FIFO prefix).
pub(super) const PREFIX: usize = 8;
/// QoS header plus CCMP header and MIC around a protected A-MSDU body.
const PROTECTED: usize = 26 + 8 + 8;

/// `fw.c::get_max_amsdu_len` (`sta->deflink.agg.max_rc_amsdu_len`) for a
/// `cfg80211_calculate_bitrate` result in 100kbps units; 0 is unlimited.
pub(super) fn max_rc_amsdu_len(bit_rate: u32) -> usize {
    match bit_rate {
        0..550 => 1,
        550..1800 => 1200,
        1800..4000 => 2600,
        4000..7000 => 3500,
        _ => 0,
    }
}

/// `fw.c::rtw_fw_ra_report_iter` bit rate (100kbps) of a C2H RA report
/// (`C2H_RA_RPT` 0x0c, `c2h_ra_report_size` 7 so `bw` is always present,
/// mac_id 0): `rate_sgi`, `bw`, `rtw_desc_to_bitrate` /
/// `rtw_desc_to_mcsrate` and `cfg80211_calculate_bitrate_{ht,vht}`.
pub(super) fn ra_report_bitrate(body: &[u8]) -> Option<u32> {
    const LEGACY: [u32; 12] = [10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540];
    const VHT: [[u32; 10]; 3] = [
        [
            6500000, 13000000, 19500000, 26000000, 39000000, 52000000, 58500000, 65000000,
            78000000, 86700000,
        ],
        [
            13500000, 27000000, 40500000, 54000000, 81000000, 108000000, 121500000, 135000000,
            162000000, 180000000,
        ],
        [
            29300000, 58500000, 87800000, 117000000, 175500000, 234000000, 263300000, 292500000,
            351000000, 390000000,
        ],
    ];
    if body.len() < 2 + 7 || body[0] != 0x0c || body[3] != 0 {
        return None;
    }
    let rate = body[2] & 0x7f;
    let sgi = body[2] & 0x80 != 0;
    let bw = body[8];
    if bw > 2 && rate >= 12 {
        return None;
    }
    let short = |b: u32| if sgi { b / 9 * 10 } else { b };
    match rate {
        0..12 => Some(LEGACY[usize::from(rate)]),
        // DESC_RATEMCS0..MCS31: `cfg80211_calculate_bitrate_ht`.
        12..44 => {
            let mcs = u32::from(rate - 12);
            let m = mcs & 7;
            let base = if bw == 1 { 13500000 } else { 6500000 };
            let factor = if m < 4 {
                m + 1
            } else if m == 4 {
                m + 2
            } else {
                m + 3
            };
            Some((short(base * factor * ((mcs >> 3) + 1)) + 50000) / 100000)
        }
        // DESC_RATEVHT1SS_MCS0 0x2c .. VHT2SS_MCS9 0x3f.
        0x2c..0x40 => {
            let nss = u32::from(rate - 0x2c) / 10 + 1;
            let mcs = usize::from(rate - 0x2c) % 10;
            Some((short(VHT[usize::from(bw)][mcs] * nss) + 50000) / 100000)
        }
        _ => None,
    }
}

impl State {
    /// `rtw_ops_can_aggregate_in_amsdu` (5GHz) on an HT/VHT QoS association
    /// with a negotiated peer, and the peer's A-MSDU size
    /// (`ht.c`/`vht.c` `agg.max_amsdu_len`: the VHT maximum MPDU length on
    /// a VHT association, else HT capability bit11).
    pub(super) fn amsdu_limit(&self) -> Option<Limit> {
        let p = self.data_profile;
        if self.peer.is_none() || !p.band5 || !p.qos || p.mcs == 0 || self.ht.is_none() {
            return None;
        }
        let phy = self.plan.as_ref().and_then(JoinPlan::negotiated_phy)?;
        if p.vht.is_some() {
            phy.vht()
                .and_then(|v| Limit::from_vht_capability(v.peer_capability()))
        } else {
            Some(Limit::from_ht_capability(phy.ht().peer_capability()))
        }
    }
    /// Largest A-MSDU body for `tid`: the peer limit, the retained native TX
    /// allocation (`MAX_TX_MPDU`) and `max_rc_amsdu_len` from the latest RA
    /// report; `None` when `tid` may not aggregate (`IEEE80211_TXQ_NO_AMSDU`).
    fn amsdu_body(&self, tid: u8) -> Option<(Limit, usize)> {
        let limit = self.amsdu_limit()?;
        if !self.tx_ba.amsdu_allowed(tid) {
            return None;
        }
        let mut body = limit
            .bytes()
            .min(super::super::packet_format::MAX_TX_MPDU - PROTECTED);
        if self.amsdu_rc != 0 {
            body = body.min(self.amsdu_rc);
        }
        Some((limit, body))
    }
    /// The interface may hand `send_batch` an aggregation prefix.
    pub(in crate::rtw88) fn amsdu_ready(&self) -> bool {
        self.ready() && self.amsdu_limit().is_some()
    }
    /// Track `max_rc_amsdu_len` from a firmware RA report.
    pub(super) fn amsdu_ra_report(&mut self, body: &[u8]) {
        if let Some(rate) = ra_report_bitrate(body) {
            self.amsdu_rc = max_rc_amsdu_len(rate);
        }
    }
    fn mpdu_length(&self, body: usize) -> usize {
        body + if self.security.is_some() {
            PROTECTED
        } else {
            26
        }
    }
    /// The longest same-TID admitted prefix of `frames` (at least two) that
    /// encodes within the body bound, and its MPDU length. No sequence or PN
    /// is consumed.
    pub(super) fn amsdu_prefix(
        &self,
        frames: &[&[u8]],
        tid: u8,
        fits: impl Fn(usize) -> bool,
    ) -> Option<(usize, usize)> {
        let (limit, maximum) = self.amsdu_body(tid)?;
        let mut best = None;
        for end in 2..=frames.len().min(PREFIX) {
            let last = frames[end - 1];
            if !admitted(last, self.own) || self.data_tid(last) != tid {
                break;
            }
            let Ok(body) = narf_wireless::amsdu::encode(&frames[..end], self.own, limit) else {
                break;
            };
            let length = self.mpdu_length(body.len());
            if body.len() > maximum || !fits(length) {
                break;
            }
            best = Some((end, length));
        }
        best
    }
    /// Produce one QoS A-MSDU MPDU carrying `frames` at the exact `expected`
    /// SN (one SN and one PN).
    pub(super) fn amsdu_mpdu(
        &mut self,
        frames: &[&[u8]],
        tid: u8,
        sequence: u16,
    ) -> Result<Vec<u8>, Error> {
        let (limit, _) = self.amsdu_body(tid).ok_or(Error::Profile)?;
        if let Some(security) = self.security.as_mut() {
            return Ok(security.transmit_amsdu_qos(frames, tid, limit)?);
        }
        let body =
            narf_wireless::amsdu::encode(frames, self.own, limit).map_err(|_| Error::Profile)?;
        let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
        let mut bytes = vec![0x88, 1, 0, 0];
        bytes.extend_from_slice(&ap);
        bytes.extend_from_slice(&self.own);
        bytes.extend_from_slice(&ap);
        bytes.extend_from_slice(&(sequence << 4).to_le_bytes());
        bytes.extend_from_slice(&[0x80 | tid, 0]);
        bytes.extend_from_slice(&body);
        Ok(bytes)
    }
    /// One non-BA A-MSDU MPDU from the FIFO prefix; `None` sends nothing.
    pub(super) fn send_amsdu_inner(
        &mut self,
        io: &mut impl Io,
        frames: &[&[u8]],
        tid: u8,
    ) -> Result<Option<usize>, Error> {
        if frames.len() < 2 || self.tx_ba.active(tid).is_some() {
            return Ok(None);
        }
        let Some((count, length)) = self.amsdu_prefix(frames, tid, |_| true) else {
            return Ok(None);
        };
        if !self.ready() || !io.packet_ready() {
            return Err(Error::Busy);
        }
        if let Some(g) = &self.tx_ba_grant {
            self.tx_ba.want(tid, g.tids());
        }
        // `send_inner`'s sequence space: per-TID only with a BA owner or a
        // protected (per-TID replay) association.
        let sequence = if self.security.is_some() {
            self.security
                .as_ref()
                .ok_or(Error::State)?
                .next_qos_sequence(tid)?
        } else if self.tx_ba_grant.is_some() {
            self.qos_sequence[usize::from(tid)]
        } else {
            self.sequence
        };
        let bytes = self.amsdu_mpdu(&frames[..count], tid, sequence)?;
        if bytes.len() != length || u16::from_le_bytes([bytes[22], bytes[23]]) >> 4 != sequence {
            return Err(Error::State);
        }
        if self.security.is_none() {
            if self.tx_ba_grant.is_some() {
                self.qos_sequence[usize::from(tid)] = (sequence + 1) & 4095;
            } else {
                self.sequence = (sequence + 1) & 4095;
            }
        }
        for frame in &frames[..count] {
            self.tracking.tx_bytes = self.tracking.tx_bytes.saturating_add(frame.len() as u64);
        }
        let rts = self
            .protection
            .as_ref()
            .is_some_and(|g| bytes.len() as u64 > u64::from(g.threshold()));
        self.transmit(io, bytes, if rts { Kind::RtsData } else { Kind::Data })?;
        if rts {
            self.data_drain = Some((self.now()?, None));
        }
        Ok(Some(count))
    }
}

#[cfg(feature = "kernel-test")]
#[path = "station_tx_amsdu_tests.rs"]
mod tests;
