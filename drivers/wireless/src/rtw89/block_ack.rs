// SPDX-License-Identifier: GPL-2.0-or-later
//! Recipient Block Ack sessions for the retained station.
//!
//! Host half of what mac80211 does for rtw89 (rtw89 sets
//! `AMPDU_AGGREGATION` but not `SUPPORTS_REORDERING_BUFFER`):
//! - `net/mac80211/agg-rx.c::{ieee80211_process_addba_request,
//!   __ieee80211_start_rx_ba_session,ieee80211_send_addba_resp,
//!   ___ieee80211_stop_rx_ba_session}` and `ht.c::ieee80211_process_delba`,
//! - `rx.c::ieee80211_rx_reorder_ampdu` / `ieee80211_rx_h_ctrl` (BAR),
//!   with the shared bounded `narf_wireless::reorder::Reorder`.
//!
//! The device half is `rtw89_ops_ampdu_action(RX_START/RX_STOP)` ->
//! `rtw89_fw_h2c_ba_cam`, issued by `station_control::Controller`.
use alloc::vec::Vec;

/// `rtw8852b_chip_info.max_rx_agg_num` (`max_rx_aggregation_subframes`).
pub(super) const MAX_BUF: u16 = 64;
/// mac80211 `HT_RX_REORDER_BUF_TIMEOUT` (HZ / 10).
pub(super) const REORDER_TIMEOUT_NS: u64 = 100_000_000;
pub(super) const STATUS_SUCCESS: u16 = 0;
pub(super) const STATUS_REQUEST_DECLINED: u16 = 37;
pub(super) const STATUS_INVALID_QOS_PARAM: u16 = 38;
/// `WLAN_REASON_QSTA_TIMEOUT`.
pub(super) const REASON_TIMEOUT: u16 = 39;

/// Parsed ADDBA Request (IEEE 802.11 9.6.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Request {
    pub(super) token: u8,
    pub(super) amsdu: bool,
    pub(super) policy: u8,
    pub(super) tid: u8,
    pub(super) buf_size: u16,
    pub(super) timeout: u16,
    pub(super) ssn: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    AddbaRequest(Request),
    /// DELBA; `initiator` is true when the sender was the originator.
    Delba {
        tid: u8,
        initiator: bool,
        reason: u16,
    },
    /// ADDBA Response to our originator request (9.6.4.3).
    AddbaResponse {
        token: u8,
        status: u16,
        amsdu: bool,
        tid: u8,
        buf_size: u16,
    },
    /// Any other Block Ack category action (ignored by a recipient).
    Other,
}

fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

/// Unprotected unicast Block Ack action (category 3) from `peer` to `own`.
pub(super) fn parse_action(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> Option<Action> {
    if frame.len() < 26
        || frame[0] != 0xd0
        || frame[1] & !0x18 != 0 // no ToDS/FromDS/MoreFrag/Order/Protected
        || frame[4..10] != own
        || frame[10..16] != peer
        || frame[16..22] != peer
        || frame[24] != 3
    {
        return None;
    }
    Some(match frame[25] {
        0 => {
            let capab = le16(frame, 27)?;
            let timeout = le16(frame, 29)?;
            let ssc = le16(frame, 31)?;
            Action::AddbaRequest(Request {
                token: *frame.get(26)?,
                amsdu: capab & 1 != 0,
                policy: ((capab >> 1) & 1) as u8,
                tid: ((capab >> 2) & 0xf) as u8,
                buf_size: capab >> 6,
                timeout,
                ssn: ssc >> 4,
            })
        }
        1 => {
            let capab = le16(frame, 29)?;
            Action::AddbaResponse {
                token: *frame.get(26)?,
                status: le16(frame, 27)?,
                amsdu: capab & 1 != 0,
                tid: ((capab >> 2) & 0xf) as u8,
                buf_size: capab >> 6,
            }
        }
        2 => {
            let params = le16(frame, 26)?;
            Action::Delba {
                tid: (params >> 12) as u8,
                initiator: params & (1 << 11) != 0,
                reason: le16(frame, 28)?,
            }
        }
        _ => Action::Other,
    })
}

/// `__ieee80211_start_rx_ba_session` admission: (status, buffer size).
/// Only an HT link may run Block Ack; delayed policy is refused because
/// rtw89 does not advertise `IEEE80211_HT_CAP_DELAY_BA`.
pub(super) fn decide(request: &Request, ht: bool) -> (u16, u16) {
    if !ht || request.tid > 7 {
        return (STATUS_REQUEST_DECLINED, 0);
    }
    if request.policy != 1 || request.buf_size > MAX_BUF {
        return (STATUS_INVALID_QOS_PARAM, 0);
    }
    let buf = if request.buf_size == 0 {
        MAX_BUF
    } else {
        request.buf_size
    };
    (STATUS_SUCCESS, buf.min(MAX_BUF))
}

fn header(own: [u8; 6], peer: [u8; 6]) -> Vec<u8> {
    let mut bytes = alloc::vec![0xd0, 0, 0, 0];
    bytes.extend_from_slice(&peer);
    bytes.extend_from_slice(&own);
    bytes.extend_from_slice(&peer);
    bytes.extend_from_slice(&[0, 0]); // sequence assigned at publication
    bytes
}

/// `ieee80211_send_addba_resp`: policy immediate, no A-MSDU (this profile
/// does not set `SUPPORTS_AMSDU_IN_AMPDU`), the request's timeout.
pub(super) fn addba_response(
    own: [u8; 6],
    peer: [u8; 6],
    request: &Request,
    status: u16,
    buf: u16,
) -> Vec<u8> {
    let mut bytes = header(own, peer);
    let capab = 1u16 << 1 | u16::from(request.tid & 0xf) << 2 | buf << 6;
    bytes.extend_from_slice(&[3, 1, request.token]);
    bytes.extend_from_slice(&status.to_le_bytes());
    bytes.extend_from_slice(&capab.to_le_bytes());
    bytes.extend_from_slice(&request.timeout.to_le_bytes());
    bytes
}

/// `ieee80211_send_delba` from the recipient side.
pub(super) fn delba(own: [u8; 6], peer: [u8; 6], tid: u8, reason: u16) -> Vec<u8> {
    let mut bytes = header(own, peer);
    let params = u16::from(tid & 0xf) << 12; // initiator = recipient (0)
    bytes.extend_from_slice(&[3, 2]);
    bytes.extend_from_slice(&params.to_le_bytes());
    bytes.extend_from_slice(&reason.to_le_bytes());
    bytes
}

/// `ieee80211_send_delba` from the originator side (`WLAN_BACK_INITIATOR`).
pub(super) fn delba_initiator(own: [u8; 6], peer: [u8; 6], tid: u8, reason: u16) -> Vec<u8> {
    let mut bytes = header(own, peer);
    let params = 1u16 << 11 | u16::from(tid & 0xf) << 12;
    bytes.extend_from_slice(&[3, 2]);
    bytes.extend_from_slice(&params.to_le_bytes());
    bytes.extend_from_slice(&reason.to_le_bytes());
    bytes
}

/// `rtw8852b_chip_info.max_tx_agg_num` (`hw->max_tx_aggregation_subframes`).
pub(super) const MAX_TX_AGG: u16 = 128;
/// `ADDBA_RESP_INTERVAL` (HZ).
pub(super) const ADDBA_RESP_MS: u64 = 1000;
/// `HT_AGG_MAX_RETRIES`, `HT_AGG_BURST_RETRIES`, `HT_AGG_RETRIES_PERIOD`.
pub(super) const MAX_RETRIES: u8 = 15;
pub(super) const BURST_RETRIES: u8 = 3;
pub(super) const RETRIES_PERIOD_MS: u64 = 15_000;
/// `RTW89_FORBID_BA_TIMER` (4s) after an EAPOL-triggered stop.
pub(super) const FORBID_MS: u64 = 4000;
/// `WLAN_REASON_QSTA_NOT_USE`.
pub(super) const REASON_NOT_USE: u16 = 37;

/// `ieee80211_send_addba_request`: immediate policy, A-MSDU capable (rtw89
/// sets `SUPPORTS_AMSDU_IN_AMPDU`), timeout 0, `start_seq_num << 4`, and an
/// ADDBA Extension element (`IEEE80211_ADDBA_EXT_NO_FRAG`) for an HE peer.
/// `ieee80211_tx_ba_session_handle_start` offers `IEEE80211_MAX_AMPDU_BUF_HT`
/// to an HT peer and min(`max_tx_agg_num`, `IEEE80211_MAX_AMPDU_BUF_HE`) to
/// an HE peer.
pub(super) fn addba_request(
    own: [u8; 6],
    peer: [u8; 6],
    token: u8,
    tid: u8,
    ssn: u16,
    he: bool,
) -> Vec<u8> {
    let buf: u16 = if he { MAX_TX_AGG.min(256) } else { 64 };
    let mut bytes = header(own, peer);
    let capab = 1u16 | 1 << 1 | u16::from(tid & 0xf) << 2 | buf << 6;
    bytes.extend_from_slice(&[3, 0, token]);
    bytes.extend_from_slice(&capab.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&((ssn & 0x0fff) << 4).to_le_bytes());
    if he {
        bytes.extend_from_slice(&[159, 1, 1]);
    }
    bytes
}

/// One originator (TX) session per TID (mac80211 `tid_ampdu_tx` state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TxState {
    /// `ieee80211_start_tx_ba_session` accepted; the request is not sent.
    Wanted,
    /// ADDBA Request with `token` sent at `sent` ms (`HT_AGG_STATE_SENT_ADDBA`).
    Requested { token: u8, sent: u64 },
    /// Successful response; `TX_OPERATIONAL` programming is outstanding.
    Responded { buf: u16 },
    /// `IEEE80211_AMPDU_TX_OPERATIONAL` done: data carries TXWD AGG_EN.
    Operational { buf: u16 },
}

/// mac80211 agg-tx.c originator bookkeeping for one peer.
#[derive(Debug, Default)]
pub(super) struct Originator {
    pub(super) tids: [Option<TxState>; 8],
    /// `sta->ampdu_mlme.dialog_token_allocator`.
    token: u8,
    /// `addba_req_num` / `last_addba_req_time`.
    attempts: [u8; 8],
    last_request: [u64; 8],
    /// `RTW89_TXQ_F_FORBID_BA` until this ms.
    forbid_until: [u64; 8],
}
impl Originator {
    /// `rtw89_core_txq_check_agg` + `ieee80211_start_tx_ba_session` gates:
    /// true when a new session for `tid` starts now.
    pub(super) fn want(&mut self, tid: u8, now: u64) -> bool {
        let t = usize::from(tid);
        if tid > 7
            || self.tids[t].is_some()
            || now < self.forbid_until[t]
            || self.attempts[t] > MAX_RETRIES
            || self.attempts[t] > BURST_RETRIES
                && now.saturating_sub(self.last_request[t]) < RETRIES_PERIOD_MS
        {
            return false;
        }
        self.tids[t] = Some(TxState::Wanted);
        true
    }
    /// Next request to send: (tid, token). Assigns the dialog token.
    pub(super) fn next_request(&mut self, now: u64) -> Option<(u8, u8)> {
        let t = self.tids.iter().position(|s| *s == Some(TxState::Wanted))?;
        self.token = self.token.wrapping_add(1);
        self.tids[t] = Some(TxState::Requested {
            token: self.token,
            sent: now,
        });
        self.attempts[t] = self.attempts[t].saturating_add(1);
        self.last_request[t] = now;
        Some((t as u8, self.token))
    }
    /// `ieee80211_process_addba_resp`; returns the buffer size that must be
    /// programmed before the session becomes operational.
    pub(super) fn response(
        &mut self,
        token: u8,
        status: u16,
        tid: u8,
        buf_size: u16,
    ) -> Option<u16> {
        let t = usize::from(tid);
        match self.tids.get(t).copied().flatten() {
            Some(TxState::Requested { token: sent, .. }) if sent == token => {}
            _ => return None,
        }
        if status == STATUS_SUCCESS && buf_size != 0 {
            let buf = buf_size.min(MAX_TX_AGG);
            self.tids[t] = Some(TxState::Responded { buf });
            self.attempts[t] = 0;
            Some(buf)
        } else {
            // AGG_STOP_DECLINED: no DELBA.
            self.tids[t] = None;
            None
        }
    }
    /// Buffer size of a session awaiting `TX_OPERATIONAL` programming.
    pub(super) fn responded(&self, tid: u8) -> Option<u16> {
        match self.tids.get(usize::from(tid)).copied().flatten() {
            Some(TxState::Responded { buf }) => Some(buf),
            _ => None,
        }
    }
    pub(super) fn operational(&mut self, tid: u8) -> bool {
        let t = usize::from(tid);
        if let Some(TxState::Responded { buf }) = self.tids.get(t).copied().flatten() {
            self.tids[t] = Some(TxState::Operational { buf });
            true
        } else {
            false
        }
    }
    /// Buffer size of an operational session for `tid`.
    pub(super) fn aggregating(&self, tid: u8) -> Option<u16> {
        match self.tids.get(usize::from(tid)).copied().flatten() {
            Some(TxState::Operational { buf }) => Some(buf),
            _ => None,
        }
    }
    /// A session is being set up (frames for the TID are held, like
    /// mac80211's `tid_tx->pending`).
    pub(super) fn holding(&self, tid: u8) -> bool {
        matches!(
            self.tids.get(usize::from(tid)).copied().flatten(),
            Some(TxState::Wanted | TxState::Requested { .. } | TxState::Responded { .. })
        )
    }
    /// `rtw89_phy_ra_recalc_agg_limit` input: min operational `agg_num`.
    pub(super) fn min_agg(&self) -> Option<u16> {
        (0..8).filter_map(|tid| self.aggregating(tid)).min()
    }
    /// Remove the session for `tid`; true when one existed.
    pub(super) fn stop(&mut self, tid: u8) -> bool {
        self.tids
            .get_mut(usize::from(tid))
            .and_then(Option::take)
            .is_some()
    }
    /// `RTW89_TXQ_F_FORBID_BA` after an EAPOL stop.
    pub(super) fn forbid(&mut self, tid: u8, until: u64) {
        if let Some(slot) = self.forbid_until.get_mut(usize::from(tid)) {
            *slot = until;
        }
    }
    /// TIDs whose ADDBA response timer expired (`sta_addba_resp_timer_expired`).
    pub(super) fn expired(&self, now: u64) -> impl Iterator<Item = u8> + '_ {
        (0..8u8).filter(move |&tid| {
            matches!(
                self.tids[usize::from(tid)],
                Some(TxState::Requested { sent, .. }) if now.saturating_sub(sent) >= ADDBA_RESP_MS
            )
        })
    }
}

/// Compressed BlockAckReq (control subtype 8) from `peer`: (TID, SSN).
pub(super) fn bar(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> Option<(u8, u16)> {
    if frame.len() < 20 || frame[0] != 0x84 || frame[4..10] != own || frame[10..16] != peer {
        return None;
    }
    let control = le16(frame, 16)?;
    // Basic (non-multi-TID) compressed BAR only: BAR Ack Policy free,
    // Multi-TID=0, Compressed=1.
    if control & 0b110 != 0b100 {
        return None;
    }
    Some(((control >> 12) as u8, le16(frame, 18)? >> 4))
}

/// QoS DATA (TID, sequence) for reorder admission.
pub(super) fn qos_sequence(frame: &[u8]) -> Option<(u8, u16)> {
    if frame.len() < 26 || frame[0] != 0x88 || frame[22] & 0xf != 0 {
        return None;
    }
    Some((
        frame[24] & 0xf,
        u16::from_le_bytes([frame[22], frame[23]]) >> 4,
    ))
}

/// One live recipient session.
pub(super) struct Session<T> {
    pub(super) reorder: narf_wireless::reorder::Reorder<T>,
    pub(super) timeout_tu: u16,
    pub(super) last_ms: u64,
    pub(super) ssn: u16,
}

#[cfg(feature = "kernel-test")]
#[path = "block_ack/tests.rs"]
mod tests;
