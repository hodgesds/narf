// SPDX-License-Identifier: GPL-2.0-or-later
//! Host-owned Block Ack sessions for the gen2 rtl8xxxu station.
//!
//! Linux `rtl8xxxu_ampdu_action` (core.c) programs no register for
//! RX_START/RX_STOP: the MAC acknowledges A-MPDUs autonomously and mac80211
//! owns the recipient session and its reorder buffer (`agg-rx.c`). TX_START
//! is `rtl8xxxu_set_ampdu_factor`/`rtl8xxxu_set_ampdu_min_space` with the
//! peer's factor/density and returns `IEEE80211_AMPDU_TX_START_IMMEDIATE`,
//! TX_OPERATIONAL sets `priv->tid_tx_operational`, every TX_STOP resets both
//! registers to 0 and clears the TID (`agg-tx.c` drives the ADDBA exchange).
//! This is the same mac80211 session state the RTL8188EU station keeps
//! inline (`station_runtime`), held here as plain data so the gen2 station
//! drives the EP0 work (`Work`) and queues the action bodies it returns.
//! Bodies start at the Category octet; the station adds the 24-byte header.
use alloc::{vec, vec::Vec};
use narf_wireless::reorder::Reorder;

/// mac80211 `IEEE80211_MAX_AMPDU_BUF_HT` (rtl8xxxu keeps the default
/// `max_rx_aggregation_subframes`).
pub(super) const BA_MAX_WINDOW: u16 = 64;
/// mac80211 `HT_RX_REORDER_BUF_TIMEOUT` (HZ / 10).
const REORDER_TIMEOUT_NS: u64 = 100_000_000;
/// `WLAN_STATUS_REQUEST_DECLINED` / `WLAN_STATUS_INVALID_QOS_PARAM`.
const STATUS_DECLINED: u16 = 37;
const STATUS_INVALID_QOS: u16 = 38;
/// `WLAN_REASON_QSTA_TIMEOUT` / `WLAN_REASON_QSTA_NOT_USE`.
const REASON_TIMEOUT: u16 = 39;
const REASON_NOT_USE: u16 = 37;
/// mac80211 `sta_info.h` originator retry policy and `ADDBA_RESP_INTERVAL`.
const HT_AGG_MAX_RETRIES: u8 = 15;
const HT_AGG_BURST_RETRIES: u8 = 3;
const HT_AGG_RETRIES_PERIOD_MS: u64 = 15_000;
const ADDBA_RESP_INTERVAL_MS: u64 = 1000;
/// `WLAN_CATEGORY_BACK` and its action codes.
const CATEGORY_BACK: u8 = 3;
const ADDBA_REQ: u8 = 0;
const ADDBA_RESP: u8 = 1;
const DELBA: u8 = 2;

/// One originator session (mac80211 `tid_ampdu_tx`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxBa {
    /// TX_START pending: EP0 aggregation limits precede the ADDBA Request.
    Starting {
        token: u8,
    },
    /// ADDBA Request queued; `ADDBA_RESP_INTERVAL` runs to `deadline`.
    Requested {
        token: u8,
        deadline: u64,
    },
    Operational {
        timeout_tu: u16,
        last_tx: u64,
    },
    /// TX_STOP pending: EP0 limits reset, then an optional initiator DELBA.
    Stopping {
        delba: bool,
    },
}

/// One accepted recipient session (mac80211 `tid_ampdu_rx`).
struct RxBa<T> {
    reorder: Reorder<T>,
    token: u8,
    timeout_tu: u16,
    last_rx: u64,
}

/// `rtl8xxxu_ampdu_action` device work the station performs before the
/// session advances.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Work {
    /// TX_START: program the peer's factor/density, then `requested`.
    Start(u8),
    /// TX_STOP: reset both limits to 0, then `stopped`.
    Stop(u8),
}

pub(super) struct Sessions<T> {
    rx: [Option<RxBa<T>>; 8],
    tx: [Option<TxBa>; 8],
    tx_token: u8,
    addba_req_num: [u8; 8],
    last_addba_req: [u64; 8],
}

impl<T> Default for Sessions<T> {
    fn default() -> Self {
        Self {
            rx: Default::default(),
            tx: [None; 8],
            tx_token: 0,
            addba_req_num: [0; 8],
            last_addba_req: [0; 8],
        }
    }
}

fn tu_ms(tu: u16) -> u64 {
    u64::from(tu) * 1024 / 1000
}

impl<T> Sessions<T> {
    /// TIDs with an accepted recipient session (A-MPDU members admissible).
    pub(super) fn rx_tids(&self) -> u8 {
        (0..8).fold(0, |bits, tid| {
            bits | u8::from(self.rx[tid].is_some()) << tid
        })
    }
    /// `priv->tid_tx_operational`.
    pub(super) fn operational(&self) -> u8 {
        (0..8).fold(0, |bits, tid| {
            bits | u8::from(matches!(self.tx[tid], Some(TxBa::Operational { .. }))) << tid
        })
    }
    /// An originator session whose TX_START limits are (or will be)
    /// programmed: a cold restart must program them again.
    pub(super) fn tx_started(&self) -> bool {
        self.tx
            .iter()
            .any(|s| matches!(s, Some(TxBa::Requested { .. } | TxBa::Operational { .. })))
    }
    /// One peer-bound Block Ack action body (Category onward). ADDBA Request
    /// follows `__ieee80211_start_rx_ba_session` and returns the ADDBA
    /// Response body (`ieee80211_send_addba_resp`); ADDBA Response follows
    /// `ieee80211_process_addba_resp`; DELBA follows `ieee80211_process_delba`.
    pub(super) fn action(&mut self, body: &[u8], now: u64) -> Option<Vec<u8>> {
        if body.len() < 2 || body[0] != CATEGORY_BACK {
            return None;
        }
        match body[1] {
            ADDBA_REQ if body.len() >= 9 => {
                let token = body[2];
                let p = u16::from_le_bytes([body[3], body[4]]);
                let timeout = u16::from_le_bytes([body[5], body[6]]);
                let ssn = u16::from_le_bytes([body[7], body[8]]) >> 4;
                let (status, tid, buf) = self.addba_request(token, p, timeout, ssn, now);
                // A-MSDU bit from SUPPORTS_AMSDU_IN_AMPDU (unset by
                // rtl8xxxu), immediate policy.
                let params = (buf << 6) | (u16::from(tid) << 2) | 2;
                let mut response = vec![CATEGORY_BACK, ADDBA_RESP, token];
                response.extend_from_slice(&status.to_le_bytes());
                response.extend_from_slice(&params.to_le_bytes());
                response.extend_from_slice(&timeout.to_le_bytes());
                Some(response)
            }
            ADDBA_RESP if body.len() >= 9 => {
                let token = body[2];
                let status = u16::from_le_bytes([body[3], body[4]]);
                let p = u16::from_le_bytes([body[5], body[6]]);
                let timeout = u16::from_le_bytes([body[7], body[8]]);
                self.addba_response(token, status, p, timeout, now);
                None
            }
            DELBA if body.len() >= 6 => {
                let p = u16::from_le_bytes([body[2], body[3]]);
                let tid = usize::from(p >> 12) & 7;
                // Initiator bit set: the AP originator tears down our
                // recipient session (buffer purged). Clear: the AP recipient
                // ends our originator session (AGG_STOP_PEER_REQUEST, no
                // DELBA of our own).
                if p & (1 << 11) != 0 {
                    if let Some(session) = self.rx[tid].take() {
                        session.reorder.retire();
                    }
                } else if !matches!(self.tx[tid], None | Some(TxBa::Stopping { .. })) {
                    self.tx[tid] = Some(TxBa::Stopping { delba: false });
                }
                None
            }
            _ => None,
        }
    }
    /// Returns (status, TID, buffer size) for the ADDBA response.
    fn addba_request(
        &mut self,
        token: u8,
        p: u16,
        timeout: u16,
        ssn: u16,
        now: u64,
    ) -> (u16, u8, u16) {
        let policy = (p >> 1) & 1;
        let tid = ((p >> 2) & 15) as u8;
        let mut buf = p >> 6;
        // IEEE80211_FIRST_TSPEC_TSID: TSPEC TIDs are declined.
        if tid >= 8 {
            return (STATUS_DECLINED, tid, buf);
        }
        // No IEEE80211_HT_CAP_DELAY_BA: delayed policy or an oversized
        // window is an invalid QoS parameter.
        if policy != 1 || buf > BA_MAX_WINDOW {
            return (STATUS_INVALID_QOS, tid, buf);
        }
        if buf == 0 {
            buf = BA_MAX_WINDOW;
        }
        let slot = &mut self.rx[usize::from(tid)];
        if let Some(session) = slot {
            // Same dialog token: an update, accepted only with an unchanged
            // timeout. A new token replaces the session without DELBA.
            if session.token == token {
                let status = if session.timeout_tu == timeout {
                    0
                } else {
                    STATUS_DECLINED
                };
                return (status, tid, buf);
            }
            if let Some(old) = slot.take() {
                old.reorder.retire();
            }
        }
        let Ok(mut reorder) = Reorder::new(buf as u8, REORDER_TIMEOUT_NS) else {
            return (STATUS_DECLINED, tid, buf);
        };
        // head_seq_num = start_seq_num.
        if reorder.advance(ssn, now.saturating_mul(1_000_000)).is_err() {
            return (STATUS_DECLINED, tid, buf);
        }
        *slot = Some(RxBa {
            reorder,
            token,
            timeout_tu: timeout,
            last_rx: now,
        });
        (0, tid, buf)
    }
    /// Only the outstanding dialog token matches; success with a nonzero
    /// window makes the TID operational, anything else stops the session
    /// without a DELBA (AGG_STOP_DECLINED).
    fn addba_response(&mut self, token: u8, status: u16, p: u16, timeout: u16, now: u64) {
        let tid = usize::from((p >> 2) & 15);
        if tid >= 8 {
            return;
        }
        let Some(TxBa::Requested {
            token: outstanding, ..
        }) = self.tx[tid]
        else {
            return;
        };
        if outstanding != token {
            return;
        }
        self.tx[tid] = Some(if status == 0 && p >> 6 != 0 {
            self.addba_req_num[tid] = 0;
            TxBa::Operational {
                timeout_tu: timeout,
                last_tx: now,
            }
        } else {
            TxBa::Stopping { delba: false }
        });
    }
    /// `ieee80211_rx_reorder_ampdu` for a unicast QoS DATA MPDU from the
    /// bound peer: `Err(item)` when the TID has no session (not reordered),
    /// otherwise the in-order releases (allocation failure drops only this
    /// MPDU, as the shared owner does).
    pub(super) fn reorder(
        &mut self,
        tid: u8,
        sequence: u16,
        now: u64,
        item: T,
    ) -> Result<Vec<T>, T> {
        let Some(session) = self.rx.get_mut(usize::from(tid)).and_then(Option::as_mut) else {
            return Err(item);
        };
        session.last_rx = now;
        Ok(session
            .reorder
            .push(sequence, now.saturating_mul(1_000_000), item)
            .unwrap_or_default())
    }
    /// Timers: `sta_addba_resp_timer_expired` and
    /// `sta_tx_agg_session_timer_expired` stop the originator as a local
    /// request (initiator DELBA); `sta_rx_agg_session_timer_expired` ends the
    /// recipient with a QSTA_TIMEOUT DELBA (returned body); reorder holes
    /// release at `sta_rx_agg_reorder_timer_expired` (returned items). The
    /// rtl8xxxu station RX filter passes no BlockAckReq, so holes advance only
    /// by window or timeout.
    pub(super) fn service(&mut self, now: u64) -> (Vec<T>, Vec<Vec<u8>>) {
        for slot in &mut self.tx {
            let expired = match *slot {
                Some(TxBa::Requested { deadline, .. }) => now >= deadline,
                Some(TxBa::Operational {
                    timeout_tu,
                    last_tx,
                }) => timeout_tu != 0 && now.saturating_sub(last_tx) >= tu_ms(timeout_tu),
                _ => false,
            };
            if expired {
                *slot = Some(TxBa::Stopping { delba: true });
            }
        }
        let mut released = Vec::new();
        let mut delba = Vec::new();
        for tid in 0..8u16 {
            let Some(session) = self.rx[usize::from(tid)].as_mut() else {
                continue;
            };
            if session.timeout_tu != 0
                && now.saturating_sub(session.last_rx) >= tu_ms(session.timeout_tu)
            {
                if let Some(session) = self.rx[usize::from(tid)].take() {
                    session.reorder.retire();
                }
                let mut body = vec![CATEGORY_BACK, DELBA];
                body.extend_from_slice(&(tid << 12).to_le_bytes());
                body.extend_from_slice(&REASON_TIMEOUT.to_le_bytes());
                delba.push(body);
                continue;
            }
            released.extend(
                session
                    .reorder
                    .expire(now.saturating_mul(1_000_000))
                    .unwrap_or_default(),
            );
        }
        (released, delba)
    }
    /// `rtl8xxxu_tx` -> `ieee80211_start_tx_ba_session` for a QoS DATA frame
    /// to the HT peer (never EAPOL), gated by HT_AGG_MAX_RETRIES /
    /// HT_AGG_BURST_RETRIES within HT_AGG_RETRIES_PERIOD; an operational
    /// session records activity for its timeout.
    pub(super) fn note_tx(&mut self, tid: u8, now: u64) {
        let tid = usize::from(tid & 7);
        match &mut self.tx[tid] {
            Some(TxBa::Operational { last_tx, .. }) => *last_tx = now,
            Some(_) => {}
            None => {
                let tries = self.addba_req_num[tid];
                if tries > HT_AGG_MAX_RETRIES
                    || tries > HT_AGG_BURST_RETRIES
                        && now < self.last_addba_req[tid].saturating_add(HT_AGG_RETRIES_PERIOD_MS)
                {
                    return;
                }
                self.tx_token = self.tx_token.wrapping_add(1);
                self.tx[tid] = Some(TxBa::Starting {
                    token: self.tx_token,
                });
            }
        }
    }
    /// The next TID needing `rtl8xxxu_ampdu_action` EP0 work.
    pub(super) fn work(&self) -> Option<Work> {
        (0..8u8).find_map(|tid| match self.tx[usize::from(tid)] {
            Some(TxBa::Starting { .. }) => Some(Work::Start(tid)),
            Some(TxBa::Stopping { .. }) => Some(Work::Stop(tid)),
            _ => None,
        })
    }
    /// After TX_START's limits: the ADDBA Request body
    /// (`ieee80211_send_addba_request`: immediate policy, A-MSDU clear,
    /// window IEEE80211_MAX_AMPDU_BUF_HT, timeout 0, SSN = the TID's next
    /// sequence) and `ADDBA_RESP_INTERVAL` armed.
    pub(super) fn requested(&mut self, tid: u8, ssn: u16, now: u64) -> Option<Vec<u8>> {
        let i = usize::from(tid);
        let Some(TxBa::Starting { token }) = self.tx.get(i).copied().flatten() else {
            return None;
        };
        let mut body = vec![CATEGORY_BACK, ADDBA_REQ, token];
        body.extend_from_slice(&(2 | u16::from(tid) << 2 | BA_MAX_WINDOW << 6).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&((ssn & 4095) << 4).to_le_bytes());
        self.last_addba_req[i] = now;
        self.addba_req_num[i] = self.addba_req_num[i].saturating_add(1);
        self.tx[i] = Some(TxBa::Requested {
            token,
            deadline: now.saturating_add(ADDBA_RESP_INTERVAL_MS),
        });
        Some(body)
    }
    /// After TX_STOP's reset: the session ends; a local stop returns the
    /// initiator DELBA body (`WLAN_REASON_QSTA_NOT_USE`).
    pub(super) fn stopped(&mut self, tid: u8) -> Option<Vec<u8>> {
        let slot = self.tx.get_mut(usize::from(tid))?;
        let Some(TxBa::Stopping { delba }) = *slot else {
            return None;
        };
        *slot = None;
        delba.then(|| {
            let mut body = vec![CATEGORY_BACK, DELBA];
            body.extend_from_slice(&(u16::from(tid) << 12 | 1 << 11).to_le_bytes());
            body.extend_from_slice(&REASON_NOT_USE.to_le_bytes());
            body
        })
    }
    /// Disconnect/failure: every session ends, buffered MPDUs are purged.
    pub(super) fn retire(&mut self) {
        for slot in &mut self.rx {
            if let Some(session) = slot.take() {
                session.reorder.retire();
            }
        }
        self.tx = [None; 8];
    }
}

#[cfg(feature = "kernel-test")]
#[path = "ba_sessions_tests.rs"]
mod tests;
