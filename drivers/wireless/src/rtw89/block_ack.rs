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
