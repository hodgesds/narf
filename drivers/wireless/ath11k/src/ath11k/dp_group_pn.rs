// SPDX-License-Identifier: BSD-3-Clause-Clear
//! Host replay detection for group-addressed data (the multicast PN/TSC
//! check).
//!
//! Responsibility, from Linux: `ath11k_dp_peer_rx_pn_replay_config` returns
//! early for a group key ("Enable PN/TSC replay check offload only for
//! unicast frames. We use mac80211 PN/TSC replay check functionality for
//! bcast/mcast for now"), so REO never checks a GTK's PN. For a decrypted
//! group-addressed MPDU `ath11k_dp_rx_h_mpdu` sets `RX_FLAG_DECRYPTED |
//! RX_FLAG_MIC_STRIPPED | RX_FLAG_ICV_STRIPPED` but *not*
//! `RX_FLAG_PN_VALIDATED`, and `ath11k_dp_rx_h_undecap_{nwifi,eth}` rebuild
//! the 802.11 header with the IV copied from the descriptor's `hdr_status`.
//! mac80211 then performs the check in `ieee80211_rx_h_decrypt`
//! (`ieee80211_crypto_ccmp_decrypt` / `_gcmp_decrypt`: PN must exceed
//! `key->u.ccmp.rx_pn[security_idx]`; `ieee80211_tkip_decrypt_data`: TSC
//! must exceed `rx[queue]` with the first-frame-at-zero exception). NARF
//! decapsulates to Ethernet before any mac80211 equivalent, so the DP owns
//! that check (IEEE 802.11-2020 12.5.2.4.4 / 12.5.3.4.4 / 12.5.5.4.4:
//! discard a received MPDU whose PN is not greater than the replay counter
//! of its key and traffic class).
//!
//! As in Linux only the first MSDU of an MPDU is group-classified
//! (`ath11k_dp_rx_h_attn_is_mcbc` requires `first_msdu`); later A-MSDU
//! subframes take the unicast `RX_FLAG_PN_VALIDATED` path.

use super::dp_frag::crypto_param_len;
use super::dp_ring::{enc, ieee80211_hdrlen};

/// `IEEE80211_NUM_TIDS`: data frames index `rx_pn[]` / `rx[]` by TID (QoS)
/// or 0 (non-QoS); index 16 is management-only and never reaches the DP.
pub const NUM_TIDS: usize = 16;
/// Key ID octet: Ext IV bit (bit 5) and Key ID (bits 7:6).
const EXT_IV: u8 = 1 << 5;

const IEEE80211_FCTL_FTYPE: u16 = 0x000c;
const IEEE80211_FTYPE_DATA: u16 = 0x0008;
const IEEE80211_STYPE_QOS_DATA: u16 = 0x0080;

/// The replay-relevant fields of a protected group-addressed MPDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupPn {
    /// Key ID from the IV (`hdr[hdrlen + 3] >> 6`).
    pub key_idx: u8,
    /// 48-bit PN (CCMP/GCMP) or TSC (TKIP: `iv32 << 16 | iv16`).
    pub pn: u64,
    /// mac80211's `rx->security_idx`: the TID of a QoS data frame, else 0.
    pub queue: usize,
}

/// Why a group-addressed MPDU was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupPnError {
    /// Header shorter than the 802.11 header plus IV, or not data.
    Short,
    /// TKIP/CCMP/GCMP without the Ext IV bit (`TKIP_DECRYPT_NO_EXT_IV`).
    NoExtIv,
    /// No group key installed at the frame's Key ID
    /// (`RX_DROP_U_NO_KEY_ID` / no `rx->key`).
    NoKey,
    /// PN/TSC not above the replay counter (`RX_DROP_U_REPLAY`).
    Replay,
}

/// Ciphers whose group frames carry a 48-bit replay counter.
pub const fn has_replay_counter(enctype: u32) -> bool {
    matches!(
        enctype,
        enc::TKIP_MIC
            | enc::TKIP_NO_MIC
            | enc::CCMP_128
            | enc::CCMP_256
            | enc::GCMP_128
            | enc::AES_GCMP_256
    )
}

/// Parse the received 802.11 header + IV (`hdr_status`) of a protected
/// group data MPDU: `ccmp_hdr2pn` / `gcmp_hdr2pn` byte order for
/// CCMP/GCMP, TKIP's TSC1-WEPSeed-TSC0-KeyID-TSC2..5 layout otherwise.
pub fn parse(hdr: &[u8], enctype: u32) -> Result<GroupPn, GroupPnError> {
    if hdr.len() < 2 {
        return Err(GroupPnError::Short);
    }
    let fc = u16::from_le_bytes([hdr[0], hdr[1]]);
    if fc & IEEE80211_FCTL_FTYPE != IEEE80211_FTYPE_DATA {
        return Err(GroupPnError::Short);
    }
    let hdrlen = ieee80211_hdrlen(fc);
    let iv_len = crypto_param_len(enctype);
    let iv = hdr
        .get(hdrlen..hdrlen + iv_len)
        .filter(|iv| iv.len() == 8)
        .ok_or(GroupPnError::Short)?;
    if iv[3] & EXT_IV == 0 {
        return Err(GroupPnError::NoExtIv);
    }
    let pn = match enctype {
        enc::TKIP_MIC | enc::TKIP_NO_MIC => {
            let iv16 = ((iv[0] as u64) << 8) | iv[2] as u64;
            let iv32 = u32::from_le_bytes([iv[4], iv[5], iv[6], iv[7]]) as u64;
            (iv32 << 16) | iv16
        }
        _ => {
            (iv[0] as u64)
                | (iv[1] as u64) << 8
                | (iv[4] as u64) << 16
                | (iv[5] as u64) << 24
                | (iv[6] as u64) << 32
                | (iv[7] as u64) << 40
        }
    };
    let queue = if fc & IEEE80211_STYPE_QOS_DATA != 0 {
        // The QoS Control field closes the header (before any HT Control).
        let qos_off = if fc & 0x0300 == 0x0300 { 30 } else { 24 };
        (hdr.get(qos_off).copied().ok_or(GroupPnError::Short)? & 0x0f) as usize
    } else {
        0
    };
    Ok(GroupPn {
        key_idx: iv[3] >> 6,
        pn,
        queue,
    })
}

/// One installed group key's receive replay counters (mac80211
/// `key->u.ccmp.rx_pn[]` / `key->u.tkip.rx[]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupRxKey {
    pub peer_id: u16,
    pub key_idx: u8,
    pub tkip: bool,
    rx: [u64; NUM_TIDS],
    /// `TKIP_STATE_NOT_INIT` cleared after the first accepted frame.
    tkip_used: [bool; NUM_TIDS],
}

impl GroupRxKey {
    /// `ieee80211_key_alloc(seq)`: every TID's counter starts at the
    /// little-endian 48-bit RSC (zero when none was supplied).
    pub fn new(peer_id: u16, key_idx: u8, tkip: bool, seq: u64) -> Self {
        GroupRxKey {
            peer_id,
            key_idx,
            tkip,
            rx: [seq & 0xffff_ffff_ffff; NUM_TIDS],
            tkip_used: [false; NUM_TIDS],
        }
    }

    /// The replay counter for `queue`.
    pub fn counter(&self, queue: usize) -> Option<u64> {
        self.rx.get(queue).copied()
    }

    /// Check and, when accepted, advance the counter. CCMP/GCMP: a PN equal
    /// to or below the counter is a replay (Linux ath11k never sets
    /// `RX_FLAG_ALLOW_SAME_PN` here). TKIP: equal is accepted only for the
    /// very first frame of a key whose RSC was zero.
    pub fn check(&mut self, pn: u64, queue: usize) -> Result<(), GroupPnError> {
        let q = queue.min(NUM_TIDS - 1);
        let rx = self.rx[q];
        let replay = if self.tkip {
            pn < rx || (pn == rx && (rx != 0 || self.tkip_used[q]))
        } else {
            pn <= rx
        };
        if replay {
            return Err(GroupPnError::Replay);
        }
        self.rx[q] = pn;
        self.tkip_used[q] = true;
        Ok(())
    }
}
