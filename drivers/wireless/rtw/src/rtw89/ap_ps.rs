// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Host AP power-save buffering and U-APSD delivery for an RTL8852B softAP.
//!
//! RTL8852B firmware never gains `RTW89_FW_FEATURE_NOTIFY_AP_INFO` (fw.c
//! `fw_feat_tbl` lists it only for RTL8922A/RTL8922D), so core.c
//! `rtw89_core_register_hw` does not set `IEEE80211_HW_AP_LINK_PS` and
//! `rtw89_core_rx_pkt_hdl` stays idle (`refcount_ap_info == 0`). mac80211
//! then owns all of AP-side power save in the host; this module mirrors
//! that owner exactly, while `WIPHY_FLAG_AP_UAPSD` and
//! `hw->uapsd_max_sp_len = IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL` are the
//! rtw89 capability:
//!
//! - rx.c `ieee80211_rx_h_uapsd_and_pspoll` (runs before) and
//!   `ieee80211_rx_h_sta_process` (PM transitions);
//! - tx.c `ieee80211_tx_h_unicast_ps_buf` + `purge_old_ps_buffers`;
//! - sta_info.c `__sta_info_recalc_tim`, `ieee80211_sta_ps_deliver_wakeup`,
//!   `ieee80211_sta_ps_get_frames`, `ieee80211_sta_ps_more_data`,
//!   `ieee80211_sta_ps_deliver_response`, `_poll_response`, `_uapsd`,
//!   `ieee80211_send_null_response`, `sta_info_buffer_expired`;
//! - status.c `IEEE80211_TX_STATUS_EOSP` clears `WLAN_STA_SP`;
//! - tx.c `__ieee80211_beacon_add_tim` / `ieee80211_beacon_add_tim_pvb`.
//!
//! The `rtw89` driver never calls `ieee80211_sta_block_awake`, so
//! `WLAN_STA_PS_DRIVER` is never set and is not modelled. Group-addressed
//! frames are not buffered here: without `HOST_BROADCAST_PS_BUFFERING`
//! mac80211 only marks them `SEND_AFTER_DTIM` and rtw89 places them on the
//! port HIQ (core.c `rtw89_core_tx_update_desc_info`), see
//! [`group_after_dtim`].
//!
//! This model holds no hardware, firmware or RF authority. Buffered MPDUs
//! are opaque byte vectors; only the frame-control MoreData bit and the QoS
//! EOSP bit are rewritten, both of which CCMP/GCMP mask out of the AAD.
extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

/// mac80211 AC indices (`IEEE80211_AC_VO..BK`).
pub(in crate::rtw89) const AC_VO: usize = 0;
pub(in crate::rtw89) const AC_VI: usize = 1;
pub(in crate::rtw89) const AC_BE: usize = 2;
pub(in crate::rtw89) const AC_BK: usize = 3;
const NUM_ACS: usize = 4;
/// util.c `ieee80211_ac_to_qos_mask`: WMM QoS Info U-APSD bit per AC.
const AC_QOS_MASK: [u8; NUM_ACS] = [1 << 0, 1 << 1, 1 << 3, 1 << 2];
/// wme.c `ieee802_1d_to_ac`.
const TID_AC: [usize; 8] = [AC_BE, AC_BK, AC_BK, AC_BE, AC_VI, AC_VI, AC_VO, AC_VO];
const ALL_ACS: u8 = 0x0f;
/// sta_info.h `STA_MAX_TX_BUFFER`.
pub(in crate::rtw89) const STA_MAX_TX_BUFFER: usize = 64;
/// ieee80211_i.h `TOTAL_MAX_TX_BUFFER`.
pub(in crate::rtw89) const TOTAL_MAX_TX_BUFFER: usize = 512;
/// `IEEE80211_MAX_AID`.
pub(in crate::rtw89) const MAX_AID: u16 = 2007;
/// `IEEE80211_MAX_TIM_LEN`.
const MAX_TIM_LEN: usize = 251;
/// sta_info.h `STA_TX_BUFFER_EXPIRE` (10 s).
const STA_TX_BUFFER_EXPIRE_MS: u64 = 10_000;

const FCTL_MOREFRAGS: u16 = 0x0400;
const FCTL_PM: u16 = 0x1000;
const FCTL_MOREDATA: u16 = 0x2000;
const FCTL_FROMDS: u16 = 0x0200;
const FCTL_TODS: u16 = 0x0100;
const QOS_CTL_EOSP: u8 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum Error {
    /// AID, U-APSD mask, Max SP or WME combination outside the source range.
    Invalid,
    /// The AID or address is already present.
    Duplicate,
    /// No associated peer with that AID.
    Unknown,
    /// MPDU too short for its own frame-control header.
    Malformed,
}

/// `NL80211_STA_WME_*` facts plus listen interval of one associated peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct PeerConfig {
    pub(in crate::rtw89) aid: u16,
    pub(in crate::rtw89) addr: [u8; 6],
    /// `sta->sta.wme`: QoS association.
    pub(in crate::rtw89) wme: bool,
    /// `sta->sta.uapsd_queues` in WMM QoS Info order (VO bit0, VI bit1,
    /// BK bit2, BE bit3). Trigger- and delivery-enabled are identical
    /// without TSPEC, as in mac80211.
    pub(in crate::rtw89) uapsd_queues: u8,
    /// `sta->sta.max_sp` (WMM QoS Info Max SP Length, 0..3).
    pub(in crate::rtw89) max_sp: u8,
    /// Association Request listen interval, in beacon intervals.
    pub(in crate::rtw89) listen_interval: u16,
}

#[derive(Debug)]
struct Buffered {
    mpdu: Vec<u8>,
    tid: u8,
    queued_ms: u64,
}

#[derive(Debug)]
struct Peer {
    config: PeerConfig,
    /// `WLAN_STA_PS_STA`.
    dozing: bool,
    /// `WLAN_STA_SP`: a PS-Poll or U-APSD service period is outstanding.
    service_period: bool,
    /// `sta->ps_tx_buf[ac]`.
    buffers: [VecDeque<Buffered>; NUM_ACS],
}

impl Peer {
    fn queued(&self, ignored: u8) -> bool {
        self.buffers
            .iter()
            .zip(AC_QOS_MASK)
            .any(|(buffer, mask)| ignored & mask == 0 && !buffer.is_empty())
    }
}

/// What normal (non-response) transmit must do with one unicast MPDU.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum Transmit {
    /// Peer awake, or a non-bufferable MMPDU: send now.
    Send(Vec<u8>),
    /// Held in the peer's PS buffer; `tim_changed` requests a beacon update
    /// (`rtw89_ops_set_tim` queues `update_beacon_work`).
    Buffered { tim_changed: bool },
}

/// One frame released towards a dozing (or waking) peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Response {
    /// Finished MPDU (MoreData/EOSP already rewritten).
    pub(in crate::rtw89) mpdu: Vec<u8>,
    /// 802.1D priority; selects the AC/qsel.
    pub(in crate::rtw89) tid: u8,
    /// Locally generated (QoS) Null rather than a buffered unit.
    pub(in crate::rtw89) null: bool,
    /// `IEEE80211_TX_STATUS_EOSP | IEEE80211_TX_CTL_REQ_TX_STATUS`: the
    /// terminal TX report for this frame ends the period
    /// ([`ApPs::tx_status`]).
    pub(in crate::rtw89) ends_period: bool,
}

/// Result of feeding one received frame from an associated peer.
#[derive(Debug, Default, PartialEq, Eq)]
pub(in crate::rtw89) struct Received {
    /// `RX_QUEUED`: a consumed PS-Poll; not delivered further.
    pub(in crate::rtw89) consumed: bool,
    /// Frames to transmit now, in order (`IEEE80211_TX_CTL_NO_PS_BUFFER`).
    pub(in crate::rtw89) responses: Vec<Response>,
    /// The peer's TIM bit flipped; the beacon template must be refreshed.
    pub(in crate::rtw89) tim_changed: bool,
    /// The peer entered (`Some(true)`) or left (`Some(false)`) power save.
    pub(in crate::rtw89) transition: Option<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reason {
    PsPoll,
    Uapsd,
}

/// AP-wide power-save owner for one BSS (`struct ps_data` + per-STA state).
#[derive(Debug)]
pub(in crate::rtw89) struct ApPs {
    own: [u8; 6],
    beacon_interval: u16,
    peers: BTreeMap<u16, Peer>,
    /// `ps->tim`: bit `aid` set when the peer has indicated traffic.
    tim: [u8; MAX_TIM_LEN + 1],
    /// `local->total_ps_buffered`.
    total: usize,
}

fn fc(mpdu: &[u8]) -> Result<u16, Error> {
    mpdu.get(..2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or(Error::Malformed)
}
fn ftype(fc: u16) -> u16 {
    (fc >> 2) & 3
}
fn stype(fc: u16) -> u16 {
    (fc >> 4) & 0xf
}
fn is_mgmt(fc: u16) -> bool {
    ftype(fc) == 0
}
fn is_data(fc: u16) -> bool {
    ftype(fc) == 2
}
fn is_pspoll(fc: u16) -> bool {
    ftype(fc) == 1 && stype(fc) == 0xa
}
/// `ieee80211_is_data_qos` (covers QoS Null).
fn is_qos(fc: u16) -> bool {
    is_data(fc) && stype(fc) & 0x8 != 0
}
fn is_qos_null(fc: u16) -> bool {
    is_data(fc) && stype(fc) == 0xc
}
/// `ieee80211_get_qos_ctl` offset for a QoS data/QoS-Null header.
fn qos_offset(fc: u16) -> usize {
    if fc & (FCTL_TODS | FCTL_FROMDS) == FCTL_TODS | FCTL_FROMDS {
        30
    } else {
        24
    }
}

/// `ieee80211_is_bufferable_mmpdu`.
fn bufferable_mmpdu(mpdu: &[u8], fc: u16) -> bool {
    if !is_mgmt(fc) {
        return false;
    }
    match stype(fc) {
        0xa | 0xc => return true, // disassoc, deauth
        0xd => {}
        _ => return false,
    }
    // `IEEE80211_MIN_ACTION_SIZE(action_code)`: header + category + code.
    if mpdu.len() < 26 {
        return true;
    }
    if mpdu[24] != 4 && mpdu[24] != 9 {
        return true; // not Public / Protected Dual of Public Action
    }
    !matches!(mpdu[25], 32 | 33) // FTM request/response
}

/// sta_info.c `find_highest_prio_tid`.
fn highest_prio_tid(tids: u16) -> u8 {
    if tids & 0xf8 != 0 {
        return (15 - tids.leading_zeros()) as u8;
    }
    if tids & 1 != 0 {
        return 0;
    }
    (15 - tids.leading_zeros()) as u8
}

/// Whether an `addr1` group frame for this BSS must go out after the DTIM
/// beacon (tx.c `ieee80211_tx_h_multicast_ps_buf` without
/// `HOST_BROADCAST_PS_BUFFERING`: set `SEND_AFTER_DTIM` when any associated
/// peer dozes; ordered frames and Probe Requests excluded). rtw89 then
/// selects `RTW89_TX_QSEL_B0_HI` and the vif port, and the port's HIQ DTIM
/// configuration releases it.
pub(in crate::rtw89) fn group_after_dtim(ps: &ApPs, fc: u16) -> bool {
    if fc & 0x8000 != 0 || (is_mgmt(fc) && stype(fc) == 4) {
        return false;
    }
    ps.peers.values().any(|peer| peer.dozing)
}

impl ApPs {
    pub(in crate::rtw89) fn new(own: [u8; 6], beacon_interval: u16) -> Self {
        Self {
            own,
            beacon_interval,
            peers: BTreeMap::new(),
            tim: [0; MAX_TIM_LEN + 1],
            total: 0,
        }
    }

    pub(in crate::rtw89) fn add_peer(&mut self, config: PeerConfig) -> Result<(), Error> {
        if config.aid == 0
            || config.aid > MAX_AID
            || config.uapsd_queues & !ALL_ACS != 0
            || config.max_sp > 3
            || (!config.wme && config.uapsd_queues != 0)
        {
            return Err(Error::Invalid);
        }
        if self.peers.contains_key(&config.aid)
            || self.peers.values().any(|p| p.config.addr == config.addr)
        {
            return Err(Error::Duplicate);
        }
        self.peers.insert(
            config.aid,
            Peer {
                config,
                dozing: false,
                service_period: false,
                buffers: Default::default(),
            },
        );
        Ok(())
    }

    /// Station removal: buffered frames are freed and the TIM bit cleared
    /// (`__sta_info_recalc_tim` for a dead STA). Returns whether the TIM
    /// changed.
    pub(in crate::rtw89) fn remove_peer(&mut self, aid: u16) -> Result<bool, Error> {
        let peer = self.peers.remove(&aid).ok_or(Error::Unknown)?;
        self.total -= peer.buffers.iter().map(VecDeque::len).sum::<usize>();
        Ok(self.set_tim(aid, false))
    }

    pub(in crate::rtw89) fn dozing(&self, aid: u16) -> Option<bool> {
        self.peers.get(&aid).map(|p| p.dozing)
    }
    pub(in crate::rtw89) fn in_service_period(&self, aid: u16) -> Option<bool> {
        self.peers.get(&aid).map(|p| p.service_period)
    }
    pub(in crate::rtw89) fn buffered(&self, aid: u16) -> usize {
        self.peers
            .get(&aid)
            .map_or(0, |p| p.buffers.iter().map(VecDeque::len).sum())
    }
    pub(in crate::rtw89) fn total_buffered(&self) -> usize {
        self.total
    }
    pub(in crate::rtw89) fn tim_bit(&self, aid: u16) -> bool {
        aid <= MAX_AID && self.tim[usize::from(aid / 8)] & (1 << (aid % 8)) != 0
    }

    fn set_tim(&mut self, aid: u16, on: bool) -> bool {
        if self.tim_bit(aid) == on {
            return false;
        }
        let (byte, bit) = (usize::from(aid / 8), 1u8 << (aid % 8));
        if on {
            self.tim[byte] |= bit;
        } else {
            self.tim[byte] &= !bit;
        }
        true
    }

    /// `__sta_info_recalc_tim`: delivery-enabled ACs are ignored unless
    /// every AC is delivery-enabled.
    fn recalc_tim(&mut self, aid: u16) -> bool {
        let Some(peer) = self.peers.get(&aid) else {
            return false;
        };
        let mut ignore = peer.config.uapsd_queues;
        if ignore == ALL_ACS {
            ignore = 0;
        }
        let indicate = peer.queued(ignore);
        self.set_tim(aid, indicate)
    }

    /// `purge_old_ps_buffers` (no group buffer exists here): drop one frame
    /// per peer from its lowest-priority nonempty AC.
    fn purge(&mut self) {
        for peer in self.peers.values_mut() {
            for buffer in peer.buffers.iter_mut().rev() {
                if buffer.pop_front().is_some() {
                    break;
                }
            }
        }
        self.total = self
            .peers
            .values()
            .map(|p| p.buffers.iter().map(VecDeque::len).sum::<usize>())
            .sum();
    }

    /// Ordinary unicast transmit to `aid` (tx.c
    /// `ieee80211_tx_h_unicast_ps_buf`). Responses produced by this module
    /// carry `NO_PS_BUFFER` and must not be passed back here.
    pub(in crate::rtw89) fn transmit(
        &mut self,
        aid: u16,
        mpdu: Vec<u8>,
        tid: u8,
        now_ms: u64,
    ) -> Result<Transmit, Error> {
        let fc = fc(&mpdu)?;
        if tid > 7 {
            return Err(Error::Invalid);
        }
        let peer = self.peers.get(&aid).ok_or(Error::Unknown)?;
        if !peer.dozing || (is_mgmt(fc) && !bufferable_mmpdu(&mpdu, fc)) {
            return Ok(Transmit::Send(mpdu));
        }
        if self.total >= TOTAL_MAX_TX_BUFFER {
            self.purge();
        }
        let ac = TID_AC[usize::from(tid)];
        let peer = self.peers.get_mut(&aid).ok_or(Error::Unknown)?;
        if peer.buffers[ac].len() >= STA_MAX_TX_BUFFER {
            peer.buffers[ac].pop_front();
        } else {
            self.total += 1;
        }
        peer.buffers[ac].push_back(Buffered {
            mpdu,
            tid,
            queued_ms: now_ms,
        });
        Ok(Transmit::Buffered {
            tim_changed: self.recalc_tim(aid),
        })
    }

    /// One frame received from associated `aid` (after duplicate filtering
    /// and before decryption, as in mac80211's handler order).
    /// `addr1_group` is `is_multicast_ether_addr(hdr->addr1)`.
    pub(in crate::rtw89) fn receive(
        &mut self,
        aid: u16,
        header: &[u8],
        addr1_group: bool,
    ) -> Result<Received, Error> {
        let fc = fc(header)?;
        let peer = self.peers.get(&aid).ok_or(Error::Unknown)?;
        let mut out = Received::default();
        // ieee80211_rx_h_uapsd_and_pspoll
        if peer.dozing {
            if is_pspoll(fc) {
                out.consumed = true;
                if !peer.service_period {
                    let mut ignore = peer.config.uapsd_queues;
                    if ignore == ALL_ACS {
                        ignore = 0;
                    }
                    out.responses = self.deliver(aid, 1, ignore, Reason::PsPoll);
                    out.tim_changed = self.recalc_tim(aid);
                }
                return Ok(out);
            }
            if fc & FCTL_MOREFRAGS == 0 && fc & FCTL_PM != 0 && (is_qos(fc) || is_qos_null(fc)) {
                let offset = qos_offset(fc);
                let tid = *header.get(offset).ok_or(Error::Malformed)? & 0x7;
                let ac = TID_AC[usize::from(tid)];
                let queues = peer.config.uapsd_queues;
                // ieee80211_sta_uapsd_trigger + ieee80211_sta_ps_deliver_uapsd
                if queues & AC_QOS_MASK[ac] != 0 && !peer.service_period {
                    let frames = match peer.config.max_sp {
                        1 => 2,
                        2 => 4,
                        3 => 6,
                        _ => 128,
                    };
                    out.responses = self.deliver(aid, frames, !queues & ALL_ACS, Reason::Uapsd);
                    out.tim_changed = self.recalc_tim(aid);
                }
            }
        }
        // ieee80211_rx_h_sta_process
        if fc & FCTL_MOREFRAGS == 0 && !addr1_group && (is_mgmt(fc) || is_data(fc)) {
            let pm = fc & FCTL_PM != 0;
            let dozing = self.peers.get(&aid).is_some_and(|p| p.dozing);
            if dozing && !pm {
                out.responses.extend(self.wake(aid));
                out.tim_changed |= self.recalc_tim(aid);
                out.transition = Some(false);
            } else if !dozing && pm {
                if let Some(peer) = self.peers.get_mut(&aid) {
                    peer.dozing = true;
                }
                out.tim_changed |= self.recalc_tim(aid);
                out.transition = Some(true);
            }
        }
        Ok(out)
    }

    /// `ieee80211_sta_ps_deliver_wakeup`: every buffered frame, AC order,
    /// unchanged; service period and pending poll/trigger cleared.
    fn wake(&mut self, aid: u16) -> Vec<Response> {
        let Some(peer) = self.peers.get_mut(&aid) else {
            return Vec::new();
        };
        peer.dozing = false;
        peer.service_period = false;
        let mut out = Vec::new();
        for buffer in peer.buffers.iter_mut() {
            for frame in buffer.drain(..) {
                out.push(Response {
                    mpdu: frame.mpdu,
                    tid: frame.tid,
                    null: false,
                    ends_period: false,
                });
            }
        }
        self.total -= out.len();
        out
    }

    /// `ieee80211_sta_ps_deliver_response` for a host-buffering driver.
    fn deliver(&mut self, aid: u16, frames: usize, ignored: u8, reason: Reason) -> Vec<Response> {
        let own = self.own;
        let Some(peer) = self.peers.get_mut(&aid) else {
            return Vec::new();
        };
        peer.service_period = true;
        // ieee80211_sta_ps_get_frames
        let mut taken: Vec<Buffered> = Vec::new();
        let mut budget = frames;
        for (buffer, mask) in peer.buffers.iter_mut().zip(AC_QOS_MASK) {
            if ignored & mask != 0 {
                continue;
            }
            while budget > 0 {
                let Some(frame) = buffer.pop_front() else {
                    break;
                };
                budget -= 1;
                taken.push(frame);
            }
            if !buffer.is_empty() {
                break;
            }
        }
        self.total -= taken.len();
        let more = peer.queued(ignored);
        let (addr, wme) = (peer.config.addr, peer.config.wme);
        if taken.is_empty() {
            // "This will evaluate to 1, 3, 5 or 7."
            let ac = (AC_VO..NUM_ACS)
                .find(|ac| ignored & AC_QOS_MASK[*ac] == 0)
                .unwrap_or(NUM_ACS);
            let tid = (7 - 2 * ac as i32).clamp(0, 7) as u8;
            return alloc::vec![null_response(own, addr, wme, tid, reason, false)];
        }
        let count = taken.len();
        let mut tids = 0u16;
        let mut out = Vec::with_capacity(count + 1);
        let mut need_null = false;
        for (index, frame) in taken.into_iter().enumerate() {
            let last = index + 1 == count;
            let mut mpdu = frame.mpdu;
            let mut fc = u16::from_le_bytes([mpdu[0], mpdu[1]]);
            if more || !last {
                fc |= FCTL_MOREDATA;
            } else {
                fc &= !FCTL_MOREDATA;
            }
            tids |= 1 << frame.tid;
            let qos = (is_qos(fc) || is_qos_null(fc)) && mpdu.len() > qos_offset(fc);
            let mut ends_period = false;
            if last {
                if reason == Reason::PsPoll {
                    ends_period = true;
                } else if qos {
                    let offset = qos_offset(fc);
                    mpdu[offset] |= QOS_CTL_EOSP;
                    ends_period = true;
                } else {
                    // Bufferable MMPDU last: pretend more data, then QoS-Null.
                    fc |= FCTL_MOREDATA;
                    need_null = true;
                }
            }
            mpdu[..2].copy_from_slice(&fc.to_le_bytes());
            out.push(Response {
                mpdu,
                tid: frame.tid,
                null: false,
                ends_period,
            });
        }
        if need_null {
            let tid = highest_prio_tid(tids);
            out.push(null_response(own, addr, wme, tid, reason, false));
        }
        out
    }

    /// Terminal TX status for a frame this module released: an
    /// `ends_period` frame ends the period whether or not it was acked.
    pub(in crate::rtw89) fn tx_status(&mut self, aid: u16, response: &Response) {
        if response.ends_period {
            if let Some(peer) = self.peers.get_mut(&aid) {
                peer.service_period = false;
            }
        }
    }

    /// `sta_info_cleanup_expire_buffered`: per-AC head expiry using
    /// `max(listen_interval * beacon_int * 2 TU, 10 s)`. Returns AIDs whose
    /// TIM bit changed.
    pub(in crate::rtw89) fn expire(&mut self, now_ms: u64) -> Vec<u16> {
        let beacon = u64::from(self.beacon_interval);
        let mut changed = Vec::new();
        let aids: Vec<u16> = self.peers.keys().copied().collect();
        for aid in aids {
            let Some(peer) = self.peers.get_mut(&aid) else {
                continue;
            };
            // (listen * beacon * 32 / 15625) whole seconds, as in Linux.
            let secs = u64::from(peer.config.listen_interval) * beacon * 32 / 15625;
            let timeout = (secs * 1000).max(STA_TX_BUFFER_EXPIRE_MS);
            let mut dropped = 0;
            for buffer in peer.buffers.iter_mut() {
                while buffer
                    .front()
                    .is_some_and(|f| now_ms > f.queued_ms.saturating_add(timeout))
                {
                    buffer.pop_front();
                    dropped += 1;
                }
            }
            self.total -= dropped;
            if dropped != 0 && self.recalc_tim(aid) {
                changed.push(aid);
            }
        }
        changed
    }

    /// TIM element (`__ieee80211_beacon_add_tim`, non-S1G). The returned
    /// bytes start with element ID 5. `dtim_count` is a template value:
    /// rtw89 hands the element offset to firmware (`GRP_IE_OFST | BIT(7)`
    /// in `rtw89_fw_h2c_update_beacon`).
    pub(in crate::rtw89) fn tim_element(&self, dtim_count: u8, dtim_period: u8) -> Vec<u8> {
        // Group traffic is never host-buffered here (bc_buf stays empty).
        let mcast = false;
        let have_bits = self.peers.values().any(|p| p.dozing) && self.tim.iter().any(|b| *b != 0);
        let mut element = alloc::vec![5, 0, dtim_count, dtim_period];
        if have_bits {
            let n1 = self.tim.iter().position(|b| *b != 0).unwrap_or(0) & 0xfe;
            let n2 = (n1..=MAX_TIM_LEN)
                .rev()
                .find(|i| self.tim[*i] != 0)
                .unwrap_or(n1);
            element.push(n1 as u8 | u8::from(mcast));
            element.extend_from_slice(&self.tim[n1..=n2]);
        } else {
            element.push(u8::from(mcast));
            element.push(0);
        }
        element[1] = (element.len() - 2) as u8;
        element
    }
}

/// `ieee80211_send_null_response`: FromDS (QoS) Null, A1 peer, A2/A3 own.
fn null_response(
    own: [u8; 6],
    peer: [u8; 6],
    wme: bool,
    tid: u8,
    reason: Reason,
    more: bool,
) -> Response {
    let mut fc: u16 = if wme { 0x00c8 } else { 0x0048 } | FCTL_FROMDS;
    let mut mpdu = Vec::with_capacity(26);
    if wme && reason == Reason::Uapsd && more {
        fc |= FCTL_MOREDATA;
    }
    mpdu.extend_from_slice(&fc.to_le_bytes());
    mpdu.extend_from_slice(&[0, 0]);
    mpdu.extend_from_slice(&peer);
    mpdu.extend_from_slice(&own);
    mpdu.extend_from_slice(&own);
    mpdu.extend_from_slice(&[0, 0]);
    if wme {
        let mut qc = tid;
        if reason == Reason::Uapsd {
            qc |= QOS_CTL_EOSP;
        }
        mpdu.extend_from_slice(&[qc, 0]);
    }
    Response {
        mpdu,
        tid,
        null: true,
        ends_period: true,
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "ap_ps_tests.rs"]
mod tests;
