// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained channel1 legacy station. The logical owner, MLME, pending
//! replies and key history stay beside the actual Prepared DMA/mailbox owner.
use super::{
    packet::{Mpdu, Port},
    Error as RadioError, Io, Memory, Phase as Hardware, Prepared,
};
use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use narf_wireless::{
    association::{self, Bss, JoinPlan, SecurityMode},
    station_security::{self, Security},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    State,
    Busy,
    Profile,
    Timeout,
    PeerLost,
    Entropy,
    Allocation,
    Radio(RadioError),
    Management(association::Error),
    Security(station_security::Error),
}
impl From<RadioError> for Error {
    fn from(error: RadioError) -> Self {
        Self::Radio(error)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Dormant,
    Starting,
    Passive,
    Joining,
    Authentication,
    Association,
    Configuring,
    FourWay,
    Open,
    Stopping,
    Stopped,
    Failed,
}
pub(crate) trait Environment: Send + Sync {
    fn now_ms(&self) -> u64;
    fn fresh_nonce(&self) -> Option<[u8; 32]>;
    fn domain(&self) -> Result<narf_wireless::reg::RegulatoryDomain, Error>;
    fn pause(&self) -> impl Future<Output = ()> + Send;
    fn preparation_failed(&self) -> bool {
        false
    }
    fn admission(&self) -> Option<&Arc<Admission>> {
        None
    }
    fn ht20(
        &self,
        _base: Arc<super::super::channel_power::Calibration>,
    ) -> Result<Option<Arc<super::super::ht::Grant>>, Error> {
        Ok(None)
    }
    /// The bound MSI vector's wake (Linux `rtl_pci_intr_mode_msi`), or
    /// `None` on the polling fallback.
    fn interrupt(&self) -> Option<Arc<super::super::irq::Signal>> {
        None
    }
    /// Enable delivery of the bound vector, or withdraw and release it.
    /// `false` means no vector remains bound; the owner keeps polling.
    fn deliver(&self, _enabled: bool) -> bool {
        false
    }
}
/// Shared public closure and bounded publication gate. No guard crosses an
/// await; an already-entered native publication completes before close returns.
pub(crate) struct Admission {
    pub(crate) closed: AtomicBool,
    pub(crate) abort: AtomicBool,
    pub(crate) publication: narf_lib::sync::IrqSafeSpinLock<()>,
}
impl Admission {
    pub(crate) fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            abort: AtomicBool::new(false),
            publication: narf_lib::sync::IrqSafeSpinLock::new(()),
        }
    }
    pub(crate) fn publish<T, E>(
        &self,
        closed: E,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let _publication = self.publication.lock();
        if self.closed.load(Ordering::Acquire) {
            Err(closed)
        } else {
            operation()
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    pub bss: Bss,
    pub rsne: Option<Vec<u8>>,
    pub rsnxe: Option<Vec<u8>>,
}
impl Candidate {
    fn receive(frame: &Mpdu, local: [u8; 6], ht: bool) -> Result<Self, Error> {
        if frame.channel() != 1 {
            return Err(Error::Profile);
        }
        let observed = if ht {
            association::observe_with_phy(frame, 1, local, None, &super::super::ht::local())
        } else {
            association::observe(frame, 1, local, None)
        }
        .map_err(Error::Management)?;
        if observed.basic_rates & 1 == 0 {
            return Err(Error::Profile);
        }
        Ok(Self {
            bss: observed.bss,
            rsne: observed.ap_rsne,
            rsnxe: observed.ap_rsnxe,
        })
    }
}
struct Entry {
    candidate: Candidate,
    seen: u64,
}
#[derive(Clone, Copy)]
enum Kind {
    Authentication,
    Association,
    Eapol,
    Data,
    Control,
}
struct Pending {
    id: u64,
    kind: Kind,
    bytes: Vec<u8>,
    deadline: u64,
}
struct Captured {
    frame: Mpdu,
    admitted: bool,
    epoch: u64,
}
/// mac80211 `IEEE80211_MAX_AMPDU_BUF_HT`; `rtl_rx_ampdu_apply` keeps it
/// without a BT-coexistence aggregation limit (RTL8188EE has no BT).
const BA_MAX_WINDOW: u16 = 64;
/// mac80211 `HT_RX_REORDER_BUF_TIMEOUT` (HZ / 10).
const REORDER_TIMEOUT_NS: u64 = 100_000_000;
/// `WLAN_STATUS_REQUEST_DECLINED` / `WLAN_STATUS_INVALID_QOS_PARAM`.
const STATUS_DECLINED: u16 = 37;
const STATUS_INVALID_QOS: u16 = 38;
/// `WLAN_REASON_QSTA_REQUIRE_SETUP` / `WLAN_REASON_QSTA_TIMEOUT`.
const REASON_REQUIRE_SETUP: u16 = 38;
const REASON_TIMEOUT: u16 = 39;
/// One accepted recipient BA session. `rtl_rx_agg_start`/`rtl_rx_agg_stop`
/// only record per-TID host state; the EE MAC acknowledges autonomously.
struct RxBa {
    reorder: narf_wireless::reorder::Reorder<Captured>,
    token: u8,
    timeout_tu: u16,
    last_rx: u64,
}
/// mac80211 `sta_info.h` originator retry policy and `ADDBA_RESP_INTERVAL`.
const HT_AGG_MAX_RETRIES: u8 = 15;
const HT_AGG_BURST_RETRIES: u8 = 3;
const HT_AGG_RETRIES_PERIOD_MS: u64 = 15_000;
const ADDBA_RESP_INTERVAL_MS: u64 = 1000;
/// `rtl_tx_status` -> `ieee80211_start_tx_ba_session(sta, tid, 5000)`.
const TX_BA_TIMEOUT_TU: u16 = 5000;
/// `_rtl_tx_aggr_check`: `cnt_after_linked < 3` with the 2 s
/// `RTL_WATCH_DOG_TIME` watchdog incrementing it once per period.
const TX_BA_LINK_SETTLE_MS: u64 = 3 * 2000;
/// `WLAN_REASON_QSTA_NOT_USE`: DELBA for a local originator stop.
const REASON_NOT_USE: u16 = 37;
/// One originator BA session (mac80211 `tid_ampdu_tx` plus rtlwifi
/// `rtl_tid_data.agg.agg_state`). `rtl_tx_agg_start` returns
/// `IEEE80211_AMPDU_TX_START_IMMEDIATE` and `rtl_tx_agg_oper`/`_stop` only
/// record the state, so no device access accompanies a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxBa {
    /// ADDBA Request queued; `ADDBA_RESP_INTERVAL` runs to `deadline`.
    Requested { token: u8, deadline: u64 },
    /// RTL_AGG_OPERATIONAL: QoS DATA on the TID carries TXD AGG_EN.
    Operational { timeout_tu: u16, last_tx: u64 },
}
fn action_header(peer: [u8; 6], own: [u8; 6]) -> Vec<u8> {
    let mut header = vec![0xd0, 0, 0, 0];
    header.extend_from_slice(&peer);
    header.extend_from_slice(&own);
    header.extend_from_slice(&peer);
    header.extend_from_slice(&[0, 0]);
    header
}
fn delba(peer: [u8; 6], own: [u8; 6], tid: u16, reason: u16) -> Vec<u8> {
    // ieee80211_send_delba as recipient: initiator bit clear.
    let mut frame = action_header(peer, own);
    frame.extend_from_slice(&[3, 2]);
    frame.extend_from_slice(&(tid << 12).to_le_bytes());
    frame.extend_from_slice(&reason.to_le_bytes());
    frame
}
pub(crate) struct Publication {
    pci: super::packet::Publication,
    base: Arc<super::super::channel_power::Calibration>,
    ht: Option<Arc<super::super::ht::Grant>>,
    permission: super::super::channel_power::Permission,
    indices: [u8; 8],
    epoch: Arc<AtomicU64>,
    expected: u64,
    failed: Arc<AtomicBool>,
}
impl Publication {
    pub(crate) fn current(&self) -> bool {
        !self.failed.load(Ordering::Acquire) && self.epoch.load(Ordering::Acquire) == self.expected
    }
    pub(crate) fn invoke<T>(
        &self,
        domain: &narf_wireless::reg::RegulatoryDomain,
        operation: impl FnOnce() -> Result<T, RadioError>,
    ) -> Result<Option<T>, Error> {
        if !self.current() {
            return Ok(None);
        }
        let op = || {
            if self.base.permission(domain, 1).map_err(RadioError::Power)? != self.permission {
                return Err(RadioError::State);
            }
            if let Some(ht) = &self.ht {
                if ht.gains(domain, self.permission)? != self.indices {
                    return Err(RadioError::State);
                }
            }
            self.pci.invoke(|| {
                if self.current() {
                    operation().map(Some)
                } else {
                    Ok(None)
                }
            })
        };
        (if let Some(ht) = &self.ht {
            ht.invoke(op)
        } else {
            self.base.with_current(op)
        })
        .map_err(Error::Radio)
    }
}
pub(super) struct State {
    phase: Phase,
    failed: Arc<AtomicBool>,
    calibration: Option<Arc<super::super::channel_power::Calibration>>,
    cache: Vec<Entry>,
    candidate: Option<Candidate>,
    plan: Option<JoinPlan>,
    pmk: Option<Zeroizing<[u8; 32]>>,
    security: Option<Security>,
    pending: Option<Pending>,
    incoming: VecDeque<Captured>,
    received: VecDeque<Vec<u8>>,
    aid: Option<u16>,
    native_associated: bool,
    admitted: bool,
    sequence: u16,
    /// Open-path per-TID QoS SN space; software CCMP keeps its own
    /// per-TID counters inside shared `Security`.
    qos_sequence: [u16; 8],
    deadline: u64,
    last_now: u64,
    last_peer: u64,
    capability: u16,
    wmm: Option<narf_wireless::wmm::Parameters>,
    ht: Option<Arc<super::super::ht::Grant>>,
    ht_indices: [u8; 8],
    ht_profile: Option<association::phy::HtNegotiation>,
    controls: VecDeque<Vec<u8>>,
    delivered_reply: Option<Pending>,
    epoch: Arc<AtomicU64>,
    retire: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Recipient BA sessions by TID (mac80211 `tid_ampdu_rx`).
    rx_ba: [Option<RxBa>; 8],
    /// mac80211 `ampdu_mlme.unexpected_agg`: one DELBA per TID.
    unexpected_ba: u16,
    /// Originator BA sessions by TID with mac80211 retry bookkeeping.
    tx_ba: [Option<TxBa>; 8],
    tx_token: u8,
    addba_req_num: [u8; 8],
    last_addba_req: [u64; 8],
    /// TIDs left at RTL_AGG_PROGRESS after mac80211 refused a start
    /// (-EBUSY): `_rtl_tx_aggr_check` never retries them on this link.
    tx_ba_stuck: u8,
    /// Time the association completed (`MAC80211_LINKED`).
    linked_at: Option<u64>,
    /// `dm.undec_sm_pwdb` and `ra.pre_ratr_state` (driver RA mask).
    ra: super::super::rate_adaptive::State,
}
impl State {
    pub(super) fn new() -> Self {
        Self {
            phase: Phase::Dormant,
            failed: Arc::new(AtomicBool::new(false)),
            calibration: None,
            cache: Vec::new(),
            candidate: None,
            plan: None,
            pmk: None,
            security: None,
            pending: None,
            incoming: VecDeque::new(),
            received: VecDeque::new(),
            aid: None,
            native_associated: false,
            admitted: false,
            sequence: 0,
            qos_sequence: [0; 8],
            deadline: 0,
            last_now: 0,
            last_peer: 0,
            capability: 0,
            wmm: None,
            ht: None,
            ht_indices: [0; 8],
            ht_profile: None,
            controls: VecDeque::new(),
            delivered_reply: None,
            epoch: Arc::new(AtomicU64::new(1)),
            retire: None,
            rx_ba: Default::default(),
            unexpected_ba: 0,
            tx_ba: [None; 8],
            tx_token: 0,
            addba_req_num: [0; 8],
            last_addba_req: [0; 8],
            ra: super::super::rate_adaptive::State::new(),
            tx_ba_stuck: 0,
            linked_at: None,
        }
    }
    fn fail(&mut self) {
        self.failed.store(true, Ordering::Release);
        self.phase = Phase::Failed;
        self.admitted = false;
        self.incoming.clear();
        self.received.clear();
        self.pmk = None;
        self.wmm = None;
        self.retire_receive();
        self.controls.clear();
        self.retire_ba();
        if let Some(plan) = &mut self.plan {
            plan.cancel();
        }
        if let Some(security) = &mut self.security {
            security.fail();
        }
    }
    fn retire_receive(&mut self) {
        self.received.clear();
        // Exhaustion is terminal and never wraps back to a captured token.
        if self
            .epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .is_err()
        {
            self.failed.store(true, Ordering::Release);
        }
        if let Some(retire) = &self.retire {
            retire();
        }
    }
    fn retire_ba(&mut self) {
        for slot in &mut self.rx_ba {
            if let Some(session) = slot.take() {
                session.reorder.retire();
            }
        }
        self.unexpected_ba = 0;
        self.tx_ba = [None; 8];
        self.addba_req_num = [0; 8];
        self.last_addba_req = [0; 8];
        self.tx_ba_stuck = 0;
        self.linked_at = None;
    }
    /// TXD aggregation facts for one frame: (peer density, operational).
    /// `rtl8188ee_tx_fill_desc` sets the station's density and, for an
    /// `IEEE80211_TX_CTL_AMPDU` frame, AGG_EN + MAX_AGG_NUM.
    fn aggregate(&mut self, bytes: &[u8], now: u64) -> Option<(u8, bool)> {
        let profile = self.ht_profile?;
        if bytes.first() != Some(&0x88) || bytes.len() < 26 {
            return None;
        }
        let tid = usize::from(bytes[24] & 7);
        let operational = match &mut self.tx_ba[tid] {
            Some(TxBa::Operational { last_tx, .. }) => {
                *last_tx = now;
                true
            }
            _ => false,
        };
        Some((profile.peer_mpdu_density(), operational))
    }
    /// `rtl_tx_status` on a delivered QoS DATA frame (never EAPOL):
    /// `_rtl_tx_aggr_check` then `ieee80211_start_tx_ba_session`, which
    /// mac80211 refuses beyond HT_AGG_BURST_RETRIES within
    /// HT_AGG_RETRIES_PERIOD or HT_AGG_MAX_RETRIES. The immediate start sends
    /// the ADDBA Request (`ieee80211_send_addba_request`: SUPPORTS_AMSDU_IN_
    /// AMPDU A-MSDU bit, immediate policy, window IEEE80211_MAX_AMPDU_BUF_HT,
    /// timeout 5000 TU, SSN = the TID's next sequence).
    fn tx_status(&mut self, bytes: &[u8], now: u64, own: [u8; 6]) -> Result<(), Error> {
        if self.ht_profile.is_none() || bytes.first() != Some(&0x88) || bytes.len() < 26 {
            return Ok(());
        }
        let tid = bytes[24] & 7;
        let i = usize::from(tid);
        if self.tx_ba[i].is_some()
            || self.tx_ba_stuck & (1 << tid) != 0
            || self
                .linked_at
                .is_none_or(|at| now < at.saturating_add(TX_BA_LINK_SETTLE_MS))
        {
            return Ok(());
        }
        let tries = self.addba_req_num[i];
        if tries > HT_AGG_MAX_RETRIES
            || tries > HT_AGG_BURST_RETRIES
                && now < self.last_addba_req[i].saturating_add(HT_AGG_RETRIES_PERIOD_MS)
        {
            self.tx_ba_stuck |= 1 << tid;
            return Ok(());
        }
        let peer = self
            .candidate
            .as_ref()
            .map(|c| c.bss.bssid)
            .ok_or(Error::State)?;
        if self.controls.len() == 8 {
            return Err(Error::Allocation);
        }
        let ssn = match &self.security {
            Some(security) => security.next_qos_sequence(tid).map_err(Error::Security)?,
            None => self.qos_sequence[i],
        };
        self.tx_token = self.tx_token.wrapping_add(1);
        let token = self.tx_token;
        let mut request = action_header(peer, own);
        request.extend_from_slice(&[3, 0, token]);
        request
            .extend_from_slice(&(1 | 2 | u16::from(tid) << 2 | BA_MAX_WINDOW << 6).to_le_bytes());
        request.extend_from_slice(&TX_BA_TIMEOUT_TU.to_le_bytes());
        request.extend_from_slice(&((ssn & 4095) << 4).to_le_bytes());
        self.controls.push_back(request);
        self.last_addba_req[i] = now;
        self.addba_req_num[i] = tries.saturating_add(1);
        self.tx_ba[i] = Some(TxBa::Requested {
            token,
            deadline: now.saturating_add(ADDBA_RESP_INTERVAL_MS),
        });
        Ok(())
    }
    /// `ieee80211_process_addba_resp`: only the outstanding dialog token is
    /// matched; success with a nonzero window makes the TID operational
    /// (`rtl_tx_agg_oper`), anything else stops it without a DELBA
    /// (AGG_STOP_DECLINED -> `rtl_tx_agg_stop`, RTL_AGG_STOP).
    fn addba_response(&mut self, token: u8, status: u16, p: u16, timeout: u16, now: u64) {
        let tid = usize::from((p >> 2) & 15);
        if tid >= 8 {
            return;
        }
        let Some(TxBa::Requested {
            token: outstanding, ..
        }) = self.tx_ba[tid]
        else {
            return;
        };
        if outstanding != token {
            return;
        }
        self.tx_ba[tid] = if status == 0 && p >> 6 != 0 {
            self.addba_req_num[tid] = 0;
            Some(TxBa::Operational {
                timeout_tu: timeout,
                last_tx: now,
            })
        } else {
            None
        };
    }
    /// `sta_addba_resp_timer_expired` and `sta_tx_agg_session_timer_expired`
    /// stop as a local request: initiator DELBA `WLAN_REASON_QSTA_NOT_USE`.
    fn service_tx_ba(&mut self, now: u64, peer: [u8; 6], own: [u8; 6]) -> Result<(), Error> {
        for tid in 0..8u16 {
            let expired = match self.tx_ba[usize::from(tid)] {
                Some(TxBa::Requested { deadline, .. }) => now >= deadline,
                Some(TxBa::Operational {
                    timeout_tu,
                    last_tx,
                }) => {
                    timeout_tu != 0
                        && now.saturating_sub(last_tx) >= u64::from(timeout_tu) * 1024 / 1000
                }
                None => false,
            };
            if expired {
                self.tx_ba[usize::from(tid)] = None;
                if self.controls.len() == 8 {
                    return Err(Error::Allocation);
                }
                let mut frame = action_header(peer, own);
                frame.extend_from_slice(&[3, 2]);
                frame.extend_from_slice(&(tid << 12 | 1 << 11).to_le_bytes());
                frame.extend_from_slice(&REASON_NOT_USE.to_le_bytes());
                self.controls.push_back(frame);
            }
        }
        Ok(())
    }
    /// mac80211 `__ieee80211_start_rx_ba_session`; returns (status, TID, window).
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
        if tid >= 8 {
            return (STATUS_DECLINED, tid, buf);
        }
        if policy != 1 || buf > BA_MAX_WINDOW {
            return (STATUS_INVALID_QOS, tid, buf);
        }
        if buf == 0 {
            buf = BA_MAX_WINDOW;
        }
        let slot = &mut self.rx_ba[usize::from(tid)];
        if let Some(session) = slot {
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
        let Ok(mut reorder) = narf_wireless::reorder::Reorder::new(buf as u8, REORDER_TIMEOUT_NS)
        else {
            return (STATUS_DECLINED, tid, buf);
        };
        if reorder.advance(ssn, now.saturating_mul(1_000_000)).is_err() {
            return (STATUS_DECLINED, tid, buf);
        }
        *slot = Some(RxBa {
            reorder,
            token,
            timeout_tu: timeout,
            last_rx: now,
        });
        self.unexpected_ba &= !(1 << tid);
        (0, tid, buf)
    }
    fn release(&mut self, released: Vec<Captured>) -> Result<(), Error> {
        if self.incoming.len() + released.len() > 256 {
            return Err(Error::Allocation);
        }
        self.incoming.extend(released);
        Ok(())
    }
    /// Session inactivity (`sta_rx_agg_session_timer_expired`) and reorder
    /// hole expiry (`sta_rx_agg_reorder_timer_expired`).
    fn service_ba(&mut self, now: u64, own: [u8; 6]) -> Result<(), Error> {
        let peer = self
            .candidate
            .as_ref()
            .map(|c| c.bss.bssid)
            .ok_or(Error::State)?;
        self.service_tx_ba(now, peer, own)?;
        for tid in 0..8u16 {
            let Some(session) = self.rx_ba[usize::from(tid)].as_mut() else {
                continue;
            };
            if session.timeout_tu != 0
                && now.saturating_sub(session.last_rx)
                    >= u64::from(session.timeout_tu) * 1024 / 1000
            {
                if let Some(session) = self.rx_ba[usize::from(tid)].take() {
                    session.reorder.retire();
                }
                if self.controls.len() == 8 {
                    return Err(Error::Allocation);
                }
                self.controls
                    .push_back(delba(peer, own, tid, REASON_TIMEOUT));
                continue;
            }
            let released = session
                .reorder
                .expire(now.saturating_mul(1_000_000))
                .unwrap_or_default();
            self.release(released)?;
        }
        Ok(())
    }
    fn receive_open(&self) -> bool {
        self.phase == Phase::Open
            && self.native_associated
            && self.admitted
            && self.delivered_reply.is_none()
            && self.security.as_ref().is_none_or(Security::port_open)
            && !self.failed.load(Ordering::Acquire)
    }
}
struct Attempt {
    failed: Arc<AtomicBool>,
    armed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.armed {
            self.failed.store(true, Ordering::Release);
        }
    }
}
fn ethernet(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() < 32
        || !matches!(frame[0], 8 | 0x88)
        || frame[1] & 0xc7 != 2
        || frame[22] & 15 != 0
        || frame[10..16] != peer
        || frame[4..10] != own && frame[4] & 1 == 0
        || frame[16..22] == [0; 6]
        || frame[16] & 1 != 0
    {
        return None;
    }
    let offset = if frame[0] == 0x88 {
        let qos = frame.get(24..26)?;
        if qos[0] & 0xf0 != 0 || qos[1] != 0 {
            return None;
        }
        26
    } else {
        24
    };
    let snap = frame.get(offset..offset + 8)?;
    let protocol = u16::from_be_bytes([snap[6], snap[7]]);
    if snap[..6] != [0xaa, 0xaa, 3, 0, 0, 0]
        || protocol < 0x600
        || matches!(protocol, 0x888e | 0x80f3 | 0x8137)
        || frame.len() + 6 - offset > 1514
    {
        return None;
    }
    let mut bytes = frame[4..10].to_vec();
    bytes.extend_from_slice(&frame[16..22]);
    bytes.extend_from_slice(&frame[offset + 6..]);
    Some(bytes)
}
fn eapol(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> bool {
    let offset = if frame.first() == Some(&0x88) {
        if frame
            .get(24..26)
            .is_none_or(|q| q[0] & 0xf0 != 0 || q[1] != 0)
        {
            return false;
        }
        26
    } else {
        24
    };
    frame.len() >= offset + 8
        && matches!(frame[0], 8 | 0x88)
        && frame[1] & 0x87 == 2
        && frame[4..10] == own
        && frame[10..16] == peer
        && frame[16..22] == peer
        && frame[22] & 15 == 0
        && frame[offset..offset + 8] == [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]
}
fn private_eapol(b: &[u8], own: [u8; 6], peer: [u8; 6]) -> bool {
    if !eapol(b, own, peer) || b[1] & 0x40 != 0 {
        return false;
    }
    let at = if b[0] == 0x88 { 34 } else { 32 };
    b.get(at..).is_some_and(|e| {
        e.len() >= 4
            && matches!(e[0], 1..=3)
            && e[1] == 3
            && usize::from(u16::from_be_bytes([e[2], e[3]])) == e.len() - 4
    })
}
impl<I: Io, M: Memory> Prepared<I, M> {
    pub(crate) fn station_receive_retirement(&mut self, retire: Arc<dyn Fn() + Send + Sync>) {
        self.station.retire = Some(retire);
    }
    pub(crate) fn station_ht_capability(&self) -> Option<[u8; 26]> {
        self.station.ht.as_ref()?;
        Some(association::phy::LocalHt::siso20(false, false).capability_body())
    }
    pub(crate) fn station_receive_epoch(&self) -> (Arc<AtomicU64>, u64) {
        (
            self.station.epoch.clone(),
            self.station.epoch.load(Ordering::Acquire),
        )
    }
    pub(crate) fn station_receive_open(&self) -> bool {
        self.station_phase() == Phase::Open && self.station.receive_open()
    }
    pub(crate) fn station_calibration_present(&self) -> bool {
        self.station.calibration.is_some()
    }
    pub(crate) fn station_cancellation(&self) -> Arc<AtomicBool> {
        self.station.failed.clone()
    }
    pub(crate) fn station_phase(&self) -> Phase {
        if self.station.failed.load(Ordering::Acquire) || self.phase == Hardware::Failed {
            Phase::Failed
        } else {
            self.station.phase
        }
    }
    pub(crate) fn stage_station_calibration(
        &mut self,
        calibration: super::super::channel_power::Calibration,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), Error> {
        if self.phase != Hardware::MacConfigured
            || self.station.phase != Phase::Dormant
            || Some(
                calibration
                    .permission(domain, 1)
                    .map_err(|_| Error::Profile)?,
            ) != self.permission
        {
            return Err(Error::Profile);
        }
        self.station.calibration = Some(Arc::new(calibration));
        Ok(())
    }
    pub(crate) fn station_peer(&self) -> Option<[u8; 6]> {
        if self.station_phase() != Phase::Open
            || !self.station.native_associated
            || !self.station.admitted
        {
            return None;
        }
        self.station
            .candidate
            .as_ref()
            .map(|candidate| candidate.bss.bssid)
    }
    pub(crate) fn station_candidates(&self, now: u64) -> Vec<Candidate> {
        self.station
            .cache
            .iter()
            .filter(|entry| now >= entry.seen && now - entry.seen < 10_000)
            .map(|entry| entry.candidate.clone())
            .collect()
    }
    pub(super) fn check_station_policy(&self, environment: &impl Environment) -> Result<(), Error> {
        if environment
            .admission()
            .is_some_and(|control| control.closed.load(Ordering::Acquire))
        {
            return Err(Error::State);
        }
        let domain = environment.domain()?;
        let permission = self
            .station
            .calibration
            .as_ref()
            .ok_or(Error::Profile)?
            .permission(&domain, 1)
            .map_err(|_| Error::Profile)?;
        if Some(permission) != self.permission {
            return Err(Error::Profile);
        }
        if let Some(ht) = &self.station.ht {
            if ht.gains(&domain, permission).map_err(Error::Radio)? != self.station.ht_indices {
                return Err(Error::Profile);
            }
            ht.readback(&self.io, self.station.ht_indices, self.packet.ht)
                .map_err(Error::Radio)?;
        }
        Ok(())
    }
    /// Program all four EDCA rows inside the retained calibration (or HT
    /// grant) invocation. Every row is admitted before the first write and
    /// every write is read back, both at association and for a live update.
    fn program_station_edca(&self, p: narf_wireless::wmm::Parameters) -> Result<(), Error> {
        let calibration = self.station.calibration.as_ref().ok_or(Error::Profile)?;
        let program = || {
            if self.station.ht_profile.is_some() {
                return super::super::wmm::program_ht(&self.io, p);
            }
            super::super::wmm::program(&self.io, p, self.station.capability & 0x400 != 0)
        };
        if let Some(ht) = &self.station.ht {
            ht.invoke(program)?;
        } else {
            calibration.with_current(program)?;
        }
        Ok(())
    }
    /// mac80211 `ieee80211_sta_wmm_params`: a beacon from the bound AP whose
    /// WMM Parameter Set Count differs from the installed one carries new
    /// EDCA rows, which `drv_conf_tx` -> rtl88ee `set_qos` writes live. An
    /// unchanged count is ignored exactly as upstream does. Losing WMM or a
    /// row this profile cannot admit (BE ACM, bad geometry) stays terminal.
    fn update_station_edca(
        &mut self,
        information_elements: &[u8],
        environment: &impl Environment,
    ) -> Result<(), Error> {
        let Some(current) = self.station.wmm else {
            return Ok(());
        };
        let fresh = narf_wireless::wmm::Parameters::parse(information_elements)
            .ok()
            .flatten()
            .ok_or(Error::Profile)?;
        if fresh.parameter_set_count == current.parameter_set_count {
            return Ok(());
        }
        self.check_station_policy(environment)?;
        self.program_station_edca(fresh)?;
        self.station.wmm = Some(fresh);
        self.check_station_policy(environment)
    }
}
impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    pub(crate) fn station_publication<T>(
        &self,
        environment: &impl Environment,
        operation: impl FnOnce() -> Result<T, RadioError>,
    ) -> Result<T, Error> {
        let calibration = self.station.calibration.as_ref().ok_or(Error::State)?;
        let operation = || {
            self.check_station_policy(environment)
                .map_err(|_| RadioError::State)?;
            self.io.authority(true, operation)
        };
        let result = if let Some(ht) = &self.station.ht {
            ht.invoke(operation)
        } else {
            calibration.with_current(operation)
        };
        result.map_err(Error::Radio)
    }
    pub(crate) fn station_publication_token(
        &self,
        environment: &impl Environment,
    ) -> Result<Publication, Error> {
        self.check_station_policy(environment)?;
        Ok(Publication {
            pci: self.io.publication()?,
            base: self
                .station
                .calibration
                .as_ref()
                .ok_or(Error::State)?
                .clone(),
            ht: self.station.ht.clone(),
            permission: self.permission.ok_or(Error::State)?,
            indices: self.station.ht_indices,
            epoch: self.station.epoch.clone(),
            expected: self.station.epoch.load(Ordering::Acquire),
            failed: self.station.failed.clone(),
        })
    }
    pub(crate) fn prepare_station_ht(
        &mut self,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if self.phase != Hardware::MacConfigured || self.station.phase != Phase::Dormant {
            return Err(Error::State);
        }
        if self.station.ht.is_some() {
            return self.check_station_policy(environment);
        }
        let base = self
            .station
            .calibration
            .as_ref()
            .ok_or(Error::Profile)?
            .clone();
        let Some(grant) = environment.ht20(base.clone())? else {
            return Ok(());
        };
        if !grant.matches(&base) {
            return Err(Error::Profile);
        }
        let indices = grant.gains(&environment.domain()?, self.permission.ok_or(Error::State)?)?;
        self.phase = Hardware::Failed;
        grant.program(&self.io, indices)?;
        self.station.ht_indices = indices;
        self.station.ht = Some(grant);
        self.phase = Hardware::MacConfigured;
        Ok(())
    }
    pub(crate) fn abort_station(&mut self) {
        self.station.fail();
        if self.phase != Hardware::Stopped {
            let _ = self.stop_packets();
        }
    }
    pub(crate) async fn start_station_service(
        &mut self,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if self.station_phase() != Phase::Dormant || self.phase != Hardware::MacConfigured {
            return Err(Error::State);
        }
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        self.station.phase = Phase::Starting;
        let result = async {
            self.check_station_policy(environment)?;
            super::super::ht::wait(
                self.station
                    .calibration
                    .as_ref()
                    .ok_or(Error::State)?
                    .clone(),
                self.station.ht.clone(),
                self.permission.ok_or(Error::State)?,
                environment,
                self.awake_station(),
            )
            .await?;
            let base = self
                .station
                .calibration
                .as_ref()
                .ok_or(Error::State)?
                .clone();
            let ht = self.station.ht.clone();
            let start = || {
                self.check_station_policy(environment)
                    .map_err(|_| RadioError::Power(super::super::channel_power::Error::Policy))?;
                self.start_packets()
            };
            let publish = || {
                (if let Some(ht) = &ht {
                    ht.invoke(start)
                } else {
                    base.with_current(start)
                })
                .map_err(Error::Radio)
            };
            if let Some(admission) = environment.admission() {
                admission.publish(Error::State, publish)?;
            } else {
                publish()?;
            }
            let now = environment.now_ms();
            self.station.last_now = now;
            self.station.last_peer = now;
            self.station.phase = Phase::Passive;
            Ok(())
        }
        .await;
        attempt.armed = false;
        if result.is_err() {
            self.abort_station();
        }
        result
    }
    fn cache_candidate(&mut self, candidate: Candidate, now: u64) {
        if let Some(entry) = self
            .station
            .cache
            .iter_mut()
            .find(|entry| entry.candidate.bss.bssid == candidate.bss.bssid)
        {
            *entry = Entry {
                candidate,
                seen: now,
            };
        } else {
            if self.station.cache.len() == 32 {
                let index = self
                    .station
                    .cache
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.seen)
                    .map(|(index, _)| index)
                    .unwrap();
                self.station.cache.swap_remove(index);
            }
            self.station.cache.push(Entry {
                candidate,
                seen: now,
            });
        }
    }
    fn queue_station(
        &mut self,
        mut bytes: Vec<u8>,
        kind: Kind,
        now: u64,
        sequence: bool,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if self.station.pending.is_some() || !self.transmit_ready() {
            return Err(Error::Busy);
        }
        super::super::station_control::radio_on(&self.io)?;
        if sequence {
            bytes[22..24].copy_from_slice(&(self.station.sequence << 4).to_le_bytes());
            self.station.sequence = (self.station.sequence + 1) & 4095;
        }
        let rate = if matches!(kind, Kind::Data) {
            let rates = self
                .station
                .plan
                .as_ref()
                .ok_or(Error::State)?
                .legacy_rates()
                .0;
            if let Some(profile) = self.station.ht_profile {
                (0u8..8)
                    .rev()
                    .find(|m| profile.tx_mcs()[0] & (1 << m) != 0)
                    .map(|m| m + 12)
                    .ok_or(Error::Profile)?
            } else {
                [11, 10, 9, 8, 7, 6, 3, 5, 4, 2, 1, 0]
                    .into_iter()
                    .find(|rate| rates & (1 << rate) != 0)
                    .ok_or(Error::Profile)?
            }
        } else {
            0
        };
        let calibration = self
            .station
            .calibration
            .as_ref()
            .ok_or(Error::Profile)?
            .clone();
        let ht = self.station.ht.clone();
        let aggregate = if matches!(kind, Kind::Data) {
            self.station.aggregate(&bytes, now)
        } else {
            None
        };
        let mut publish = || {
            let op = || {
                self.check_station_policy(environment)
                    .map_err(|_| RadioError::Power(super::super::channel_power::Error::Policy))?;
                self.submit_aggregate(&bytes, rate, aggregate, matches!(kind, Kind::Data))
            };
            if let Some(ht) = &ht {
                ht.invoke(op)
            } else {
                calibration.with_current(op)
            }
            .map_err(Error::Radio)
        };
        let id = if let Some(admission) = environment.admission() {
            admission.publish(Error::State, publish)?
        } else {
            publish()?
        };
        self.station.pending = Some(Pending {
            id,
            kind,
            bytes,
            deadline: now.saturating_add(1000),
        });
        Ok(())
    }
    pub(crate) async fn connect_station(
        &mut self,
        bssid: [u8; 6],
        ssid: &[u8],
        mode: SecurityMode,
        pmk: Option<Zeroizing<[u8; 32]>>,
        ies: &[u8],
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if self.station_phase() != Phase::Passive || self.station.plan.is_some() {
            return Err(Error::State);
        }
        if mode.is_wpa2() != pmk.is_some() {
            return Err(Error::Profile);
        }
        self.check_station_policy(environment)?;
        let now = environment.now_ms();
        let candidate = self
            .station_candidates(now)
            .into_iter()
            .find(|candidate| candidate.bss.bssid == bssid)
            .ok_or(Error::Profile)?;
        let has_wmm = narf_wireless::wmm::Parameters::parse(&candidate.bss.information_elements)
            .map_err(|_| Error::Profile)?
            .is_some();
        let mut plan = if self.station.ht.is_some() && has_wmm {
            JoinPlan::prepare_with_phy(
                &candidate.bss,
                self.local().ok_or(Error::State)?,
                ssid,
                mode,
                super::super::ht::local(),
            )
        } else {
            JoinPlan::prepare(
                &candidate.bss,
                self.local().ok_or(Error::State)?,
                ssid,
                mode,
            )
        }
        .map_err(Error::Management)?;
        plan.append_sme_ies(ies).map_err(Error::Management)?;
        let (rates, basic) = plan.legacy_rates();
        let capability = candidate.bss.capability;
        let wmm = narf_wireless::wmm::Parameters::parse(&candidate.bss.information_elements)
            .map_err(|_| Error::Profile)?;
        if let Some(p) = wmm {
            super::super::wmm::admit(p, capability & 0x400 != 0)?;
        }
        if rates & 1 == 0 || basic & 1 == 0 || basic & !0x15f != 0 {
            return Err(Error::Profile);
        }
        self.station.phase = Phase::Joining;
        self.station.candidate = Some(candidate);
        self.station.plan = Some(plan);
        self.station.pmk = pmk;
        self.station.capability = capability;
        self.station.wmm = wmm;
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        let result = async {
            super::super::ht::wait(
                self.station
                    .calibration
                    .as_ref()
                    .ok_or(Error::State)?
                    .clone(),
                self.station.ht.clone(),
                self.permission.ok_or(Error::State)?,
                environment,
                self.prepare_station_peer(bssid, rates, basic, capability),
            )
            .await?;
            let auth = self
                .station
                .plan
                .as_mut()
                .ok_or(Error::State)?
                .start_authentication()
                .map_err(Error::Management)?
                .to_vec();
            self.queue_station(auth, Kind::Authentication, now, true, environment)?;
            self.station.phase = Phase::Authentication;
            self.station.deadline = now.saturating_add(5000);
            self.station.last_peer = now;
            loop {
                let idle = self.progress_station_inner(environment)?;
                if self.station.phase == Phase::Configuring {
                    self.check_station_policy(environment)?;
                    let (rates, basic) = self
                        .station
                        .plan
                        .as_ref()
                        .ok_or(Error::State)?
                        .legacy_rates();
                    self.station_publication(environment, || {
                        super::super::station_control::configure_rates(
                            &self.io,
                            rates,
                            basic,
                            self.station.capability,
                        )
                    })?;
                    if let Some(p) = self.station.wmm {
                        self.program_station_edca(p)?;
                        self.check_station_policy(environment)?;
                        self.packet.qos = true;
                    }
                    if let Some(profile) = self.station.ht_profile {
                        if self.station.wmm.is_none()
                            || profile.operation().protection() != 0
                            || profile.tx_sgi20()
                            || profile.rx_sgi20()
                        {
                            return Err(Error::Profile);
                        }
                        let ht = self.station.ht.as_ref().ok_or(Error::Profile)?;
                        ht.invoke(|| super::super::station_control::ht_timing(&self.io))?;
                        ht.readback(&self.io, self.station.ht_indices, true)?;
                        self.packet.ht = true;
                    }
                    self.station.linked_at = Some(environment.now_ms());
                    let base = self
                        .station
                        .calibration
                        .as_ref()
                        .ok_or(Error::State)?
                        .clone();
                    let ht = self.station.ht.clone();
                    let permission = self.permission.ok_or(Error::State)?;
                    super::super::ht::wait(
                        base,
                        ht,
                        permission,
                        environment,
                        self.complete_station_peer_admitted(
                            bssid,
                            self.station.aid.ok_or(Error::State)?,
                            environment.admission().map(Arc::as_ref),
                            |owner| {
                                owner.check_station_policy(environment).map_err(|_| {
                                    RadioError::Power(super::super::channel_power::Error::Policy)
                                })
                            },
                        ),
                    )
                    .await?;
                    self.check_station_policy(environment)?;
                    self.station.native_associated = true;
                    // core.c BSS_CHANGED_ASSOC: update_rate_tbl(sta, 0).
                    self.install_station_rate_mask(
                        super::super::rate_adaptive::STA_INIT,
                        environment,
                    )
                    .await?;
                    if mode.is_wpa2() {
                        let candidate = self.station.candidate.as_ref().ok_or(Error::State)?;
                        let body = self
                            .station
                            .plan
                            .as_ref()
                            .ok_or(Error::State)?
                            .rsn_body()
                            .ok_or(Error::State)?;
                        let pmk = self.station.pmk.take().ok_or(Error::State)?;
                        self.station.security = Some(
                            Security::new(
                                self.local().ok_or(Error::State)?,
                                bssid,
                                &pmk,
                                &body,
                                candidate.rsne.as_deref().ok_or(Error::Profile)?,
                                candidate.rsnxe.as_deref(),
                                self.station.sequence,
                            )
                            .map_err(Error::Security)?,
                        );
                        self.station.phase = Phase::FourWay;
                        self.station.deadline = environment.now_ms().saturating_add(10_000);
                    } else {
                        self.station.phase = Phase::Open;
                    }
                    // A native peer command can have queued deauthentication
                    // or early EAPOL while this owner awaited its receipt.
                    // Drain that actual RX generation before publishing link.
                    continue;
                }
                if idle
                    && self.station.phase == Phase::Open
                    && self.station.native_associated
                    && self
                        .station
                        .security
                        .as_ref()
                        .is_none_or(Security::port_open)
                {
                    self.station.admitted = true;
                    return Ok(());
                }
                environment.pause().await;
            }
        }
        .await;
        attempt.armed = false;
        if result.is_err() {
            self.abort_station();
        }
        result
    }
    pub(crate) fn progress_station(
        &mut self,
        environment: &impl Environment,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if self.station_phase() == Phase::Failed {
            self.abort_station();
            return Err(Error::State);
        }
        if !matches!(self.station.phase, Phase::Passive | Phase::Open) {
            return Err(Error::State);
        }
        let result = self.progress_station_inner(environment);
        if result.is_err() {
            self.abort_station();
        }
        if result?
            && self.station_peer().is_some()
            && self
                .station
                .security
                .as_ref()
                .is_none_or(Security::port_open)
        {
            Ok(self.station.received.drain(..).collect())
        } else {
            Ok(Vec::new())
        }
    }
    fn progress_station_inner(&mut self, environment: &impl Environment) -> Result<bool, Error> {
        if self.station.failed.load(Ordering::Acquire) || self.phase != Hardware::Running {
            return Err(Error::State);
        }
        self.check_station_policy(environment)?;
        super::super::station_control::radio_on(&self.io)?;
        let now = environment.now_ms();
        if now < self.station.last_now {
            return Err(Error::State);
        }
        self.station.last_now = now;
        if self.station.phase != Phase::Passive
            && self.station.phase != Phase::Open
            && now >= self.station.deadline
        {
            return Err(Error::Timeout);
        }
        if self.station.phase == Phase::Open && now.saturating_sub(self.station.last_peer) >= 5000 {
            return Err(Error::PeerLost);
        }
        if self.station.admitted
            && now >= self.station.deadline
            && self
                .station
                .security
                .as_ref()
                .is_some_and(Security::handshake_active)
        {
            return Err(Error::Timeout);
        }
        if let Some(pending) = &self.station.pending {
            if now >= pending.deadline {
                return Err(Error::Timeout);
            }
            if let Some(delivery) = self.poll_delivery()? {
                let pending = self.station.pending.take().ok_or(Error::State)?;
                if delivery.id != pending.id || delivery.bytes != pending.bytes {
                    return Err(Error::Profile);
                }
                if matches!(pending.kind, Kind::Eapol) {
                    let security = self.station.security.as_ref().ok_or(Error::State)?;
                    if security.pending_frame() != Some(delivery.bytes.as_slice()) {
                        return Err(Error::Profile);
                    }
                    // A real host receipt is necessary but queued DMA must be
                    // copied under the still-closed capture generation first.
                    self.station.delivered_reply = Some(pending);
                } else if matches!(pending.kind, Kind::Data) {
                    let own = self.local().ok_or(Error::State)?;
                    self.station.tx_status(&pending.bytes, now, own)?;
                }
            }
        }
        let own = self.local().ok_or(Error::State)?;
        let peer = self
            .station
            .candidate
            .as_ref()
            .map(|candidate| candidate.bss.bssid);
        if self.station.receive_open() {
            self.station.service_ba(now, own)?;
        }
        let mut idle = false;
        for _ in 0..64 {
            let step = self.poll_receive_step()?;
            if !step.consumed {
                idle = true;
                break;
            }
            let Some(frame) = step.packet else {
                continue;
            };
            // _rtl88ee_translate_rx_signal_stuff → rtl_process_phyinfo.
            if let (Some(pwdb), Some(bssid)) = (frame.pwdb(), peer) {
                if super::super::rate_adaptive::matches_bssid(frame.bytes(), bssid) {
                    self.station.ra.sample(pwdb);
                }
            }
            if let Ok(candidate) = Candidate::receive(&frame, own, self.station.ht.is_some()) {
                if self.station.phase == Phase::Passive {
                    self.cache_candidate(candidate, now);
                } else if Some(candidate.bss.bssid) == peer {
                    let old = self.station.candidate.as_ref().ok_or(Error::State)?;
                    if candidate.bss.ssid != old.bss.ssid
                        || candidate.rsne != old.rsne
                        || candidate.rsnxe != old.rsnxe
                        || self.station.ht_profile.is_some()
                            && association::phy::ApElements::parse(
                                &candidate.bss.information_elements,
                            ) != association::phy::ApElements::parse(
                                &old.bss.information_elements,
                            )
                    {
                        return Err(Error::Profile);
                    }
                    if self.station.native_associated {
                        self.update_station_edca(&candidate.bss.information_elements, environment)?;
                    }
                    self.station.last_peer = now;
                }
                continue;
            }
            let bytes = frame.bytes();
            let bar = bytes.len() == 20 && bytes[0] == 0x84;
            if bytes.len() < 24 && !bar || Some(bytes[10..16].try_into().unwrap()) != peer {
                continue;
            }
            if matches!(bytes[0], 0xa0 | 0xc0)
                && bytes[16..22] == bytes[10..16]
                && (bytes[4..10] == own || bytes[4..10] == [255; 6])
            {
                if bytes[1] & 0xc7 != 0 || bytes.get(24..26).is_none_or(|reason| reason == [0, 0]) {
                    return Err(Error::Profile);
                }
                return Err(Error::PeerLost);
            }
            let peer_address = peer.ok_or(Error::State)?;
            if bytes[0] == 0xd0
                && self.station.ht_profile.is_some()
                && self.station.receive_open()
                && bytes.len() >= 26
                && bytes[1] & 0xc7 == 0
                && bytes[4..10] == own
                && bytes[16..22] == bytes[10..16]
                && bytes[22] & 15 == 0
                && bytes[24] == 3
            {
                match bytes[25] {
                    // ieee80211_process_addba_request; the response A-MSDU bit
                    // follows SUPPORTS_AMSDU_IN_AMPDU, which rtlwifi sets.
                    0 if bytes.len() >= 33 => {
                        if self.station.controls.len() == 8 {
                            return Err(Error::Allocation);
                        }
                        let token = bytes[26];
                        let p = u16::from_le_bytes([bytes[27], bytes[28]]);
                        let timeout = u16::from_le_bytes([bytes[29], bytes[30]]);
                        let ssn = u16::from_le_bytes([bytes[31], bytes[32]]) >> 4;
                        let (status, tid, buf) =
                            self.station.addba_request(token, p, timeout, ssn, now);
                        let params = (buf << 6) | (u16::from(tid) << 2) | 2 | 1;
                        let mut response = action_header(peer_address, own);
                        response.extend_from_slice(&[3, 1, token]);
                        response.extend_from_slice(&status.to_le_bytes());
                        response.extend_from_slice(&params.to_le_bytes());
                        response.extend_from_slice(&timeout.to_le_bytes());
                        self.station.controls.push_back(response);
                    }
                    1 if bytes.len() >= 33 => {
                        let token = bytes[26];
                        let status = u16::from_le_bytes([bytes[27], bytes[28]]);
                        let p = u16::from_le_bytes([bytes[29], bytes[30]]);
                        let timeout = u16::from_le_bytes([bytes[31], bytes[32]]);
                        self.station.addba_response(token, status, p, timeout, now);
                    }
                    // ieee80211_process_delba: initiator set tears down our
                    // recipient session; clear ends our originator session
                    // (AGG_STOP_PEER_REQUEST, no DELBA of our own).
                    2 if bytes.len() >= 30 => {
                        let p = u16::from_le_bytes([bytes[26], bytes[27]]);
                        let tid = usize::from(p >> 12) & 7;
                        if p & (1 << 11) != 0 {
                            if let Some(session) = self.station.rx_ba[tid].take() {
                                session.reorder.retire();
                            }
                        } else {
                            self.station.tx_ba[tid] = None;
                        }
                    }
                    _ => {}
                }
                continue;
            }
            // ieee80211_rx_h_ctrl BlockAckReq: release up to its SSN, refresh
            // the session timer; a BAR for a TID without a session sends one
            // recipient DELBA QSTA_REQUIRE_SETUP per TID.
            if bar {
                if bytes[4..10] != own
                    || self.station.ht_profile.is_none()
                    || !self.station.receive_open()
                {
                    continue;
                }
                let control = u16::from_le_bytes([bytes[16], bytes[17]]);
                let tid = control >> 12;
                let ssn = u16::from_le_bytes([bytes[18], bytes[19]]) >> 4;
                match self
                    .station
                    .rx_ba
                    .get_mut(usize::from(tid))
                    .and_then(Option::as_mut)
                {
                    Some(session) => {
                        if session.timeout_tu != 0 {
                            session.last_rx = now;
                        }
                        let released = session
                            .reorder
                            .advance(ssn, now.saturating_mul(1_000_000))
                            .unwrap_or_default();
                        self.station.release(released)?;
                    }
                    None if self.station.unexpected_ba & (1 << tid) == 0 => {
                        if self.station.controls.len() == 8 {
                            return Err(Error::Allocation);
                        }
                        self.station.unexpected_ba |= 1 << tid;
                        self.station.controls.push_back(delba(
                            peer_address,
                            own,
                            tid,
                            REASON_REQUIRE_SETUP,
                        ));
                    }
                    None => {}
                }
                continue;
            }
            let management = matches!(
                self.station.phase,
                Phase::Authentication | Phase::Association
            ) && matches!(bytes[0], 0xb0 | 0x10);
            let key = eapol(bytes, own, peer.ok_or(Error::State)?);
            let data = self.station.phase == Phase::Open
                && (bytes[0] == 8 || self.station.wmm.is_some() && bytes[0] == 0x88);
            if management || key && self.station.phase != Phase::Passive || data {
                if self.station.incoming.len() >= 64 {
                    return Err(Error::Allocation);
                }
                // ieee80211_rx_reorder_ampdu: unicast QoS DATA from the peer
                // on a session TID is ordered before CCMP/PN and delivery.
                let session_tid = (data
                    && bytes[0] == 0x88
                    && bytes.len() >= 26
                    && bytes[1] & 3 == 2
                    && bytes[4..10] == own
                    && bytes[22] & 15 == 0)
                    .then_some(usize::from(bytes[24] & 15))
                    .filter(|tid| self.station.rx_ba.get(*tid).is_some_and(Option::is_some));
                let sequence = u16::from_le_bytes([bytes[22], bytes[23]]) >> 4;
                let aggregated = frame.aggregated();
                let captured = Captured {
                    admitted: self.station.receive_open(),
                    epoch: self.station.epoch.load(Ordering::Acquire),
                    frame,
                };
                if let Some(tid) = session_tid {
                    if let Some(session) = self.station.rx_ba[tid].as_mut() {
                        session.last_rx = now;
                        let released = session
                            .reorder
                            .push(sequence, now.saturating_mul(1_000_000), captured)
                            .unwrap_or_default();
                        self.station.release(released)?;
                    }
                } else if !aggregated {
                    // A-MPDU membership without an accepted session is refused
                    // before CCMP/PN.
                    self.station.incoming.push_back(captured);
                }
            }
        }
        if idle {
            if let Some(reply) = self.station.delivered_reply.take() {
                let security = self.station.security.as_mut().ok_or(Error::State)?;
                security
                    .reply_delivered(reply.bytes.len())
                    .map_err(Error::Security)?;
                let open = security.port_open();
                self.station.retire_receive();
                if open {
                    self.station.phase = Phase::Open;
                }
            }
        }
        while self.station.pending.is_none() && self.station.delivered_reply.is_none() {
            let Some(Captured {
                frame,
                mut admitted,
                epoch,
            }) = self.station.incoming.pop_front()
            else {
                break;
            };
            let bytes = frame.bytes();
            let key = eapol(bytes, own, peer.ok_or(Error::State)?);
            let private = private_eapol(bytes, own, peer.ok_or(Error::State)?);
            if epoch != self.station.epoch.load(Ordering::Acquire) {
                if !private {
                    continue;
                }
                admitted = false; // private complete plaintext EAPOL alone may cross M2 receipt.
            }
            match self.station.phase {
                Phase::Authentication => {
                    if let Some(assoc) = self
                        .station
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .authentication_response(bytes)
                        .map_err(Error::Management)?
                    {
                        let mut assoc = assoc.to_vec();
                        if self.station.wmm.is_some() {
                            assoc.extend_from_slice(&narf_wireless::wmm::INFORMATION);
                        }
                        self.queue_station(assoc, Kind::Association, now, true, environment)?;
                        self.station.phase = Phase::Association;
                        self.station.deadline = now.saturating_add(5000);
                    }
                }
                Phase::Association => {
                    if let Some(aid) = self
                        .station
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .association_response(bytes)
                        .map_err(Error::Management)?
                    {
                        let capability = u16::from_le_bytes([bytes[24], bytes[25]]);
                        if self.station.wmm.is_some() {
                            let p = narf_wireless::wmm::Parameters::parse(
                                bytes.get(30..).ok_or(Error::Profile)?,
                            )
                            .map_err(|_| Error::Profile)?
                            .ok_or(Error::Profile)?;
                            super::super::wmm::admit(
                                p,
                                self.station.capability & capability & 0x400 != 0,
                            )?;
                            self.station.wmm = Some(p);
                        }
                        self.station.capability &= capability;
                        self.station.ht_profile = self
                            .station
                            .plan
                            .as_ref()
                            .and_then(|p| p.negotiated_phy())
                            .map(|p| *p.ht());
                        if self.station.ht_profile.is_some_and(|p| {
                            p.operation().primary() != 1 || p.operation().protection() != 0
                        }) {
                            return Err(Error::Profile);
                        }
                        self.station.aid = Some(aid);
                        self.station.phase = Phase::Configuring;
                        return Ok(false);
                    }
                }
                Phase::FourWay | Phase::Open => {
                    let aggregate =
                        bytes[0] == 0x88 && bytes.get(24).is_some_and(|q| q & 0x80 != 0);
                    if !key && (!admitted || !self.station.receive_open()) {
                        continue;
                    }
                    if aggregate {
                        if self.station.ht_profile.is_none()
                            || bytes[22] & 15 != 0
                            || bytes
                                .get(24..26)
                                .is_none_or(|q| q[0] & 0xf0 != 0x80 || q[1] != 0)
                        {
                            continue;
                        }
                        let frames = if let Some(security) = &mut self.station.security {
                            security.receive_amsdu(&frame).map_err(Error::Security)?
                        } else {
                            if bytes[1] & 0xc7 != 2 || bytes[16..22] == [0; 6] || bytes[16] & 1 != 0
                            {
                                continue;
                            }
                            narf_wireless::amsdu::decode(
                                &bytes[26..],
                                own,
                                bytes[4..10].try_into().unwrap(),
                            )
                            .ok()
                        };
                        if let Some(frames) = frames {
                            if self.station.received.len() + frames.len() > 256 {
                                return Err(Error::Allocation);
                            }
                            self.station.received.extend(frames);
                            self.station.last_peer = now;
                        }
                        continue;
                    }
                    if let Some(security) = &mut self.station.security {
                        let handshake_active = security.handshake_active();
                        match security
                            .receive_with_nonce(&frame, || environment.fresh_nonce())
                            .map_err(Error::Security)?
                        {
                            station_security::Rx::Ignored => {}
                            station_security::Rx::ReplyReady => {
                                let reply = security.pending_frame().ok_or(Error::State)?.to_vec();
                                if self.station.admitted && !handshake_active {
                                    self.station.deadline = now.saturating_add(5000);
                                }
                                self.station.retire_receive();
                                self.station.controls.clear();
                                self.queue_station(reply, Kind::Eapol, now, false, environment)?;
                                self.station.last_peer = now;
                            }
                            station_security::Rx::Data(normalized) => {
                                if let Some(bytes) =
                                    ethernet(&normalized, own, peer.ok_or(Error::State)?)
                                {
                                    if self.station.received.len() == 64 {
                                        return Err(Error::Allocation);
                                    }
                                    self.station.received.push_back(bytes);
                                    self.station.last_peer = now;
                                }
                            }
                        }
                    } else if let Some(bytes) = ethernet(bytes, own, peer.ok_or(Error::State)?) {
                        if self.station.received.len() == 64 {
                            return Err(Error::Allocation);
                        }
                        self.station.received.push_back(bytes);
                        self.station.last_peer = now;
                    }
                }
                _ => {}
            }
        }
        if self.station.pending.is_none()
            && self.station.delivered_reply.is_none()
            && self.station.receive_open()
        {
            if let Some(frame) = self.station.controls.pop_front() {
                self.queue_station(frame, Kind::Control, now, true, environment)?;
            }
        }
        Ok(idle)
    }
    /// `rtl88ee_update_hal_rate_mask` for the bound AP at `level`, from
    /// the association's legacy intersection (`supp_rates[0]`) and HT
    /// TX MCS set (`ht_cap.mcs.rx_mask[0]`). SGI is never offered: the
    /// LGI-only profile refuses an AP SGI20 join.
    async fn install_station_rate_mask(
        &mut self,
        level: u8,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        let (rates, _) = self
            .station
            .plan
            .as_ref()
            .ok_or(Error::State)?
            .legacy_rates();
        let mcs = self.station.ht_profile.map(|profile| profile.tx_mcs()[0]);
        let payload = super::super::rate_adaptive::rate_mask(rates, mcs, level, false);
        let base = self
            .station
            .calibration
            .as_ref()
            .ok_or(Error::State)?
            .clone();
        let ht = self.station.ht.clone();
        let permission = self.permission.ok_or(Error::State)?;
        super::super::ht::wait(
            base,
            ht,
            permission,
            environment,
            self.install_rate_mask(payload, environment.admission().map(Arc::as_ref)),
        )
        .await?;
        self.check_station_policy(environment)
    }
    /// `rtl88e_dm_watchdog` → `rtl88e_dm_refresh_rate_adaptive_mask`: every
    /// `RTL_WATCHDOG_TIME`, outside firmware LPS, a linked station whose
    /// smoothed PWDB crossed its hysteresis re-sends the mask at the new
    /// level. Returns whether a mask was sent. Failure is terminal.
    pub(crate) async fn refresh_station_rate_mask(
        &mut self,
        environment: &impl Environment,
    ) -> Result<bool, Error> {
        if !self.station_linked()
            || self.leisure()
            || !self.transmit_ready()
            || self.rate_mask().is_none()
            || !self.station.ra.due(environment.now_ms())
        {
            return Ok(false);
        }
        let Some(level) = self.station.ra.refresh() else {
            return Ok(false);
        };
        let result = self.install_station_rate_mask(level, environment).await;
        if result.is_err() {
            self.abort_station();
        }
        result?;
        self.station.ra.commit(level);
        Ok(true)
    }
    /// Smoothed station PWDB (`dm.undec_sm_pwdb`) and RA level.
    pub(crate) fn station_rate_state(&self) -> (i64, u8) {
        (self.station.ra.smoothed(), self.station.ra.level())
    }
    /// Linux `rtl_lps_enter_core` link gate: associated, not
    /// `being_setkey` (RSNA port open, no handshake frame outstanding).
    pub(crate) fn station_linked(&self) -> bool {
        self.station_peer().is_some()
            && matches!(self.station.phase, Phase::Open)
            && self
                .station
                .security
                .as_ref()
                .is_none_or(|security| security.port_open() && security.pending_frame().is_none())
    }
    pub(crate) fn station_transmit_ready(&self) -> bool {
        self.station_peer().is_some()
            && self.station.pending.is_none()
            && self.station.delivered_reply.is_none()
            && self.station.controls.is_empty()
            && self.transmit_ready()
            && self
                .station
                .security
                .as_ref()
                .is_none_or(|security| security.port_open() && security.pending_frame().is_none())
    }
    pub(crate) fn send_station_ethernet(
        &mut self,
        bytes: &[u8],
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if !self.station_transmit_ready() {
            return Err(Error::Busy);
        }
        let result = (|| {
            self.check_station_policy(environment)?;
            let own = self.local().ok_or(Error::State)?;
            let peer = self.station_peer().ok_or(Error::State)?;
            // Classify before forming the header: the TID selects the AC
            // ring/QSEL and is authenticated by CCMP's nonce priority.
            let tid = self
                .station
                .wmm
                .as_ref()
                .map(|p| super::super::wmm::priority(bytes, p));
            let frame = if let Some(security) = &mut self.station.security {
                if let Some(tid) = tid {
                    security.transmit_ethernet_qos(bytes, tid)
                } else {
                    security.transmit_ethernet(bytes)
                }
                .map_err(Error::Security)?
            } else {
                if !(14..=1514).contains(&bytes.len())
                    || bytes[6..12] != own
                    || bytes[..6] == [0; 6]
                {
                    return Err(Error::Profile);
                }
                let protocol = u16::from_be_bytes([bytes[12], bytes[13]]);
                if protocol < 0x600 || matches!(protocol, 0x888e | 0x80f3 | 0x8137) {
                    return Err(Error::Profile);
                }
                let mut frame = vec![if tid.is_some() { 0x88 } else { 8 }, 1, 0, 0];
                frame.extend_from_slice(&peer);
                frame.extend_from_slice(&own);
                frame.extend_from_slice(&bytes[..6]);
                let counter = match tid {
                    Some(tid) => &mut self.station.qos_sequence[usize::from(tid)],
                    None => &mut self.station.sequence,
                };
                frame.extend_from_slice(&(*counter << 4).to_le_bytes());
                *counter = (*counter + 1) & 4095;
                if let Some(tid) = tid {
                    frame.extend_from_slice(&[tid, 0]);
                }
                frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
                frame.extend_from_slice(&bytes[12..]);
                frame
            };
            self.queue_station(frame, Kind::Data, environment.now_ms(), false, environment)
        })();
        if result.is_err() {
            self.abort_station();
        }
        result
    }
    pub(crate) async fn disconnect_station(&mut self) -> Result<(), Error> {
        if self.station.phase == Phase::Stopped {
            return Ok(());
        }
        self.station.phase = Phase::Stopping;
        self.station.received.clear();
        self.station.retire_receive();
        self.station.controls.clear();
        self.station.incoming.clear();
        self.station.retire_ba();
        self.station.pmk = None;
        if let Some(security) = &mut self.station.security {
            security.fail();
        }
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        let result = self.disconnect_station_peer().await.map_err(Error::Radio);
        attempt.armed = false;
        if result.is_err() {
            self.abort_station();
        } else {
            self.station.native_associated = false;
            self.station.phase = Phase::Stopped;
        }
        result
    }
}
