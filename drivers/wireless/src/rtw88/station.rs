// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8821CE/RTL8822CE channel1 host station state. The exact firmware Owner
//! keeps its native backend; this state never owns or reconstructs hardware.
use super::{
    firmware_transport::{self, Io},
    packet_core::{self as packet, Frame as Mpdu, Receipt},
    station_control::{self, Admission},
};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec, vec::Vec};
use narf_wireless::{
    association::{self, JoinPlan, ObservedBss, SecurityMode},
    reg::{
        witness::{self, BeaconWitness, ScanGeneration},
        RegulatoryDomain,
    },
    station_security::{self, RawFrame, Security},
};
use zeroize::Zeroizing;
// One whole mandatory A-MSDU must fit after a bounded ordinary-frame batch.
const RECEIVE_OUTPUTS: usize = 64 + narf_wireless::amsdu::MAX_SUBFRAMES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    State,
    Busy,
    Profile,
    Entropy,
    Timeout,
    PeerLost,
    Transport(packet::Error),
    Native(firmware_transport::Error),
    Management(association::Error),
    Security(station_security::Error),
}
impl From<packet::Error> for Error {
    fn from(error: packet::Error) -> Self {
        Self::Transport(error)
    }
}
impl From<firmware_transport::Error> for Error {
    fn from(error: firmware_transport::Error) -> Self {
        Self::Native(error)
    }
}
impl From<association::Error> for Error {
    fn from(error: association::Error) -> Self {
        Self::Management(error)
    }
}
impl From<station_security::Error> for Error {
    fn from(error: station_security::Error) -> Self {
        Self::Security(error)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Prepared,
    Passive,
    Authentication,
    Association,
    FourWay,
    Open,
    Failed,
    Stopped,
}
#[async_trait::async_trait]
pub(super) trait Environment: Send + Sync {
    fn now_ms(&self) -> u64;
    fn nonce(&self) -> Option<[u8; 32]>;
    async fn pause(&self);
}
pub(super) struct NativeEnvironment;
#[async_trait::async_trait]
impl Environment for NativeEnvironment {
    fn now_ms(&self) -> u64 {
        narf_time::monotonic_ns() / 1_000_000
    }
    fn nonce(&self) -> Option<[u8; 32]> {
        let mut bytes = [0; 32];
        narf_crypto::try_fill_random_bytes(&mut bytes).ok()?;
        Some(bytes)
    }
    async fn pause(&self) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Authentication,
    Association,
    Security,
    Data,
    RtsData,
    Decline,
    Ba,
    TxBa,
    /// HT SM Power Save action (`ieee80211_send_smps_action`); mac80211
    /// acts only on an acknowledged status, so a lost one is not fatal.
    Smps,
    /// Broadcast software-scan Probe Request: no ACK, so no CCX report.
    Probe,
}
struct Pending {
    id: u64,
    bytes: Vec<u8>,
    kind: Kind,
}
struct Entry {
    candidate: ObservedBss,
    seen: u64,
}
struct Attempt {
    admission: Admission,
    armed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.armed {
            self.admission.close();
        }
    }
}
pub(super) struct State {
    environment: Arc<dyn Environment>,
    own: [u8; 6],
    phase: Phase,
    admission: Admission,
    prepared: bool,
    extension: Option<Arc<super::station_profile::Grant>>,
    ht: Option<Arc<super::ht::Grant>>,
    rx_ba_grant: Option<Arc<super::rx_ba_power::Grant>>,
    rx_ba: super::rx_ba::Table,
    tx_ba_grant: Option<Arc<super::tx_ba_power::Grant>>,
    protection: Option<Arc<super::protection::Grant>>,
    /// Bound N2xC TX coding (`coding`, tag `C`) and its admitted flags.
    coding: Option<(Arc<super::qualification::Grant>, u8)>,
    /// Firmware RA_INFO still carries LDPC after a coding downgrade.
    coding_restore: bool,
    /// Bound N2xF DATA rate fallback (`fallback`, tag `F`).
    fallback: Option<Arc<super::qualification::Grant>>,
    /// Current random scan SA (`rtw_core_scan_start`).
    scan_address: Option<[u8; 6]>,
    /// Bound N2xQ all-TID QoS routing (`qos`, tag `Q`) and its AC set.
    qos: Option<(Arc<super::qualification::Grant>, u8)>,
    tx_ba: super::tx_ba::Originators,
    tx_config: Option<super::packet_format::Aggregation>,
    /// `sta->deflink.agg.max_rc_amsdu_len` from the latest firmware RA
    /// report (`fw.c::get_max_amsdu_len`); 0 is unlimited, as before any.
    amsdu_rc: usize,
    data_pending: VecDeque<Pending>,
    data_drain: Option<(u64, Option<u8>)>,
    qos_sequence: [u16; 8],
    local_ht: Option<association::phy::LocalPhy>,
    decline: Option<Vec<u8>>,
    wmm_requested: bool,
    wmm: Option<narf_wireless::wmm::Parameters>,
    data_profile: super::packet_format::DataProfile,
    peer_commit: Option<(u16, bool)>,
    associated_aid: Option<u16>,
    cache: Vec<Entry>,
    peer: Option<ObservedBss>,
    plan: Option<JoinPlan>,
    security: Option<Security>,
    incoming: VecDeque<(Mpdu, bool, u64, bool)>,
    ordered: VecDeque<(Mpdu, u64)>,
    received: VecDeque<Vec<u8>>,
    pending: Option<Pending>,
    delivered_reply: Option<Pending>,
    initial_nonce: Option<[u8; 32]>,
    sequence: u16,
    established: bool,
    deadline: u64,
    last_peer: u64,
    last_now: u64,
    tracking: Tracking,
    power_tracking: Option<Box<super::tracking8821c::Tracker>>,
    /// Committed operating primary (`channel_policy`); 1 is the base.
    channel: u8,
    /// Primary on which the last RF calibration (IQK) completed. Initial
    /// preparation calibrated channel 1; any other retune clears it, like
    /// Linux `rtw_set_channel` setting `need_rfk`.
    rfk_channel: Option<u8>,
    /// A native retune is in progress; the station reports Failed until it
    /// commits, so a cancelled retune never looks Passive again.
    retuning: bool,
    /// Accepted AP channel switch awaiting its countdown (`channel_policy::
    /// Switch`, mac80211 software CSA).
    switch: Option<super::channel_policy::Switch>,
    /// Block-mode switch done: TX stays blocked until a peer beacon arrives on
    /// the new primary (`mlme.c::ieee80211_chswitch_post_beacon`).
    switch_wait_beacon: bool,
    /// Bound N2xB HT40 record (identity loaded before the association
    /// request, bound with the HT program).
    ht40: Option<(Arc<super::qualification::Grant>, super::ht40::Record)>,
    /// Bound N2xV VHT80 record (identity loaded before the association
    /// request, bound with the HT program; never together with N2xB).
    vht: Option<(Arc<super::qualification::Grant>, super::vht::Record)>,
    /// Hardware runs the N2xB 40MHz pair or the N2xV 80MHz block
    /// (`ht40::program` / `vht::program` committed).
    wide: bool,
    /// Bound SU or MU beamformee entry (`bf.c::rtw_bf_assoc`), N2xV only.
    bfee: Option<super::bf::Bfee>,
    /// `bss_conf.mu_group` last programmed by `rtw_bf_set_gid_table`;
    /// zero from association (`mlme.c` resets it on disassociation).
    mu_group: super::bf::MuGroup,
    /// cfg80211 `beacon_found` for passive-only (RADAR / NO_IR) primaries
    /// (shared `narf_wireless::reg::witness`): admits association / CSA
    /// onto a passive-only primary only after a Beacon heard in its latest
    /// scan under the current policy snapshot.
    witness: BeaconWitness,
    /// Witness generation of the current scan dwell, if one is open.
    witness_scan: Option<ScanGeneration>,
    /// Separately qualified coexistence owner (`coex`, tag `K`).
    coex: Coexistence,
    /// Coexistence-driven `hal.txrx_1ss` (`main.c::rtw_set_txrx_1ss`).
    one_ss: OneSs,
    /// `rtw_watch_dog_work`'s `rtw_hci_dynamic_rx_agg` traffic window.
    rx_agg: rx_agg::RxAgg,
}
/// `hal.txrx_1ss` as the station follows it: the coexistence owner programs
/// `config_trx_mode`, the station limits DATA/RA to one stream without STBC
/// and tells the AP (`rtw_vif_smps_iter` -> `ieee80211_request_smps`).
#[derive(Default)]
struct OneSs {
    /// The hardware runs `config_trx_mode(A, A)`.
    on: bool,
    /// The native DATA profile still has to follow `on`.
    profile: bool,
    /// RA_INFO still has to follow `on` (next watchdog, as Linux's
    /// `rtw_phy_ra_info_update` -> `rtw_update_sta_info`).
    ra: bool,
    /// mac80211 `link->u.mgd.req_smps` is `IEEE80211_SMPS_STATIC`.
    smps_static: bool,
    /// SM Power Save action frame waiting for the control slot.
    frame: Option<Vec<u8>>,
}
/// The N2xK coexistence owner and its Linux trigger inputs.
#[derive(Default)]
struct Coexistence {
    facts: Option<super::coex::Facts>,
    grant: Option<Arc<super::qualification::Grant>>,
    owner: Option<Box<super::coex::Coex>>,
    /// Base gate captured at bind, for the synchronous `stop` restore.
    gate: Option<super::power_policy::Gate>,
    next: u64,
    scanning: bool,
    traffic: super::coex::Traffic,
    /// C2H events queued by `progress` (Linux `rtw_c2h_work`).
    c2h: VecDeque<Vec<u8>>,
}
/// One Linux coexistence trigger point.
enum CoexEvent {
    Start,
    Scan(Option<bool>),
    Switchband(bool),
    Connect(bool),
    Media(bool, u16),
    C2h(Vec<u8>),
    Watchdog(super::coex::Traffic),
    Works,
    /// ps.c `rtw_enter_ips` (`COEX_IPS_ENTER`) / `rtw_ips_pwr_up`
    /// (`COEX_IPS_LEAVE`).
    Ips(bool),
    /// ps.c `rtw_enter_lps_core` (`COEX_LPS_ENABLE`) /
    /// `rtw_leave_lps_core` (`COEX_LPS_DISABLE`).
    Lps(bool),
}
/// Separately qualified dynamic-mechanism watchdog (`dm`, tag `D`).
#[derive(Default)]
struct Tracking {
    facts: Option<super::dm::Facts>,
    grant: Option<Arc<super::qualification::Grant>>,
    /// RTL8822BE `N2BW` associated IQK bound to `grant` (`tracking8822b`).
    iqk: Option<Arc<super::qualification::Grant>>,
    tracker: Option<Box<super::dm::Tracker>>,
    next: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    ticks: u64,
}
/// Every dm register group: current admission, continuation and base gate.
struct Live<'a> {
    admission: &'a Admission,
    grant: &'a super::qualification::Grant,
    gate: &'a super::power_policy::Gate,
}
impl super::dm::Authority for Live<'_> {
    fn run<T>(
        &self,
        op: impl FnOnce() -> Result<T, firmware_transport::Error>,
    ) -> Result<T, firmware_transport::Error> {
        self.admission.run(|| self.grant.invoke(self.gate, op))
    }
    fn b22_indices(&self) -> Option<([[u8; super::tracking8822b::RATES]; 2], usize)> {
        self.gate.b22_rate_indices()
    }
    fn b22_temperature(&self, value: u8) -> Result<(), firmware_transport::Error> {
        self.gate.b22_temperature(value)
    }
    fn b22_channel(&self) -> Option<u8> {
        Some(self.gate.channel())
    }
}
/// Base-gate-only authority used to restore the base program.
struct Base<'a> {
    admission: &'a Admission,
    gate: &'a super::power_policy::Gate,
}
impl super::dm::Authority for Base<'_> {
    fn run<T>(
        &self,
        op: impl FnOnce() -> Result<T, firmware_transport::Error>,
    ) -> Result<T, firmware_transport::Error> {
        self.admission.run(|| self.gate.invoke(op))
    }
}
impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88Station")
            .field("phase", &self.phase)
            .field("established", &self.established)
            .finish_non_exhaustive()
    }
}
impl State {
    pub(super) fn new(
        own: [u8; 6],
        environment: Arc<dyn Environment>,
        admission: Admission,
    ) -> Self {
        Self {
            environment,
            own,
            phase: Phase::Prepared,
            admission,
            prepared: false,
            extension: None,
            ht: None,
            rx_ba_grant: None,
            rx_ba: super::rx_ba::Table::new(),
            tx_ba_grant: None,
            protection: None,
            coding: None,
            coding_restore: false,
            fallback: None,
            qos: None,
            scan_address: None,
            tx_ba: super::tx_ba::Originators::new(),
            tx_config: None,
            amsdu_rc: 0,
            data_pending: VecDeque::new(),
            data_drain: None,
            qos_sequence: [1; 8],
            local_ht: None,
            decline: None,
            wmm_requested: false,
            wmm: None,
            data_profile: super::packet_format::DataProfile::LEGACY,
            peer_commit: None,
            associated_aid: None,
            cache: Vec::new(),
            peer: None,
            plan: None,
            security: None,
            incoming: VecDeque::new(),
            ordered: VecDeque::new(),
            received: VecDeque::new(),
            pending: None,
            delivered_reply: None,
            initial_nonce: None,
            sequence: 1,
            established: false,
            deadline: 0,
            last_peer: 0,
            last_now: 0,
            tracking: Tracking::default(),
            power_tracking: None,
            channel: 1,
            rfk_channel: Some(1),
            retuning: false,
            ht40: None,
            vht: None,
            wide: false,
            bfee: None,
            mu_group: super::bf::MuGroup::default(),
            switch: None,
            switch_wait_beacon: false,
            witness: BeaconWitness::new(),
            witness_scan: None,
            coex: Coexistence::default(),
            one_ss: OneSs::default(),
            rx_agg: rx_agg::RxAgg::default(),
        }
    }
    /// Exact retained efuse antenna facts for the coexistence owner.
    pub(super) fn set_coex_facts(&mut self, facts: Option<super::coex::Facts>) {
        self.coex.facts = facts;
    }
    pub(super) fn coex_active(&self) -> bool {
        self.coex.owner.is_some()
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn coex(&self) -> Option<&super::coex::Coex> {
        self.coex.owner.as_deref()
    }
    fn coex_link(&self) -> super::coex::Link {
        super::coex::Link {
            now: self.last_now,
            connected: self.associated_aid.is_some(),
            scanning: self.coex.scanning,
            band5: super::band5::primary(self.channel),
            channel: self.channel,
            width: if self.vht.is_some() && self.wide {
                2
            } else {
                u8::from(self.ht40.is_some() && self.wide)
            },
            rssi: self
                .tracking
                .tracker
                .as_ref()
                .filter(|_| self.peer.is_some())
                .map(|t| t.min_rssi()),
            t_owns_retry: self.tx_ba_grant.is_some(),
        }
    }
    /// Bind the separately signed N2xK record at station start (Linux
    /// `rtw_power_on`) when it was qualified on the retained efuse facts.
    async fn coex_bind(&mut self, io: &mut impl Io) -> Result<(), Error> {
        let Some(facts) = self.coex.facts else {
            return Ok(());
        };
        let Some(g) = io.station_continuation(&super::coex::KIND)? else {
            return Ok(());
        };
        let gate = io.station_gate()?;
        let Some(owner) = super::coex::record(gate.did(), g.payload())
            .filter(|_| facts.did == gate.did() && g.check(&gate).is_ok())
            .and_then(|r| super::coex::Coex::new(r, facts))
        else {
            return Ok(());
        };
        self.coex.grant = Some(g);
        self.coex.owner = Some(Box::new(owner));
        self.coex.gate = Some(gate);
        self.coex_event(io, CoexEvent::Start).await
    }
    /// Run one coexistence trigger under the N2xK grant and send its H2C
    /// commands. A refused mode or hardware failure restores every register
    /// the owner touched under the base gate and unbinds coexistence.
    async fn coex_event(&mut self, io: &mut impl Io, event: CoexEvent) -> Result<(), Error> {
        let (Some(grant), Some(mut owner)) = (self.coex.grant.clone(), self.coex.owner.take())
        else {
            return Ok(());
        };
        let gate = io.station_gate()?;
        let admission = self.admission.clone();
        let link = self.coex_link();
        let live = Live {
            admission: &admission,
            grant: &grant,
            gate: &gate,
        };
        let result = match event {
            CoexEvent::Start => Box::pin(owner.start(io, &live, link)).await,
            CoexEvent::Scan(start) => Box::pin(owner.scan(io, &live, link, start)).await,
            CoexEvent::Switchband(to5g) => {
                let scan = self.coex.scanning;
                Box::pin(owner.switchband(io, &live, link, to5g, scan)).await
            }
            CoexEvent::Connect(start) => Box::pin(owner.connect(io, &live, link, start)).await,
            CoexEvent::Media(connect, interval) => {
                Box::pin(owner.media(io, &live, link, connect, interval)).await
            }
            CoexEvent::C2h(body) => Box::pin(owner.c2h(io, &live, link, &body))
                .await
                .map(Option::unwrap_or_default),
            CoexEvent::Watchdog(traffic) => {
                Box::pin(owner.watchdog(io, &live, link, traffic)).await
            }
            CoexEvent::Works => Box::pin(owner.poll(io, &live, link)).await,
            CoexEvent::Ips(enter) => Box::pin(owner.ips(io, &live, link, enter)).await,
            CoexEvent::Lps(enable) => Box::pin(owner.lps(io, &live, link, enable)).await,
        };
        // rtw_coex_mimo_ps -> rtw_set_txrx_1ss: the dm path diversity is
        // first returned to path A and held, then config_trx_mode runs.
        let result = match result {
            Ok(commands) => {
                let mut held = Ok(());
                if owner.txrx_1ss() && !owner.trx_1ss() {
                    if let Some(t) = self.tracking.tracker.as_mut() {
                        let base = Base {
                            admission: &admission,
                            gate: &gate,
                        };
                        held = Box::pin(t.hold_tx_path(io, &base)).await;
                    }
                }
                match held {
                    Ok(()) => Box::pin(owner.config_trx(io, &live))
                        .await
                        .map(|_| commands),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(commands) => {
                let on = owner.trx_1ss();
                self.coex.owner = Some(owner);
                self.follow_txrx_1ss(on);
                for words in commands {
                    grant.check(&gate)?;
                    station_control::send(io, words, Some(&admission)).await?;
                }
                Ok(())
            }
            Err(firmware_transport::Error::State) if admission.closed() => Err(Error::State),
            Err(e) => {
                let base = Base {
                    admission: &admission,
                    gate: &gate,
                };
                let commands = Box::pin(owner.restore(io, &base)).await?;
                self.follow_txrx_1ss(false);
                for words in commands {
                    station_control::send(io, words, Some(&admission)).await?;
                }
                self.coex = Coexistence {
                    facts: self.coex.facts,
                    ..Coexistence::default()
                };
                match e {
                    firmware_transport::Error::Gone => Err(Error::Native(e)),
                    _ => Ok(()),
                }
            }
        }
    }
    /// `main.c::rtw_set_txrx_1ss` after the coexistence owner changed
    /// `config_trx_mode`: the HT readback expects the new TX path at once;
    /// the DATA profile (`tx.c` STBC off, one-stream rates), RA_INFO
    /// (`rtw_update_sta_info` 1SS mask) and the SM Power Save request
    /// (`rtw_vif_smps_iter`) follow on the associated HT link.
    fn follow_txrx_1ss(&mut self, on: bool) {
        if on == self.one_ss.on {
            return;
        }
        self.one_ss.on = on;
        if let Some(h) = &self.ht {
            h.set_txrx_1ss(on);
        }
        if self.peer.is_none() {
            return;
        }
        self.one_ss.profile = true;
        self.one_ss.ra = true;
        // rtw_vif_smps_iter: associated stations only; mac80211
        // __ieee80211_request_smps_mgd sends nothing on a non-HT link or
        // for an unchanged request.
        if self.data_profile.mcs != 0
            && self.associated_aid.is_some()
            && self.one_ss.smps_static != on
        {
            if let Some(ap) = self.peer.as_ref().map(|p| p.bss.bssid) {
                self.one_ss.smps_static = on;
                self.one_ss.frame = Some(smps_action(self.own, ap, on));
            }
        }
    }
    /// The profile the hardware may send with: under `hal.txrx_1ss`,
    /// `tx.c::rtw_tx_pkt_info_update` clears STBC and `rtw_update_sta_info`
    /// keeps only one-stream HT/VHT rates.
    pub(super) fn hal_profile(
        &self,
        p: super::packet_format::DataProfile,
    ) -> super::packet_format::DataProfile {
        if !self.one_ss.on {
            return p;
        }
        super::packet_format::DataProfile {
            mcs: p.mcs & 0xff,
            stbc: false,
            vht: p.vht.map(|v| super::packet_format::VhtRates {
                tx: v.tx & 0x3ff,
                ..v
            }),
            ..p
        }
    }
    /// Apply a pending 1SS profile change once the native packet owner is
    /// idle; DATA waits (`Busy`) until it has.
    pub(super) fn txrx_1ss_live(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if !self.one_ss.profile {
            return Ok(());
        }
        if !self.established || !self.ready() || !io.packet_ready() {
            return Err(Error::Busy);
        }
        io.packet_profile(self.hal_profile(self.data_profile))?;
        self.one_ss.profile = false;
        Ok(())
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn txrx_1ss(&self) -> bool {
        self.one_ss.on
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn smps_static(&self) -> bool {
        self.one_ss.smps_static
    }
    /// Drain queued coexistence C2H and due delayed works.
    async fn coex_progress(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if self.coex.owner.is_none() || self.admission.closed() {
            self.coex.c2h.clear();
            return Ok(());
        }
        while let Some(body) = self.coex.c2h.pop_front() {
            self.coex_event(io, CoexEvent::C2h(body)).await?;
        }
        self.coex_event(io, CoexEvent::Works).await
    }
    /// Best-effort synchronous restore at `stop` (owner already closed),
    /// like `rtw_coex_power_off_setting` returning the hardware to the base.
    fn coex_unbind(&mut self, io: &mut impl Io) {
        if let (Some(mut owner), Some(gate)) = (self.coex.owner.take(), self.coex.gate.take()) {
            struct GateOnly<'a>(&'a super::power_policy::Gate);
            impl super::dm::Authority for GateOnly<'_> {
                fn run<T>(
                    &self,
                    op: impl FnOnce() -> Result<T, firmware_transport::Error>,
                ) -> Result<T, firmware_transport::Error> {
                    self.0.invoke(op)
                }
            }
            let _ = super::firmware_transport::ready_now(owner.restore(io, &GateOnly(&gate)));
        }
        // The owner is closed: nothing more is sent to the AP.
        self.follow_txrx_1ss(false);
        self.one_ss = OneSs::default();
        self.coex = Coexistence {
            facts: self.coex.facts,
            ..Coexistence::default()
        };
    }
    /// Exact retained factory/radio facts for the dm watchdog statistics.
    pub(super) fn set_tracking_facts(&mut self, facts: Option<super::dm::Facts>) {
        self.tracking.facts = facts;
    }
    pub(super) fn dm_grant(&self) -> Option<Arc<super::qualification::Grant>> {
        self.tracking.grant.clone()
    }
    pub(super) fn tracking_active(&self) -> bool {
        self.tracking.grant.is_some()
    }
    pub(super) fn tracking_ticks(&self) -> u64 {
        self.tracking.ticks
    }
    pub(super) fn tracker(&self) -> Option<&super::dm::Tracker> {
        self.tracking.tracker.as_deref()
    }
    /// One Linux `rtw_watch_dog_work` period, at most every 2s, once the
    /// separately qualified N2xD continuation is bound and the station is
    /// established. Losing the continuation or leaving its measured envelope
    /// restores the base program under the base gate and stops tracking.
    pub(super) async fn watchdog(&mut self, io: &mut impl Io) -> Result<bool, Error> {
        let due = match &self.switch {
            Some(s) if self.established => Some(s.due),
            _ => None,
        };
        if due.is_some_and(|due| self.now().is_ok_and(|now| now >= due)) {
            if let Err(e) = self.channel_switch(io).await {
                self.fail(io);
                return Err(e);
            }
            return Ok(true);
        }
        if self.coex.owner.is_some() && !self.admission.closed() {
            let now = self.now()?;
            if now >= self.coex.next {
                self.coex.next = now.saturating_add(super::coex::PERIOD_MS);
                let traffic = core::mem::take(&mut self.coex.traffic);
                self.coex_event(io, CoexEvent::Watchdog(traffic)).await?;
            }
        }
        let mut power_changed = false;
        if self.power_tracking.is_some() && self.established && self.ready() {
            let now = self.now()?;
            let mut tracker = self.power_tracking.take().ok_or(Error::State)?;
            let mut attempt = Attempt {
                admission: self.admission.clone(),
                armed: true,
            };
            let result = Box::pin(tracker.tick(io, &self.admission, now, self.data_profile)).await;
            if tracker.grant().active() {
                self.power_tracking = Some(tracker);
            }
            match result {
                Ok(changed) => {
                    power_changed = changed;
                    attempt.armed = false;
                }
                Err(error) => {
                    self.fail(io);
                    attempt.armed = false;
                    return Err(Error::Native(error));
                }
            }
        }
        if self.established && self.ready() {
            let admission = self.admission.clone();
            admission.run(|| {
                Ok(self
                    .coding_live(io)
                    .and_then(|()| self.qos_live(io))
                    .and_then(|()| self.fallback_live(io)))
            })??;
            if self.one_ss.profile && io.packet_ready() {
                admission.run(|| Ok(self.txrx_1ss_live(io)))??;
            }
            if self.coding_restore || self.one_ss.ra {
                // Source RA_INFO without LDPC once coding is no longer
                // current, and with the 1SS mask while hal.txrx_1ss.
                super::wmm::ra_info(io, self.hal_profile(self.data_profile), &self.admission)
                    .await?;
                self.coding_restore = false;
                self.one_ss.ra = false;
            }
        }
        self.dynamic_rx_agg(io).await?;
        if self.tracking.grant.is_none() || !self.established || !self.ready() {
            return Ok(power_changed);
        }
        let now = self.now()?;
        if now < self.tracking.next {
            return Ok(power_changed);
        }
        self.tracking.next = now.saturating_add(super::dm::PERIOD_MS);
        let grant = self.tracking.grant.clone().ok_or(Error::State)?;
        let gate = io.station_gate()?;
        let facts = self.tracking.facts.ok_or(Error::State)?;
        if self.tracking.tracker.is_none() {
            let bounds = super::dm::bounds(facts.did, grant.payload()).ok_or(Error::State)?;
            self.tracking.tracker = Some(Box::new(super::dm::Tracker::new(bounds, facts)));
        }
        let period = super::dm::Period {
            linked: self.peer.is_some(),
            profile: self.hal_profile(self.data_profile),
            tx_bytes: core::mem::take(&mut self.tracking.tx_bytes),
            rx_bytes: core::mem::take(&mut self.tracking.rx_bytes),
            country: narf_wireless::reg::db::get_domain().map_or(*b"00", |d| d.country_code),
            txrx_1ss: self.one_ss.on,
        };
        let admission = self.admission.clone();
        let live = Live {
            admission: &admission,
            grant: &grant,
            gate: &gate,
        };
        let tracker = self.tracking.tracker.as_mut().ok_or(Error::State)?;
        // Boxed: keep the dm state machine off small (aarch64) task stacks.
        let result = Box::pin(tracker.tick(io, &live, period)).await;
        let commands = match result {
            Ok(c) => c,
            Err(firmware_transport::Error::State) if admission.closed() => {
                return Err(Error::State)
            }
            Err(e) => {
                // Restore through the base gate; a failed restore is terminal.
                let base = Base {
                    admission: &admission,
                    gate: &gate,
                };
                Box::pin(tracker.restore(io, &base)).await?;
                self.tracking.grant = None;
                self.tracking.iqk = None;
                self.tracking.tracker = None;
                return match e {
                    firmware_transport::Error::Gone => Err(Error::Native(e)),
                    _ => Ok(false),
                };
            }
        };
        for words in commands {
            grant.check(&gate)?;
            station_control::send(io, words, Some(&admission)).await?;
        }
        if tracker.take_iqk() {
            // `rtw8822b_phy_pwrtrack` -> `rtw8822b_do_iqk`, after the period's
            // H2C commands as in `rtw_phy_dynamic_mechanism` order.
            let iqk = self.tracking.iqk.clone().ok_or(Error::State)?;
            if let Err(e) = Box::pin(Self::iqk8822b(io, &admission, &iqk, &gate)).await {
                self.fail(io);
                return Err(e);
            }
        }
        self.tracking.ticks += 1;
        Ok(true)
    }
    /// RTL8822BE associated `rtw8822b_do_iqk` under the `N2BW` record:
    /// TXPAUSE and RXDMA park, quiet receipts (TX rings, packet core, FIFO
    /// pages, RXDMA idle) before the H2C, then the RF08/0x1bf0 completion and
    /// the TX/RX restore. Copied receive admission is retired around it as
    /// for C21 N21W maintenance. Any failure closes the station.
    async fn iqk8822b(
        io: &mut impl Io,
        admission: &Admission,
        iqk: &super::qualification::Grant,
        gate: &super::power_policy::Gate,
    ) -> Result<(), Error> {
        use super::tracking8822b::Step;
        let run = |op: &mut dyn FnMut() -> Result<Option<bool>, firmware_transport::Error>| {
            admission.run(|| iqk.invoke(gate, op))
        };
        let thermal = super::tracking8822b::window(iqk);
        admission.retire_receive()?;
        let mut quiet = firmware_transport::enclosed(run, io.station_b22_iqk(Step::Begin)).await?;
        for _ in 0..1000 {
            if quiet {
                break;
            }
            io.delay_us(10).await;
            quiet = firmware_transport::enclosed(run, io.station_b22_iqk(Step::Quiet)).await?;
        }
        if !quiet {
            return Err(Error::Native(firmware_transport::Error::Timeout));
        }
        firmware_transport::enclosed(|op| admission.run(|| iqk.invoke(gate, op)), async {
            let t = ((super::radio8822b::rf_read(io, 0, 0x42).await? & 0xfc00) >> 10) as u8;
            if !(thermal[0]..=thermal[1]).contains(&t) {
                return Err(firmware_transport::Error::Prerequisite);
            }
            gate.b22_temperature(t)?;
            super::channel_policy::iqk8822b_associated(io).await
        })
        .await?;
        firmware_transport::enclosed(run, io.station_b22_iqk(Step::Finish)).await?;
        admission.retire_receive()?;
        Ok(())
    }
    pub(super) fn admission(&self) -> Admission {
        self.admission.clone()
    }
    pub(super) fn local(&self) -> [u8; 6] {
        self.own
    }
    pub(super) fn phase(&self) -> Phase {
        if self.admission.closed() && self.phase != Phase::Stopped || self.retuning {
            Phase::Failed
        } else {
            self.phase
        }
    }
    pub(super) fn peer(&self) -> Option<[u8; 6]> {
        if self.established && !self.admission.closed() {
            self.peer.as_ref().map(|peer| peer.bss.bssid)
        } else {
            None
        }
    }
    /// Association ID the AP granted (`vif->cfg.aid`), only while linked;
    /// the WoW PS-Poll reserved page carries it (`rtw_add_rsvd_page_sta`).
    pub(super) fn aid(&self) -> Option<u16> {
        self.peer().and(self.associated_aid)
    }
    /// The association negotiated WMM (`sta->wme`), only while linked; the
    /// WoW keep-alive reserved pages then include the QoS NULL template.
    pub(super) fn wmm(&self) -> Option<bool> {
        self.peer().map(|_| self.wmm.is_some())
    }
    /// After a kept-link WoW resume: the suspended interval does not count
    /// toward the 5 s link-loss window, as mac80211's jiffies-based beacon
    /// and connection monitors do not advance across system suspend.
    pub(super) fn wow_resumed(&mut self) -> Result<(), Error> {
        if self.peer().is_none() {
            return Err(Error::State);
        }
        self.last_peer = self.now()?;
        Ok(())
    }
    /// Current temporal keys for the WoW security CAM (`wow.c` AOAC):
    /// `Ok(None)` for an open BSS, an error unless an associated protected
    /// port is open and settled (no handshake or reply in flight).
    pub(super) fn suspend_keys(&self) -> Result<Option<station_security::SuspendKeys>, Error> {
        if self.peer().is_none() {
            return Err(Error::State);
        }
        match self.security.as_ref() {
            None => Ok(None),
            Some(security) => security.suspend_keys().map(Some).ok_or(Error::State),
        }
    }
    pub(super) fn ready(&self) -> bool {
        self.peer().is_some()
            && !self.switch.as_ref().is_some_and(|s| s.block)
            && !self.switch_wait_beacon
            && self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.data_pending.is_empty()
            && self.data_drain.is_none()
            && !self.tx_ba.waiting()
            && self.security.as_ref().is_none_or(Security::port_open)
    }
    pub(super) fn receive_open(&self) -> bool {
        self.peer().is_some() && self.security.as_ref().is_none_or(Security::port_open)
    }
    /// ps.c `rtw_coex_lps_notify` from the LPS enter (`enable`) / leave
    /// paths (`runtime_lps::lps_window`). No-op without a bound coexistence
    /// owner; a failed run restores and unbinds coexistence (`coex_event`).
    pub(super) async fn coex_lps(&mut self, io: &mut impl Io, enable: bool) -> Result<(), Error> {
        self.coex_event(io, CoexEvent::Lps(enable)).await
    }
    /// ps.c `rtw_enter_ips` -> `rtw_coex_ips_notify(COEX_IPS_ENTER)` before
    /// the unassociated station is stopped (`Device::idle_claim`).
    pub(super) async fn coex_ips_enter(&mut self, io: &mut impl Io) -> Result<(), Error> {
        self.coex_event(io, CoexEvent::Ips(true)).await
    }
    /// ps.c `rtw_enter_lps`: `coex.stat.wl_force_lps_ctrl` (set by
    /// `COEX_PS_LPS_OFF`) keeps the station out of LPS.
    pub(super) fn coex_forces_lps_off(&self) -> bool {
        self.coex
            .owner
            .as_deref()
            .is_some_and(super::coex::Coex::forces_lps_off)
    }
    /// Actual completed association, unextended fixed CCK1 only. This new
    /// program does not borrow qualification for HT/BA/tracking combinations.
    /// Off channel 1 its N2xZ record is that channel's own (channel-scoped
    /// base), so a channel-1 LPS record never applies.
    pub(super) fn lps_peer(&self) -> Option<([u8; 6], [u8; 6], u16)> {
        if self.phase() != Phase::Open
            || !self.ready()
            || self.extension.is_some()
            || self.ht.is_some()
            || self.rx_ba_grant.is_some()
            || self.tx_ba_grant.is_some()
            || self.protection.is_some()
            || self.power_tracking.is_some()
            || self.tracking.grant.is_some()
            || !self.incoming.is_empty()
            || !self.ordered.is_empty()
            || !self.received.is_empty()
        {
            return None;
        }
        Some((self.own, self.peer()?, self.associated_aid?))
    }
    /// Receive-only native prefix consumption. Preserve DATA/EAPOL for normal
    /// processing after confirmed awake; never emit a reply while in LPS.
    pub(super) fn lps_collect(
        &mut self,
        io: &mut impl Io,
        source: &super::runtime_ps_scope::Bound,
    ) -> Result<(bool, bool), Error> {
        let mut wake = false;
        for _ in 0..32 {
            let step = self.admission.run(|| {
                source.invoke(|| {
                    io.packet_poll()
                        .map_err(|_| firmware_transport::Error::State)
                })
            })?;
            if step.receipt.is_some() {
                return Err(Error::State);
            }
            if let Some(body) = &step.c2h {
                wake |= super::runtime_ps_wire::wake_event(body);
            }
            if let Some(frame) = step.frame {
                if frame.phy.is_some_and(|p| !p.on_channel(self.channel)) {
                    continue;
                }
                if self.lost(&frame) {
                    return Err(Error::PeerLost);
                }
                if frame.bytes().len() > super::packet_format::MAX_MPDU {
                    continue;
                }
                if self.incoming.len() == 64 {
                    return Err(Error::State);
                }
                let now = self.now()?;
                self.cache(&frame, now);
                self.incoming
                    .push_back((frame, true, self.admission.receive_generation(), false));
            }
            if !step.consumed_rx {
                return Ok((true, wake));
            }
        }
        Ok((false, wake))
    }
    pub(super) async fn start(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if self.phase() != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let mut attempt = Attempt {
            admission: self.admission.clone(),
            armed: true,
        };
        station_control::prepare_initial(io, self.own, &self.admission).await?;
        self.admission
            .run(|| Ok(io.packet_prepare(self.own, 0)))??;
        self.prepared = true;
        self.admission.run(|| Ok(io.packet_start()))??;
        // USB opens CR/TXPAUSE over asynchronous EP0 (PCI: in packet_start).
        let admission = self.admission.clone();
        crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
            Ok(io.packet_open().await)
        })
        .await??;
        self.last_now = self.environment.now_ms();
        self.phase = Phase::Passive;
        self.local_ht = io.station_ht_facts().and_then(super::ht::Facts::local);
        self.coex_bind(io).await?;
        attempt.armed = false;
        Ok(())
    }
    pub(super) fn stop(&mut self, io: &mut impl Io) -> Result<(), Error> {
        self.coex_unbind(io);
        self.admission.close();
        self.established = false;
        self.phase = Phase::Stopped;
        if let Some(security) = &mut self.security {
            security.fail();
        }
        self.incoming.clear();
        self.ordered.clear();
        self.rx_ba.clear();
        self.tx_ba.terminal();
        self.tx_config = None;
        self.data_pending.clear();
        self.data_drain = None;
        self.received.clear();
        self.peer_commit = None;
        self.associated_aid = None;
        self.decline = None;
        self.wmm = None;
        self.wmm_requested = false;
        // The base profile of the band the station is tuned to.
        self.data_profile = if super::band5::primary(self.channel) {
            super::packet_format::DataProfile::LEGACY5
        } else {
            super::packet_format::DataProfile::LEGACY
        };
        self.coding = None;
        self.coding_restore = false;
        self.fallback = None;
        self.qos = None;
        self.ht40 = None;
        self.vht = None;
        // `rtw_bf_disassoc`: best effort, the owner is already closed and a
        // fresh association reprograms the entry.
        if let Some(b) = self.bfee.take() {
            let _ = super::firmware_transport::ready_now(super::bf::remove(io, b));
        }
        self.mu_group = super::bf::MuGroup::default();
        self.witness.clear();
        self.witness_scan = None;
        let _ = io.station_passive_tx(None);
        if self.prepared {
            io.packet_stop()?;
        }
        Ok(())
    }
    /// Asynchronous counterpart run before [`State::stop`] where the caller
    /// can await: `Io::packet_close` (USB TXPAUSE/CR over EP0 and bulk
    /// receipt retirement; PCI closes inside `packet_stop`).
    pub(super) async fn close_packets(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if self.prepared {
            io.packet_close().await?;
        }
        Ok(())
    }
    fn fail(&mut self, io: &mut impl Io) {
        let _ = self.stop(io);
        self.phase = Phase::Failed;
    }
    pub(super) async fn disconnect(&mut self, io: &mut impl Io) -> Result<(), Error> {
        // Public Device reserves before waiting for this owner's mutex.
        // Direct private callers need the same cancellation/worker ordering.
        let reservation = if self.admission.teardown_pending() {
            None
        } else {
            Some(self.admission.begin_disconnect()?)
        };
        if self.associated_aid.is_some() && !self.admission.closed() {
            // mac80211 BSS_CHANGED_ASSOC (false): media disconnect.
            self.associated_aid = None;
            let _ = self.coex_event(io, CoexEvent::Media(false, 0)).await;
        }
        self.admission.close();
        self.established = false;
        if let Some(security) = &mut self.security {
            security.fail();
        }
        let mut attempt = Attempt {
            admission: self.admission.clone(),
            armed: true,
        };
        let control = if let Some(peer) = &self.peer {
            station_control::disconnect(io, peer.bss.bssid).await
        } else {
            Ok(())
        };
        let closed = self.close_packets(io).await;
        let stopped = self.stop(io);
        attempt.armed = false;
        drop(reservation);
        control?;
        closed?;
        stopped
    }
    /// `rx.c::rtw_rx_addr_match_iter`: peer frames to us (or its beacons).
    fn observe(&mut self, frame: &Mpdu, facts: super::dm::Facts) {
        let Some(tracker) = self.tracking.tracker.as_mut() else {
            return;
        };
        let Some(peer) = self.peer.as_ref().map(|p| p.bss.bssid) else {
            return;
        };
        let b = frame.bytes();
        if b.len() < 24 || b[0] & 0x0c == 0x04 || b[10..16] != peer {
            return;
        }
        if b[4..10] != self.own && b[0] != 0x80 {
            return;
        }
        self.tracking.rx_bytes = self.tracking.rx_bytes.saturating_add(b.len() as u64);
        if let Some(sample) = frame
            .status
            .as_deref()
            .and_then(|s| super::dm::sample(&facts, frame.rate, s))
        {
            tracker.observe(sample);
        }
    }
    fn coex_rx(&mut self, len: usize) {
        self.rx_agg.rx(len);
        let t = &mut self.coex.traffic;
        t.rx_cnt = t.rx_cnt.saturating_add(1);
        t.rx_bytes = t.rx_bytes.saturating_add(len as u64);
    }
    fn now(&mut self) -> Result<u64, Error> {
        let now = self.environment.now_ms();
        if now < self.last_now {
            return Err(Error::State);
        }
        self.last_now = now;
        Ok(now)
    }
    pub(super) fn candidates(&self) -> Vec<ObservedBss> {
        let now = self.environment.now_ms();
        self.cache
            .iter()
            .filter(|entry| now >= entry.seen && now - entry.seen < 10_000)
            .map(|entry| entry.candidate.clone())
            .collect()
    }
    pub(super) fn information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.candidates()
            .into_iter()
            .find(|candidate| candidate.bss.bssid == bssid)
            .map(|candidate| candidate.bss.information_elements)
    }
    fn transmit(&mut self, io: &mut impl Io, mut bytes: Vec<u8>, kind: Kind) -> Result<(), Error> {
        // Caller holds publication; this helper never awaits or re-enters it.
        if self.admission.closed() {
            return Err(Error::State);
        }
        if self.pending.is_some()
            || self.delivered_reply.is_some()
            || !self.data_pending.is_empty()
            || self.data_drain.is_some()
        {
            return Err(Error::Busy);
        }
        if !matches!(kind, Kind::Security | Kind::Data | Kind::RtsData) && bytes.len() != 20 {
            bytes[22..24].copy_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
        }
        let id = io.packet_submit(&bytes, !matches!(kind, Kind::Data | Kind::Probe))?;
        if kind == Kind::Ba {
            self.rx_ba.submitted(&bytes)?;
        }
        if kind == Kind::TxBa {
            self.tx_ba.submitted(&bytes)?;
        }
        self.pending = Some(Pending { id, bytes, kind });
        Ok(())
    }
    fn cache(&mut self, frame: &Mpdu, now: u64) {
        // This native profile exposes no calibrated per-frame dBm estimate.
        let signal = None;
        // During a random-address scan, Probe Responses answer that SA.
        let own = match self.scan_address {
            Some(a) if frame.bytes().get(4..10) == Some(&a[..]) => a,
            _ => self.own,
        };
        let observed = match &self.local_ht {
            Some(p) => association::observe_with_phy(frame, self.channel, own, signal, p),
            None => association::observe(frame, self.channel, own, signal),
        };
        let Ok(candidate) = observed else {
            return;
        };
        // cfg80211 `beacon_found` for this dwell's witness: an actual Beacon
        // (not a Probe Response) with a nonzero interval for the tuned
        // primary. `scan_inner` opens the generation only for its dwell.
        if let Some(generation) = self.witness_scan {
            if frame.bytes().first() == Some(&0x80)
                && candidate.bss.channel == self.channel
                && candidate.bss.beacon_interval != 0
            {
                if let Some(c) = super::channel_policy::any_frequency(self.channel) {
                    let _ = self.witness.beacon_found(generation, c);
                }
            }
        }
        if !super::channel_policy::base_rate_ok(self.channel, candidate.basic_rates) {
            return;
        }
        if self
            .peer
            .as_ref()
            .is_some_and(|peer| peer.bss.bssid == candidate.bss.bssid)
        {
            self.last_peer = now;
        }
        if let Some(entry) = self
            .cache
            .iter_mut()
            .find(|entry| entry.candidate.bss.bssid == candidate.bss.bssid)
        {
            *entry = Entry {
                candidate,
                seen: now,
            };
        } else {
            if self.cache.len() == 32 {
                let oldest = self
                    .cache
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.seen)
                    .map(|(index, _)| index)
                    .unwrap_or(0);
                self.cache.swap_remove(oldest);
            }
            self.cache.push(Entry {
                candidate,
                seen: now,
            });
        }
    }
    fn lost(&self, frame: &Mpdu) -> bool {
        let Some(peer) = &self.peer else {
            return false;
        };
        let bytes = frame.bytes();
        bytes.len() >= 26
            && matches!(bytes[0], 0xa0 | 0xc0)
            && bytes[1] & 0xc7 == 0
            && bytes[22] & 15 == 0
            && bytes[10..16] == peer.bss.bssid
            && bytes[16..22] == peer.bss.bssid
            && (bytes[4..10] == self.own || bytes[4..10] == [255; 6])
    }
    fn delivery(&mut self, delivery: Receipt) -> Result<(), Error> {
        if let Some(data) = self.data_pending.front() {
            if data.id != delivery.id
                || data.bytes != delivery.bytes
                || !delivery.radio_acknowledged
            {
                return Err(Error::State);
            }
            self.data_pending.pop_front();
            return Ok(());
        }
        let pending = self.pending.take().ok_or(Error::State)?;
        if pending.id != delivery.id || pending.bytes != delivery.bytes {
            return Err(Error::State);
        }
        if !delivery.radio_acknowledged
            && !matches!(pending.kind, Kind::Data | Kind::Probe | Kind::Smps)
        {
            return Err(Error::State);
        }
        if pending.kind == Kind::Security {
            self.delivered_reply = Some(pending);
        } else if pending.kind == Kind::Ba {
            self.rx_ba.delivered(&pending.bytes)?;
        } else if pending.kind == Kind::TxBa {
            self.tx_ba.delivered(&pending.bytes)?;
        }
        Ok(())
    }
    pub(super) async fn poll(&mut self, io: &mut impl Io) -> Result<Vec<Vec<u8>>, Error> {
        let admission = self.admission.clone();
        let result = crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
            Ok(self.progress(io).await)
        })
        .await
        .map_err(Error::Native)
        .and_then(|result| result);
        let result = match result {
            Ok(out) => self.coex_progress(io).await.map(|()| out),
            Err(e) => Err(e),
        };
        if result.is_err() && !self.admission.teardown_pending() {
            self.fail(io);
        }
        result
    }
    async fn progress(&mut self, io: &mut impl Io) -> Result<Vec<Vec<u8>>, Error> {
        if self.admission.closed()
            || matches!(self.phase, Phase::Prepared | Phase::Failed | Phase::Stopped)
        {
            return Err(Error::State);
        }
        io.station_allowed()?;
        let now = self.now()?;
        let mut idle = false;
        for _ in 0..32 {
            let step = io.packet_poll()?;
            if let Some(receipt) = step.receipt {
                self.delivery(receipt)?;
            }
            if let Some(body) = &step.c2h {
                self.amsdu_ra_report(body);
                if self.coex.owner.is_some()
                    && matches!(body.first(), Some(0x09 | 0x0b | 0x27 | 0x45))
                    && self.coex.c2h.len() < 16
                {
                    self.coex.c2h.push_back(body.to_vec());
                }
            }
            if let (Some(body), Some(t)) = (&step.c2h, self.power_tracking.as_mut()) {
                t.c2h(body);
            }
            if let (Some(body), Some(t)) = (&step.c2h, self.tracking.tracker.as_mut()) {
                t.c2h(body);
            }
            if let (Some(frame), Some(facts)) = (&step.frame, self.tracking.facts) {
                self.observe(frame, facts);
            }
            if !step.consumed_rx {
                idle = true;
                break;
            }
            if let Some(mut frame) = step.frame {
                if frame.phy.is_some_and(|p| !p.on_channel(self.channel)) {
                    continue;
                }
                let aggregate = frame.bytes().first() == Some(&0x88)
                    && frame.bytes().get(24).is_some_and(|q| q & 0x80 != 0);
                if frame.bytes().len() > super::packet_format::MAX_MPDU && !aggregate
                    || aggregate && (self.ht.is_none() || frame.rate < 12)
                {
                    continue;
                }
                if self.lost(&frame) {
                    return Err(Error::PeerLost);
                }
                if self.gid_management(io, frame.bytes()).await? {
                    continue;
                }
                if self.receive_open() && self.tx_ba_grant.is_some() {
                    let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                    if let Some(tid) = super::tx_ba::peer_delba(frame.bytes(), self.own, ap) {
                        self.tx_ba.retire_tid(tid);
                        continue;
                    }
                    if self.tx_ba.response(frame.bytes(), self.own, ap) {
                        continue;
                    }
                }
                // A peer DELBA can arrive while the success response's native
                // receipt is held. Retire its proposal before any idle commit.
                if self.receive_open() && self.rx_ba_grant.is_some() {
                    let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                    if let Some(tid) = super::rx_ba::delba(frame.bytes(), self.own, ap) {
                        self.rx_ba.retire(tid);
                        // Requests captured earlier in this same native batch
                        // have not produced a Table proposal yet. Retire those
                        // too, so a later loop cannot emit stale success.
                        self.incoming.retain(|(f, _, _, _)| {
                            super::rx_ba::request(f.bytes(), self.own, ap)
                                .is_none_or(|r| r.tid() != tid)
                        });
                        continue;
                    }
                    if let Some((tid, ssn)) = super::rx_ba::bar(frame.bytes(), self.own, ap) {
                        let epoch = self.admission.receive_generation();
                        self.ordered.extend(
                            self.rx_ba
                                .advance(tid, ssn, now)?
                                .into_iter()
                                .map(|f| (f, epoch)),
                        );
                        continue;
                    }
                    frame = match self.rx_ba.stage_pending(
                        frame,
                        self.own,
                        ap,
                        self.admission.receive_generation(),
                        now,
                    )? {
                        Some(f) => f,
                        None => continue,
                    };
                }
                self.cache(&frame, now);
                if matches!(self.phase, Phase::FourWay | Phase::Open) {
                    self.channel_switch_ie(io, frame.bytes(), now)?;
                }
                if self.phase != Phase::Passive {
                    if self.incoming.len() == 64 {
                        return Err(Error::State);
                    }
                    let admitted =
                        self.established && self.security.as_ref().is_none_or(Security::port_open);
                    let captured = self
                        .peer
                        .as_ref()
                        .is_some_and(|p| self.rx_ba.captured(&frame, self.own, p.bss.bssid));
                    self.incoming.push_back((
                        frame,
                        admitted,
                        self.admission.receive_generation(),
                        captured,
                    ));
                }
            }
        }
        // A CRC/report descriptor is consumed input, never an RX-idle fence.
        // Inspect all queued peer loss before committing an exact M4 receipt.
        if idle {
            if let Some(receipt) = self.delivered_reply.take() {
                let publication = io.station_publication()?;
                let security = self.security.as_mut().ok_or(Error::State)?;
                if security.pending_frame() != Some(receipt.bytes.as_slice()) {
                    return Err(Error::State);
                }
                publication.invoke(|| Ok(security.reply_delivered(receipt.bytes.len())))??;
                self.admission.retire_receive()?;
                self.rx_ba.clear();
                self.tx_ba.after_key();
                self.ordered.clear();
            }
            if self.receive_open() {
                io.station_publication()?.invoke(|| {
                    let epoch = self.admission.receive_generation();
                    self.ordered.extend(
                        self.rx_ba
                            .idle(now, epoch)
                            .map_err(|_| firmware_transport::Error::State)?
                            .into_iter()
                            .map(|f| (f, epoch)),
                    );
                    Ok(())
                })?;
            }
        }
        if self.receive_open() && self.rx_ba_grant.is_some() {
            let epoch = self.admission.receive_generation();
            let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
            self.ordered.extend(
                self.rx_ba
                    .expire(now, self.own, ap)?
                    .into_iter()
                    .map(|f| (f, epoch)),
            );
        }
        for _ in 0..64 {
            if self.received.len() >= 64 {
                break;
            }
            if self.pending.is_some()
                || self.delivered_reply.is_some()
                || self.peer_commit.is_some()
                || self
                    .security
                    .as_ref()
                    .is_some_and(|s| s.pending_frame().is_some())
            {
                break;
            }
            let (frame, mut data_admitted, epoch, captured, ordered) =
                match self.ordered.pop_front() {
                    Some((f, e)) => (f, true, e, true, true),
                    None => match self.incoming.pop_front() {
                        Some((f, a, e, c)) => (f, a, e, c, false),
                        None => break,
                    },
                };
            // M3 can arrive in native DMA before the host observes the M2
            // CCX/idle receipt. That receipt retires DATA/publication epochs,
            // but cannot discard this still-private EAPOL transaction. Only
            // an exact original plaintext authenticator control may cross;
            // shared Security must still validate its phase/MIC/replay. Its
            // captured DATA admission remains false, and it grants no BA.
            let private_eapol = !ordered
                && self
                    .peer
                    .as_ref()
                    .is_some_and(|p| plaintext_eapol(frame.bytes(), self.own, p.bss.bssid));
            if epoch != self.admission.receive_generation() {
                if !private_eapol {
                    continue;
                }
                // A previous open capture is not current DATA/BA admission.
                // In particular a QoS EAPOL must not enter a successor TID
                // window before the real Supplicant validates its control.
                data_admitted = false;
            }
            if !ordered && self.receive_open() && data_admitted && self.rx_ba_grant.is_some() {
                let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                if let Some((tid, seq)) = super::rx_ba::data(frame.bytes(), self.own, ap) {
                    if self.rx_ba.active(tid) {
                        // Originals observed before the agreement's terminal
                        // publication cannot be authorized retrospectively.
                        if captured {
                            self.ordered.extend(
                                self.rx_ba
                                    .push(tid, seq, now, frame)?
                                    .into_iter()
                                    .map(|f| (f, epoch)),
                            );
                        }
                        continue;
                    }
                }
            }
            match self.phase {
                Phase::Authentication => {
                    if let Some(mut association) = self
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .authentication_response(frame.bytes())?
                        .map(|bytes| bytes.to_vec())
                    {
                        if self.wmm_requested {
                            association.extend_from_slice(&narf_wireless::wmm::INFORMATION);
                        }
                        self.phase = Phase::Association;
                        self.transmit(io, association, Kind::Association)?;
                    }
                }
                Phase::Association => {
                    if let Some(aid) = self
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .association_response(frame.bytes())?
                    {
                        let peer = self.peer.as_ref().ok_or(Error::State)?;
                        let response_cap =
                            u16::from_le_bytes([frame.bytes()[24], frame.bytes()[25]]);
                        let short = peer.bss.capability & response_cap & 0x400 != 0;
                        if let Some(grant) = &self.extension {
                            let (rates, basic) =
                                self.plan.as_ref().ok_or(Error::State)?.legacy_rates();
                            let rates = rates & grant.rates();
                            let band5 = grant.band5();
                            if (if band5 {
                                rates & 0x1f != 0x10
                            } else {
                                rates & 1 == 0
                            }) || basic & !rates != 0
                            {
                                return Err(Error::Profile);
                            }
                            if self.wmm_requested {
                                let p = narf_wireless::wmm::Parameters::parse(&frame.bytes()[30..])
                                    .map_err(|_| Error::Profile)?
                                    .ok_or(Error::Profile)?;
                                super::wmm::words(p, short, band5)?;
                                self.wmm = Some(p);
                            }
                            self.data_profile = super::packet_format::DataProfile {
                                rates,
                                qos: self.wmm.is_some(),
                                mcs: 0,
                                rx_mcs: 0,
                                sgi: false,
                                ldpc: false,
                                stbc: false,
                                acs: 0,
                                fallback: false,
                                bw40: false,
                                band5,
                                vht: None,
                            };
                            if let Some(h) = &self.ht {
                                let negotiated = self
                                    .plan
                                    .as_ref()
                                    .and_then(JoinPlan::negotiated_phy)
                                    .ok_or(Error::Profile)?;
                                // Linux rtw88 reads no ht_operation_mode and takes no
                                // protection action (mac80211.c/tx.c); nonzero HT
                                // protection modes are admitted unchanged.
                                // The response must keep the programmed width:
                                // 40MHz exactly on the bound N2xB pair.
                                // 80MHz exactly on the bound N2xV block with VHT.
                                if let Some((_, v)) = &self.vht {
                                    let vht = negotiated.vht().ok_or(Error::Profile)?;
                                    if negotiated.width() != association::phy::Width::Eighty
                                        || negotiated.center_channel() != v.center
                                        || !self.wide
                                    {
                                        return Err(Error::Profile);
                                    }
                                    // rtw_update_sta_info: VHT ra_mask from the
                                    // negotiated TX map (the peer's RX map within
                                    // the N2xV selection), bw_mode 80, SGI from
                                    // the peer's SHORT_GI_80 and N2xV's SGI80;
                                    // TX uncoded (no VHT coding qualification).
                                    let tx =
                                        super::packet_format::VhtRates::from_map(vht.tx_mcs_map())
                                            & v.tx_mask();
                                    let mcs = u16::from_le_bytes(
                                        negotiated.ht().tx_mcs()[..2].try_into().unwrap(),
                                    );
                                    self.data_profile = super::packet_format::DataProfile {
                                        sgi: vht.tx_sgi80(),
                                        vht: Some(super::packet_format::VhtRates {
                                            tx,
                                            rx: h.vht_rx(),
                                        }),
                                        ..h.profile(rates, mcs, false)?
                                    };
                                    if !self.data_profile.valid() {
                                        return Err(Error::Profile);
                                    }
                                }
                                let wide = match (negotiated.width(), &self.ht40) {
                                    _ if self.vht.is_some() => true,
                                    (association::phy::Width::Twenty, _) => false,
                                    (association::phy::Width::Forty, Some((_, r)))
                                        if negotiated.occupied_channels()
                                            == [
                                                r.primary.min(r.secondary),
                                                r.primary.max(r.secondary),
                                            ] =>
                                    {
                                        true
                                    }
                                    _ => return Err(Error::Profile),
                                };
                                if wide != self.wide {
                                    return Err(Error::Profile);
                                }
                                let mcs = u16::from_le_bytes(
                                    negotiated.ht().tx_mcs()[..2].try_into().unwrap(),
                                );
                                self.data_profile = if self.vht.is_some() {
                                    self.data_profile
                                } else if wide {
                                    // rtw_update_sta_info: bw_mode 40, SGI from
                                    // the peer's SGI_40 (and N2xB's SGI40).
                                    super::packet_format::DataProfile {
                                        bw40: true,
                                        sgi: negotiated.ht().tx_sgi40(),
                                        ..h.profile(rates, mcs, false)?
                                    }
                                } else {
                                    h.profile(rates, mcs, negotiated.ht().tx_sgi20())?
                                };
                                if let Some((_, flags)) =
                                    self.coding.as_ref().filter(|_| self.vht.is_none())
                                {
                                    self.data_profile = super::coding::apply(
                                        *flags,
                                        self.data_profile,
                                        negotiated.ht().tx_ldpc(),
                                        negotiated.ht().tx_stbc(),
                                    );
                                }
                            }
                        }
                        if let Some((_, acs)) = &self.qos {
                            if self.data_profile.qos {
                                self.data_profile.acs = *acs;
                            }
                        }
                        self.data_profile.fallback = self.fallback.is_some();
                        self.peer_commit = Some((aid, short));
                        self.last_peer = now;
                        // Firmware peer commit is an awaited continuation in associate().
                    }
                }
                Phase::FourWay | Phase::Open => {
                    if self.receive_open() && data_admitted {
                        if let Some(g) = &self.rx_ba_grant {
                            let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                            if let Some(r) = super::rx_ba::request(frame.bytes(), self.own, ap) {
                                if let Some(maximum) = g.window(r.tid()) {
                                    g.check()?;
                                    io.station_profile_readback().await?;
                                    let did =
                                        self.ht.as_ref().ok_or(Error::State)?.rx_ba_identity().2;
                                    super::rx_ba::readback(io, did).await?;
                                    if self.rx_ba.propose(
                                        r,
                                        maximum,
                                        self.own,
                                        ap,
                                        now,
                                        self.admission.receive_generation(),
                                    )? {
                                        if !self.rx_ba.active(r.tid()) {
                                            self.incoming.retain(|(f, _, _, _)| {
                                                super::rx_ba::data(f.bytes(), self.own, ap)
                                                    .is_none_or(|(tid, _)| tid != r.tid())
                                            });
                                        }
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    if self.ht.is_some() {
                        if let Some(bytes) = super::ht::decline(
                            frame.bytes(),
                            self.own,
                            self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                        ) {
                            if self
                                .decline
                                .as_ref()
                                .is_some_and(|pending| pending != &bytes)
                            {
                                return Err(Error::State);
                            }
                            self.decline = Some(bytes);
                            continue;
                        }
                    }
                    if self.extension.is_some()
                        && (if frame.rate >= 0x2c {
                            // VHT only within the advertised N2xV RX set.
                            self.data_profile.vht.is_none_or(|v| {
                                frame.rate >= 0x40 || v.rx >> (frame.rate - 0x2c) & 1 == 0
                            })
                        } else if frame.rate >= 12 {
                            self.ht.is_none() || frame.rate >= 20
                        } else {
                            self.data_profile.rates & (1 << frame.rate) == 0
                        })
                    {
                        continue;
                    }
                    let qos = frame.bytes().get(24..26);
                    let live_ba = ordered && qos.is_some_and(|q| self.rx_ba.active(q[0] & 15));
                    let aggregate = frame.bytes().first() == Some(&0x88)
                        && qos.is_some_and(|q| q[0] & 0x80 != 0);
                    if frame.bytes().first() == Some(&0x88)
                        && (!self.data_profile.qos
                            || if self.ht.is_some() {
                                qos.is_none_or(|q| {
                                    q[0] & 0x10 != 0
                                        || q[1] != 0
                                        || q[0] & 0x60 != 0 && !(live_ba && q[0] & 0x60 == 0x60)
                                })
                            } else if self.data_profile.acs != 0 {
                                // N2xQ: any TID0..7 with normal ack.
                                qos.is_none_or(|q| q[0] & 0xf8 != 0 || q[1] != 0)
                            } else {
                                qos != Some(&[0, 0])
                            })
                    {
                        continue;
                    }
                    if !data_admitted
                        && !plaintext_eapol(
                            frame.bytes(),
                            self.own,
                            self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                        )
                    {
                        continue;
                    }
                    if aggregate {
                        let b = frame.bytes();
                        if self.ht.is_none()
                            || frame.rate < 12
                            || !self.established
                            || b.len() < 26
                            || b[1] & 0x87 != 2
                            || b[22] & 15 != 0
                            || b[10..16] != self.peer.as_ref().ok_or(Error::State)?.bss.bssid
                            || b[16..22] == [0; 6]
                            || b[16] & 1 != 0
                        {
                            continue;
                        }
                        let decoded = if let Some(s) = &mut self.security {
                            if !s.port_open() {
                                continue;
                            }
                            if live_ba && qos.is_some_and(|q| q[0] & 0x60 == 0x60) {
                                s.receive_amsdu_block_ack(&frame)?
                            } else {
                                s.receive_amsdu(&frame)?
                            }
                        } else if b[1] & 0x40 == 0 {
                            narf_wireless::amsdu::decode(
                                &b[26..],
                                self.own,
                                b[4..10].try_into().unwrap(),
                            )
                            .ok()
                        } else {
                            None
                        };
                        if let Some(frames) = decoded {
                            if self.received.len().saturating_add(frames.len()) > RECEIVE_OUTPUTS {
                                return Err(Error::State);
                            }
                            self.received.extend(frames);
                            self.last_peer = now;
                        }
                        continue;
                    }
                    if let Some(security) = &mut self.security {
                        let handshake_active = security.handshake_active();
                        let environment = &self.environment;
                        let initial = &mut self.initial_nonce;
                        match security.receive_with_nonce(&frame, || {
                            initial.take().or_else(|| environment.nonce())
                        })? {
                            station_security::Rx::Data(bytes) => {
                                if let Some(bytes) = ethernet_profile(
                                    &bytes,
                                    self.own,
                                    self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                                    self.data_profile.qos,
                                    self.ht.is_some() || self.data_profile.acs != 0,
                                ) {
                                    self.last_peer = now;
                                    if self.received.len() == RECEIVE_OUTPUTS {
                                        return Err(Error::State);
                                    }
                                    self.coex_rx(bytes.len());
                                    self.received.push_back(bytes);
                                }
                            }
                            station_security::Rx::ReplyReady => {
                                self.admission.retire_receive()?;
                                self.received.clear();
                                self.incoming.clear();
                                self.ordered.clear();
                                self.rx_ba.clear();
                                self.tx_ba.stop(
                                    self.own,
                                    self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                                    now,
                                );
                                self.decline = None;
                                if self.established && !handshake_active {
                                    self.deadline = now.saturating_add(5000);
                                }
                            }
                            station_security::Rx::Ignored => {}
                        }
                    } else if let Some(bytes) = ethernet_profile(
                        frame.bytes(),
                        self.own,
                        self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                        self.data_profile.qos,
                        self.ht.is_some() || self.data_profile.acs != 0,
                    ) {
                        self.last_peer = now;
                        if self.received.len() == RECEIVE_OUTPUTS {
                            return Err(Error::State);
                        }
                        self.coex_rx(bytes.len());
                        self.received.push_back(bytes);
                    }
                }
                _ => {}
            }
        }
        self.service_tx_ba(io, now, idle).await?;
        if self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.data_pending.is_empty()
            && self.data_drain.is_none()
        {
            if let Some(reply) = self
                .security
                .as_ref()
                .and_then(Security::pending_frame)
                .map(|bytes| bytes.to_vec())
            {
                self.transmit(io, reply, Kind::Security)?;
            } else if let Some(reply) = self.decline.take() {
                self.transmit(io, reply, Kind::Decline)?;
            } else if let Some(reply) = self.rx_ba.next() {
                self.transmit(io, reply, Kind::Ba)?;
            } else if let Some(reply) = self.tx_ba.next() {
                self.transmit(io, reply, Kind::TxBa)?;
            } else if let Some(frame) = self.one_ss.frame.take() {
                self.transmit(io, frame, Kind::Smps)?;
            }
        }
        if idle
            && self.incoming.is_empty()
            && self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.phase == Phase::FourWay
            && self.security.as_ref().is_none_or(Security::port_open)
        {
            io.station_publication()?.invoke(|| {
                self.admission.check()?;
                self.established = true;
                self.phase = Phase::Open;
                self.last_peer = now;
                Ok(())
            })?;
        }
        if self.phase != Phase::Passive {
            let expired = if self.established {
                now.saturating_sub(self.last_peer) >= 5000
                    || now >= self.deadline
                        && self
                            .security
                            .as_ref()
                            .is_some_and(Security::handshake_active)
            } else {
                now >= self.deadline
            };
            if expired {
                return Err(Error::Timeout);
            }
        }
        if idle && self.established && self.security.as_ref().is_none_or(Security::port_open) {
            io.station_publication()?
                .invoke(|| {
                    self.admission.check()?;
                    Ok(self.received.drain(..).collect())
                })
                .map_err(Error::Native)
        } else {
            Ok(Vec::new())
        }
    }
    /// mac80211 software scan on the retained channel: each Probe Request
    /// is published and retired (DMA consumption, no ACK) before the next,
    /// then the dwell runs from the last retirement. Empty `probes` is the
    /// original passive scan.
    ///
    /// With `address`, Linux `main.c::rtw_core_scan_start` points the port0
    /// MAC (`REG_MACID` 0x610) at the random scan address for the duration
    /// of the scan and `rtw_core_scan_complete` restores the own address.
    pub(super) async fn scan_for(
        &mut self,
        io: &mut impl Io,
        dwell_ms: u64,
        probes: &[Vec<u8>],
        address: Option<[u8; 6]>,
        channels: &[u8],
    ) -> Result<Vec<ObservedBss>, Error> {
        if !(1..=1024).contains(&dwell_ms)
            || probes.len() > 4
            || channels.len()
                > usize::from(super::channel_policy::LAST) + super::channel_policy::PRIMARIES5.len()
            || channels.iter().any(|c| !super::channel_policy::tunable(*c))
        {
            return Err(Error::Profile);
        }
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        let source = address.unwrap_or(self.own);
        if address
            .is_some_and(|a| a == self.own || a[0] & 1 != 0 || a == [0; 6] || probes.is_empty())
        {
            return Err(Error::Profile);
        }
        for probe in probes {
            if probe.len() < 24
                || probe[..4] != [0x40, 0, 0, 0]
                || probe[4..10] != [255; 6]
                || probe[10..16] != source
                || probe[16..22] != [255; 6]
            {
                return Err(Error::Profile);
            }
        }
        if let Some(a) = address {
            station_control::port_address(io, a, &self.admission).await?;
            let admission = self.admission.clone();
            admission.run(|| Ok(io.packet_scan_address(Some(a))))??;
            self.scan_address = Some(a);
        }
        // rtw_core_scan_start / rtw_core_scan_complete coexistence notify.
        self.coex.scanning = true;
        let started = self.coex_event(io, CoexEvent::Scan(Some(false))).await;
        let result = match started {
            Ok(()) => self.scan_channels(io, dwell_ms, probes, channels).await,
            Err(e) => Err(e),
        };
        self.coex.scanning = false;
        let finished = self.coex_event(io, CoexEvent::Scan(None)).await;
        let result = result.and_then(|r| finished.map(|()| r));
        if self.scan_address.take().is_some() {
            // rtw_core_scan_complete: back to the own address on every exit.
            let own = self.own;
            let restored = station_control::port_address(io, own, &self.admission)
                .await
                .map_err(Error::Native)
                .and_then(|()| io.packet_scan_address(None).map_err(Error::Transport));
            if result.is_ok() {
                restored?;
            }
        }
        result
    }
    /// mac80211 software scan over `channels` (empty: the current one).
    /// Each channel is retuned without RF calibration (`RTW_FLAG_SCANNING`),
    /// probes carry that channel's DS parameter, and the scan returns to the
    /// pre-scan channel (`rtw_core_scan_complete`). The operating channel is
    /// restored even on failure; a failed restore leaves the station failed.
    async fn scan_channels(
        &mut self,
        io: &mut impl Io,
        dwell_ms: u64,
        probes: &[Vec<u8>],
        channels: &[u8],
    ) -> Result<Vec<ObservedBss>, Error> {
        let home = self.channel;
        let policy = io.station_regulatory()?;
        if channels.is_empty() || channels == [home] {
            // mac80211 `ieee80211_scan_state_decision`: a RADAR / NO_IR
            // channel is dwelt passively, without probe requests.
            if passive_only(policy.as_ref(), home) {
                return self.scan_inner(io, dwell_ms, &[], policy.as_ref()).await;
            }
            if super::band5::primary(home) {
                // The 5GHz preq carries the OFDM rate set and no DS element.
                let mut tuned = Vec::new();
                for probe in probes {
                    tuned
                        .push(super::channel_policy::probe_for(probe, home).ok_or(Error::Profile)?);
                }
                return self.scan_inner(io, dwell_ms, &tuned, policy.as_ref()).await;
            }
            return self.scan_inner(io, dwell_ms, probes, policy.as_ref()).await;
        }
        let mut result = Ok(Vec::new());
        for channel in channels.iter().copied() {
            let mut tuned = Vec::new();
            if !passive_only(policy.as_ref(), channel) {
                for probe in probes {
                    tuned.push(
                        super::channel_policy::probe_for(probe, channel).ok_or(Error::Profile)?,
                    );
                }
            }
            result = match self.retune(io, channel, false).await {
                Ok(()) => self.scan_inner(io, dwell_ms, &tuned, policy.as_ref()).await,
                Err(e) => Err(e),
            };
            if result.is_err() {
                break;
            }
        }
        let restored = self.retune(io, home, false).await;
        let observed = result?;
        restored?;
        Ok(observed)
    }
    /// Native retune owner (`main.c::rtw_set_channel` order) for an
    /// unassociated station: load the signed record, install the target gate,
    /// pause and drain TX, program the chip channel and TX power (plus IQK
    /// when `rfk`), then commit the epoch and reopen TX. Any failure or
    /// cancellation leaves TX closed and the station failed.
    /// Native retune plus `main.c::rtw_set_channel`'s
    /// `rtw_coex_switchband_notify` when the band changes.
    pub(super) async fn retune(
        &mut self,
        io: &mut impl Io,
        channel: u8,
        rfk: bool,
    ) -> Result<(), Error> {
        let was5 = super::band5::primary(self.channel);
        self.retune_native(io, channel, rfk).await?;
        let is5 = super::band5::primary(self.channel);
        if was5 != is5 {
            self.coex_event(io, CoexEvent::Switchband(is5)).await?;
        }
        Ok(())
    }
    async fn retune_native(
        &mut self,
        io: &mut impl Io,
        channel: u8,
        rfk: bool,
    ) -> Result<(), Error> {
        if self.phase() != Phase::Passive || self.pending.is_some() {
            return Err(Error::State);
        }
        if channel == self.channel && (!rfk || self.rfk_channel == Some(channel)) {
            return Ok(());
        }
        let grant = if channel == 1 {
            None
        } else {
            Some(
                self.admission
                    .run(|| io.station_channel_grant(channel))?
                    .ok_or(Error::Profile)?,
            )
        };
        self.retune_to(io, channel, grant, rfk, Phase::Passive)
            .await
    }
    /// Shared retune body: `resume` is the phase restored after commit
    /// (Passive for scan/association, the associated phase for a CSA).
    async fn retune_to(
        &mut self,
        io: &mut impl Io,
        channel: u8,
        grant: Option<Arc<super::qualification::Grant>>,
        rfk: bool,
        resume: Phase,
    ) -> Result<(), Error> {
        self.retuning = true;
        let mut quiet = false;
        for _ in 0..1000 {
            let g = grant.clone();
            if firmware_transport::enclosed(
                |op| self.admission.run(op),
                io.station_retune_begin(channel, g),
            )
            .await?
            {
                quiet = true;
                break;
            }
            self.poll(io).await?;
            self.environment.pause().await;
        }
        if !quiet {
            return Err(Error::Timeout);
        }
        self.phase = Phase::Failed;
        self.rfk_channel = None;
        let gate = self.admission.run(|| io.station_gate())?;
        super::channel_policy::program(io, &gate, rfk).await?;
        firmware_transport::enclosed(
            |op| self.admission.run(op),
            io.station_retune_finish(channel),
        )
        .await?;
        self.channel = channel;
        if rfk {
            self.rfk_channel = Some(channel);
        }
        self.phase = resume;
        self.retuning = false;
        Ok(())
    }
    /// `rtw_set_channel(center, BW40/BW80, sc)` for the bound N2xB pair or
    /// N2xV block, then the pre-association IQK and HT40 / VHT80 TX power
    /// (`rtw_ops_mgd_prepare_tx`), under the retune owner: TX refused,
    /// TXPAUSE, drained, readbacks, epoch. Failure is terminal like a retune
    /// failure.
    async fn widen(&mut self, io: &mut impl Io, wide: &super::ht::Wide) -> Result<(), Error> {
        let primary = match wide {
            super::ht::Wide::Forty(r) => r.primary,
            super::ht::Wide::Eighty(v) => v.primary,
        };
        if self.phase() != Phase::Passive || primary != self.channel {
            return Err(Error::State);
        }
        self.retuning = true;
        let mut quiet = false;
        for _ in 0..1000 {
            if firmware_transport::enclosed(|op| self.admission.run(op), io.station_width_begin())
                .await?
            {
                quiet = true;
                break;
            }
            self.poll(io).await?;
            self.environment.pause().await;
        }
        if !quiet {
            return Err(Error::Timeout);
        }
        self.phase = Phase::Failed;
        self.rfk_channel = None;
        let gate = self.admission.run(|| io.station_gate())?;
        match wide {
            super::ht::Wide::Forty(record) => {
                if gate.ht40_record().as_ref() != Some(record) || gate.vht_record().is_some() {
                    return Err(Error::State);
                }
                super::ht40::program(io, &gate, record).await?;
            }
            super::ht::Wide::Eighty(record) => {
                if gate.vht_record().as_ref() != Some(record) || gate.ht40_record().is_some() {
                    return Err(Error::State);
                }
                super::vht::program(io, &gate, record).await?;
            }
        }
        let channel = self.channel;
        firmware_transport::enclosed(
            |op| self.admission.run(op),
            io.station_retune_finish(channel),
        )
        .await?;
        self.rfk_channel = Some(channel);
        self.wide = true;
        self.phase = Phase::Passive;
        self.retuning = false;
        Ok(())
    }
    /// mac80211 software CSA receipt (`mlme.c::ieee80211_sta_process_chanswitch`
    /// with emulated channel contexts, which set `CHANCTX_STA_CSA`) for the
    /// associated BSS's own Beacon/Probe Response. Same-channel announcements
    /// are ignored; another band, an unadmitted primary or a program that
    /// cannot carry over drops the connection like mac80211's
    /// `drop_connection`. Runs under the caller's publication.
    fn channel_switch_ie(&mut self, io: &mut impl Io, bytes: &[u8], now: u64) -> Result<(), Error> {
        let Some(peer) = &self.peer else {
            return Ok(());
        };
        if bytes.len() < 36
            || !matches!(bytes[0], 0x80 | 0x50)
            || bytes[1] & 0xc7 != 0
            || bytes[16..22] != peer.bss.bssid
        {
            return Ok(());
        }
        if self.switch_wait_beacon && bytes[0] == 0x80 {
            // RX already requires the PHY report of the committed primary.
            self.switch_wait_beacon = false;
        }
        // Associated at 40MHz: an AP HT Operation that no longer names the
        // programmed pair (e.g. the AP fell back to 20MHz after 20/40 BSS
        // coexistence) cannot be followed in place; drop the connection like
        // mac80211 does for a bandwidth change it cannot apply, and the SME
        // re-associates at the width the AP now operates.
        if let Some((_, r)) = self.ht40.as_ref().filter(|_| self.wide) {
            if super::ht40::ht_operation(&bytes[36..])
                .is_some_and(|op| op != (r.primary, Some(r.secondary)))
            {
                return Err(Error::PeerLost);
            }
        }
        // Likewise at 80MHz: a VHT Operation no longer naming the bound
        // block (channel width 0 or another CCFS0), or an HT Operation on
        // another primary, drops the connection.
        if let Some((_, v)) = self.vht.as_ref().filter(|_| self.wide) {
            if super::vht::vht_operation(&bytes[36..])
                .is_some_and(|(width, ccfs0, _)| width != 1 || ccfs0 != v.center)
                || super::ht40::ht_operation(&bytes[36..])
                    .is_some_and(|(primary, _)| primary != v.primary)
            {
                return Err(Error::PeerLost);
            }
        }
        let Some(ie) = super::channel_policy::switch_ie(&bytes[36..]) else {
            return Ok(());
        };
        if self.switch.is_some() || self.retuning || ie.channel == Some(self.channel) {
            return Ok(());
        }
        // Programs qualified for the old primary (WMM/HT/BA/RTS/coding/QoS/
        // fallback/dm/N21W) cannot be carried over in place; the SME
        // re-associates and loads the new primary's own records.
        let carried = self.extension.is_none()
            && self.ht.is_none()
            && self.rx_ba_grant.is_none()
            && self.tx_ba_grant.is_none()
            && self.protection.is_none()
            && self.coding.is_none()
            && self.qos.is_none()
            && self.fallback.is_none()
            && self.tracking.grant.is_none()
            && self.power_tracking.is_none()
            && self.ht40.is_none()
            && self.vht.is_none();
        let channel = ie.channel.ok_or(Error::PeerLost)?;
        if !carried || !super::channel_policy::tunable(channel) {
            return Err(Error::PeerLost);
        }
        // mac80211 `ieee80211_sta_process_chanswitch` drops the connection
        // on an unusable target. A passive-only (RADAR / NO_IR) target is
        // usable here only under a current beacon witness for it (NARF's
        // stricter client rule: the station performs no radar detection).
        self.passive_grant(io, channel)?;
        let grant = if channel == 1 {
            None
        } else {
            Some(io.station_channel_grant(channel)?.ok_or(Error::PeerLost)?)
        };
        let interval = u64::from(u16::from_le_bytes([bytes[32], bytes[33]]));
        let wait = u64::from(ie.count.max(1) - 1) * interval * 1024 / 1000;
        self.switch = Some(super::channel_policy::Switch {
            channel,
            grant,
            due: now.saturating_add(wait),
            block: ie.block,
        });
        Ok(())
    }
    /// `ieee80211_chswitch_work` -> `rtw_ops_config(CHANGE_CHANNEL)` ->
    /// `rtw_set_channel` on the associated station: the native retune owner
    /// (TX refusal, TXPAUSE, drain, chip `set_channel`, TX power level,
    /// readback, epoch) without RF calibration, which Linux defers to the
    /// next `mgd_prepare_tx` (`need_rfk`). Keys, peer/AID and port state are
    /// unchanged; beacon-loss monitoring restarts on the new primary.
    async fn channel_switch(&mut self, io: &mut impl Io) -> Result<(), Error> {
        let switch = self.switch.take().ok_or(Error::State)?;
        let resume = self.phase;
        if !matches!(resume, Phase::FourWay | Phase::Open) {
            return Err(Error::State);
        }
        // Re-check the witness at the switch: the target's passive TX grant
        // follows only a still-current witness under the current policy.
        let passive = self.passive_grant(io, switch.channel)?;
        self.retune_to(io, switch.channel, switch.grant, false, resume)
            .await?;
        if passive.is_some() {
            self.admission.run(|| io.station_passive_tx(passive))?;
        }
        self.peer.as_mut().ok_or(Error::State)?.bss.channel = switch.channel;
        self.switch = None;
        self.switch_wait_beacon = switch.block;
        self.last_peer = self.now()?;
        Ok(())
    }
    pub(super) fn channel(&self) -> u8 {
        self.channel
    }
    /// The passive TX grant for joining or switching onto `channel`: `None`
    /// for an active primary (or without a policy snapshot, when nothing is
    /// passive-only), the grant for a passive-only one heard in its latest
    /// scan (`BeaconWitness::may_associate`), else `PeerLost`/`Profile`
    /// refusal (an unwitnessed passive-only primary is unusable).
    fn passive_grant(
        &self,
        io: &mut impl Io,
        channel: u8,
    ) -> Result<Option<(u8, Arc<RegulatoryDomain>)>, Error> {
        let Some(policy) = io.station_regulatory()? else {
            return Ok(None);
        };
        if !passive_only(Some(&policy), channel) {
            return Ok(None);
        }
        let center = super::channel_policy::any_frequency(channel).ok_or(Error::Profile)?;
        if !self.witness.may_associate(&policy, &[center]) {
            return Err(if self.peer.is_some() {
                Error::PeerLost
            } else {
                Error::Profile
            });
        }
        Ok(Some((channel, policy)))
    }
    /// A wide 5GHz span over the 20MHz `channels` may carry frame TX: under
    /// the installed policy snapshot either no constituent is passive-only,
    /// or every constituent is passive-only and heard in its latest
    /// covering scan (`BeaconWitness::may_associate`, cfg80211
    /// `beacon_found` per 20MHz channel). A span mixing plain and
    /// passive-only constituents is refused (the primary's passive TX grant
    /// would not cover the passive half). 2.4GHz spans are always plain.
    fn wide_witnessed(&self, io: &mut impl Io, channels: &[u8]) -> Result<bool, Error> {
        let Some(policy) = io.station_regulatory()? else {
            return Ok(true);
        };
        let passive = channels
            .iter()
            .filter(|c| passive_only(Some(&policy), **c))
            .count();
        if passive == 0 {
            return Ok(true);
        }
        if passive != channels.len() {
            return Ok(false);
        }
        let mut centers = Vec::with_capacity(channels.len());
        for c in channels {
            centers.push(super::channel_policy::any_frequency(*c).ok_or(Error::Profile)?);
        }
        Ok(self.witness.may_associate(&policy, &centers))
    }
    /// One dwell on the committed primary. Under a policy snapshot the dwell
    /// is a new witness scan generation for the primary (retracting its
    /// earlier witness until a Beacon is heard again, cfg80211
    /// `beacon_found`); the generation closes on every exit.
    async fn scan_inner(
        &mut self,
        io: &mut impl Io,
        dwell_ms: u64,
        probes: &[Vec<u8>],
        policy: Option<&Arc<RegulatoryDomain>>,
    ) -> Result<Vec<ObservedBss>, Error> {
        let center = super::channel_policy::any_frequency(self.channel).ok_or(Error::State)?;
        self.witness_scan = policy.map(|p| self.witness.begin_scan(p, &[center]));
        let result = self.scan_dwell(io, dwell_ms, probes).await;
        self.witness_scan = None;
        result
    }
    async fn scan_dwell(
        &mut self,
        io: &mut impl Io,
        dwell_ms: u64,
        probes: &[Vec<u8>],
    ) -> Result<Vec<ObservedBss>, Error> {
        for probe in probes {
            let admission = self.admission.clone();
            admission.run(|| Ok(self.transmit(io, probe.clone(), Kind::Probe)))??;
            while self.pending.is_some() {
                self.poll(io).await?;
                if self.pending.is_none() {
                    break;
                }
                self.environment.pause().await;
            }
        }
        let until = self.now()?.saturating_add(dwell_ms);
        loop {
            self.poll(io).await?;
            if self.now()? >= until {
                return Ok(self.candidates());
            }
            self.environment.pause().await;
        }
    }
    pub(super) async fn associate(
        &mut self,
        io: &mut impl Io,
        bssid: [u8; 6],
        ssid: &[u8],
        pmk: Option<Zeroizing<[u8; 32]>>,
        ies: &[u8],
    ) -> Result<(), Error> {
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        // The HT program writes the TX paths coexistence 1SS holds; Linux
        // leaves 1SS only while connected (2GFREE needs `wl_connected`), so
        // joining waits for the media-disconnect run to clear it.
        if self.one_ss.on {
            return Err(Error::Busy);
        }
        let candidate = self
            .candidates()
            .into_iter()
            .find(|c| c.bss.bssid == bssid)
            .ok_or(Error::Profile)?;
        if !super::channel_policy::tunable(candidate.bss.channel)
            || !super::channel_policy::base_rate_ok(candidate.bss.channel, candidate.basic_rates)
        {
            return Err(Error::Profile);
        }
        // A passive-only (RADAR / NO_IR) primary is joined only under its
        // beacon witness from the latest scan of it (cfg80211 `beacon_found`).
        let passive = self.passive_grant(io, candidate.bss.channel)?;
        // rtw_ops_mgd_prepare_tx: tune to the BSS primary and run RF
        // calibration there unless it is already current.
        self.retune(io, candidate.bss.channel, true).await?;
        // Frame TX on the passive-only primary, before the first
        // Authentication frame (`Native::passive_tx_allowed`).
        if passive.is_some() {
            self.admission.run(|| io.station_passive_tx(passive))?;
        }
        // HT40 (N2xB): the AP's HT Operation names a secondary whose 20MHz
        // half is itself an admitted channel (channel 1 or a loadable N2xO
        // record over the still base-only gate), and the firmware reports
        // `hw_cap.bw` 40 (`rtw_init_ht_cap`). On 5GHz a passive-only
        // (RADAR / NO_IR) span needs both halves passive and both halves
        // beacon-witnessed (`wide_witnessed`); otherwise the BSS is joined
        // at 20MHz.
        let secondary = match super::ht40::ht_operation(&candidate.bss.information_elements) {
            Some((primary, Some(secondary)))
                if primary == self.channel
                    && super::ht40::center(primary, secondary).is_some()
                    && io
                        .station_ht_facts()
                        .is_some_and(|f| super::ht40::hardware_allows(f.hardware.bandwidth))
                    && (secondary == 1
                        || self
                            .admission
                            .run(|| io.station_channel_grant(secondary))?
                            .is_some())
                    && self.wide_witnessed(io, &[primary, secondary])? =>
            {
                Some(secondary)
            }
            _ => None,
        };
        // VHT80 (N2xV): the AP's VHT Operation names this primary's Annex E
        // 80MHz block (channel width 1, CCFS0 the center; mac80211
        // `ieee80211_chandef_vht_oper`), the firmware reports `hw_cap.bw` 80
        // (`hw_bw_cap_to_bitamp`), the three other 20MHz constituents are
        // admitted channels (loadable N2xO records), and a passive-only span
        // is passive and beacon-witnessed on all four constituents
        // (`wide_witnessed`). Preferred over N2xB; otherwise HT40 or 20MHz.
        let center80 = match (
            super::band5::center80(self.channel),
            super::vht::vht_operation(&candidate.bss.information_elements),
        ) {
            (Some(center), Some((1, ccfs0, _)))
                if ccfs0 == center
                    && io
                        .station_ht_facts()
                        .is_some_and(|f| super::vht::hardware_allows(f.hardware.bandwidth)) =>
            {
                let channels = super::band5::constituents80(center);
                let mut admitted = true;
                for c in channels {
                    if c != self.channel
                        && self
                            .admission
                            .run(|| io.station_channel_grant(c))?
                            .is_none()
                    {
                        admitted = false;
                        break;
                    }
                }
                (admitted && self.wide_witnessed(io, &channels)?).then_some(center)
            }
            _ => None,
        };
        // Off channel 1 every program below loads only its own per-channel
        // record over the channel-scoped base (`channel_policy::scope_request`);
        // absent records leave the base legacy CCK1 profile.
        let mode = if pmk.is_some() {
            SecurityMode::Wpa2Psk
        } else {
            SecurityMode::Open
        };
        let extension = io
            .station_extension()?
            // A 5GHz primary loads its own band-5 N2xL (OFDM-only, OFDM6
            // base; `channel_policy::scope_request`).
            .filter(|g| {
                g.band5() == super::band5::primary(self.channel)
                    && candidate.basic_rates & !g.rates() == 0
                    && g.channel() == self.channel
            });
        let proposed = match &extension {
            Some(g)
                if g.wmm()
                    && narf_wireless::wmm::Parameters::parse(
                        &candidate.bss.information_elements,
                    )
                    .map_err(|_| Error::Profile)?
                    .is_some() =>
            {
                io.station_ht_extension(g.clone())?
            }
            _ => None,
        };
        // N2xC TX coding needs the HT program and its own exact continuation.
        let coding = match &proposed {
            // Identity only here: the live check runs once the extension and
            // HT programs enclose it (`station_bind_continuation`).
            Some(_) => io
                .station_continuation(&super::coding::KIND)?
                .and_then(|g| {
                    let gate = io.station_gate().ok()?;
                    let flags = super::coding::bounds(gate.did(), g.payload())?;
                    g.matches(&gate).then_some((g, flags))
                }),
            None => None,
        };
        let flags = coding.as_ref().map_or(0, |c| c.1);
        // N2xB HT40 needs the HT program (same MCS set), this primary and the
        // AP's admitted secondary. Identity only here, like N2xC.
        // N2xV VHT80 needs the HT program, this primary and the AP's block.
        // Identity only here, like N2xB.
        let vht = match (&proposed, center80) {
            (Some(_), Some(center)) => io.station_continuation(&super::vht::KIND)?.and_then(|g| {
                let gate = io.station_gate().ok()?;
                let r = super::vht::Record::decode(gate.did(), g.payload())?;
                (g.matches(&gate) && r.primary == self.channel && r.center == center)
                    .then_some((g, r))
            }),
            _ => None,
        };
        let ht40 = match (&proposed, secondary) {
            (Some(h), Some(secondary)) if vht.is_none() => io
                .station_continuation(super::ht40::kind(self.channel))?
                .and_then(|g| {
                    let gate = io.station_gate().ok()?;
                    let r = super::ht40::Record::decode(gate.did(), g.payload())?;
                    (g.matches(&gate)
                        && r.primary == self.channel
                        && r.secondary == secondary
                        && r.mcs == h.mcs())
                    .then_some((g, r))
                }),
            _ => None,
        };
        let mut plan = match (&proposed, &ht40) {
            // rtw_init_ht_cap + rtw_init_vht_cap; VHT DATA is uncoded, so no
            // N2xC TX coding is advertised.
            (Some(h), _) if vht.is_some() => JoinPlan::prepare_with_phy(
                &candidate.bss,
                self.own,
                ssid,
                mode,
                h.local_vht80(0, &vht.as_ref().ok_or(Error::State)?.1)
                    .ok_or(Error::State)?,
            )?,
            (Some(h), Some((_, r))) => JoinPlan::prepare_with_phy(
                &candidate.bss,
                self.own,
                ssid,
                mode,
                h.local_wide(flags, r.sgi),
            )?,
            (Some(h), None) => JoinPlan::prepare_with_phy(
                &candidate.bss,
                self.own,
                ssid,
                mode,
                h.local_coded(flags),
            )?,
            (None, _) => JoinPlan::prepare(&candidate.bss, self.own, ssid, mode)?,
        };
        let ht = proposed.filter(|_| plan.offered_phy().is_some());
        // Upstream rtw88 takes no HT protection-mode action (ht_protection_modes).
        // 40MHz only as the exact N2xB pair.
        let wide = match plan.offered_phy().map(|p| {
            (
                p.width(),
                p.occupied_channels(),
                p.center_channel(),
                p.vht().is_some(),
            )
        }) {
            None | Some((association::phy::Width::Twenty, ..)) => false,
            // 80MHz only as the exact N2xV block with VHT.
            Some((association::phy::Width::Eighty, _, center, true)) => match &vht {
                Some((_, v)) if ht.is_some() && center == v.center => true,
                _ => return Err(Error::Profile),
            },
            Some((association::phy::Width::Forty, channels, ..)) => match &ht40 {
                Some((_, r))
                    if ht.is_some()
                        && channels == [r.primary.min(r.secondary), r.primary.max(r.secondary)] =>
                {
                    true
                }
                _ => return Err(Error::Profile),
            },
            Some(_) => return Err(Error::Profile),
        };
        let ht40 = ht40.filter(|_| wide);
        let vht = vht.filter(|_| wide);
        if vht.is_some() && ht40.is_some() {
            return Err(Error::State);
        }
        plan.append_sme_ies(ies)?;
        if let Some(pmk) = pmk {
            let nonce = self.environment.nonce().ok_or(Error::Entropy)?;
            let station_rsne = plan.rsn_body().ok_or(Error::Profile)?;
            self.security = Some(Security::new(
                self.own,
                bssid,
                &pmk,
                &station_rsne,
                candidate.ap_rsne.as_deref().ok_or(Error::Profile)?,
                candidate.ap_rsnxe.as_deref(),
                3,
            )?);
            self.initial_nonce = Some(nonce);
        }
        let mut attempt = Attempt {
            admission: self.admission.clone(),
            armed: true,
        };
        // Missing/unqualified extension preserves the original CCK1 profile.
        // Each chip can supply only its own exact-board sealed extension.
        if let Some(grant) = extension {
            if candidate.basic_rates & !grant.rates() == 0 {
                let p = if grant.wmm() {
                    narf_wireless::wmm::Parameters::parse(&candidate.bss.information_elements)
                        .map_err(|_| Error::Profile)?
                } else {
                    None
                };
                if let Some(p) = p {
                    super::wmm::words(p, candidate.bss.capability & 0x400 != 0, grant.band5())?;
                }
                self.wmm_requested = p.is_some();
                self.admission
                    .run(|| io.station_bind_extension(grant.clone()))?;
                self.extension = Some(grant);
                // N2xF fallback needs only the bound extension.
                if let Some(g) = io.station_continuation(&super::fallback::KIND)? {
                    let gate = io.station_gate()?;
                    if super::fallback::bounds(g.payload()) && g.check(&gate).is_ok() {
                        self.admission
                            .run(|| io.station_bind_continuation(g.clone()))?;
                        self.fallback = Some(g);
                    }
                }
                if self.wmm_requested {
                    if let Some(g) = io.station_continuation(&super::qos::KIND)? {
                        let gate = io.station_gate()?;
                        if let Some(acs) = super::qos::bounds(g.payload()) {
                            if g.check(&gate).is_ok() {
                                self.admission
                                    .run(|| io.station_bind_continuation(g.clone()))?;
                                self.qos = Some((g, acs));
                            }
                        }
                    }
                }
            }
        }
        if let Some(h) = ht {
            self.admission.run(|| io.station_bind_ht(h.clone()))?;
            if let Some((g, flags)) = coding {
                // A grant that is not current leaves TX uncoded.
                if self
                    .admission
                    .run(|| io.station_bind_continuation(g.clone()))
                    .is_ok()
                {
                    self.coding = Some((g, flags));
                }
            }
            h.program(io, &self.admission).await?;
            if let Some((g, r)) = ht40 {
                self.admission
                    .run(|| io.station_bind_continuation(g.clone()))?;
                self.widen(io, &super::ht::Wide::Forty(r)).await?;
                self.ht40 = Some((g, r));
            }
            if let Some((g, v)) = vht {
                self.admission
                    .run(|| io.station_bind_continuation(g.clone()))?;
                self.widen(io, &super::ht::Wide::Eighty(v)).await?;
                self.vht = Some((g, v));
            }
            // RX may arrive at negotiated HT rates immediately after the AP's
            // association response, before the awaited native peer commit.
            // The native RX bound is the locally advertised MCS0..7, whereas
            // ordinary TX remains phase-gated until the bound response.
            let p = h.profile(
                candidate.rates & self.extension.as_ref().ok_or(Error::State)?.rates(),
                h.mcs(),
                false,
            )?;
            // At 80MHz the RX bound also admits the advertised VHT set.
            let p = super::packet_format::DataProfile {
                vht: self
                    .vht
                    .as_ref()
                    .map(|(_, v)| super::packet_format::VhtRates {
                        tx: v.tx_mask(),
                        rx: h.vht_rx(),
                    }),
                ..p
            };
            let hal = self.hal_profile(p);
            self.admission.run(|| io.packet_profile(hal))?;
            if let Some(g) = io.station_rx_ba_extension(h.clone())? {
                self.admission.run(|| io.station_bind_rx_ba(g.clone()))?;
                self.rx_ba_grant = Some(g);
            }
            if let Some(g) = io.station_tx_ba_extension()? {
                self.admission.run(|| io.station_bind_tx_ba(g.clone()))?;
                super::tx_ba::program(io).await?;
                // The ADDBA request offers A-MSDU only where the producer
                // may run (`rtw_ops_can_aggregate_in_amsdu`: not 2.4GHz).
                self.tx_ba
                    .request_amsdu(super::band5::primary(self.channel));
                self.tx_ba_grant = Some(g);
            }
            // The RTS program (N2xR), the dynamic mechanism (N2xD) and N21W
            // thermal tracking are qualified on 2.4GHz only (CCK RTS rate,
            // CCK PD, 2.4GHz swing tables): a 5GHz association runs without.
            let band5 = super::band5::primary(self.channel);
            if let Some(g) = io.station_protection_extension()?.filter(|_| !band5) {
                self.admission
                    .run(|| io.station_bind_protection(g.clone()))?;
                self.protection = Some(g);
            }
            self.ht = Some(h);
        }
        if let Some(g) = io
            .station_continuation(&super::dm::KIND)?
            .filter(|_| !super::band5::primary(self.channel))
        {
            let gate = io.station_gate()?;
            if let Some(b) =
                super::dm::bounds(gate.did(), g.payload()).filter(|_| g.check(&gate).is_ok())
            {
                // B22 `rtw8822b_pwr_track` re-IQKs at threshold 8: the dm
                // program binds only together with its exact `N2BW` record.
                let iqk = if gate.did() == 0xb822 && b.enabled & super::dm::PWR_TRACK != 0 {
                    io.station_continuation(&super::tracking8822b::KIND)?
                        .filter(|w| super::tracking8822b::binds(w, &g) && w.check(&gate).is_ok())
                        .map(Some)
                } else {
                    Some(None)
                };
                if let Some(iqk) = iqk {
                    self.tracking.grant = Some(g);
                    self.tracking.iqk = iqk;
                }
            }
        }
        if let Some(facts) = self
            .tracking
            .facts
            .filter(|f| f.did == 0xc821 && f.power_track_type == 0 && f.thermal[0] <= 63)
        {
            // N21W tracks the committed TXAGC selection: the HT20 indices
            // on a 20MHz association, the N2xB HT40 indices (one-stream
            // MCS0..7, as `ht40::write_power` commits them to 0x1d0c) on a
            // 40MHz association. The grant's request identity binds the
            // bound N2xB record, so an HT20 record cannot authorize HT40
            // tracking and vice versa.
            if self.ht.is_some() && !super::band5::primary(self.channel) {
                if let Some(g) = io
                    .station_power_tracking_extension(facts.thermal[0], self.tracking.grant.clone())
                    .await?
                {
                    firmware_transport::enclosed(
                        |op| self.admission.run(op),
                        io.station_bind_power_tracking(g.clone()),
                    )
                    .await?;
                    self.admission.retire_receive()?;
                    self.power_tracking = Some(Box::new(super::tracking8821c::Tracker::new(g)));
                }
            }
        }
        station_control::prepare_peer(io, bssid, &self.admission).await?;
        self.peer = Some(candidate);
        self.deadline = self.now()?.saturating_add(5000);
        self.last_peer = self.last_now;
        // mac80211 mgd_prepare_tx: rtw_coex_connect_notify(ASSOCIATE_START).
        self.coex_event(io, CoexEvent::Connect(true)).await?;
        let auth = plan.start_authentication()?.to_vec();
        self.plan = Some(plan);
        self.phase = Phase::Authentication;
        let admission = self.admission.clone();
        admission.run(|| Ok(self.transmit(io, auth, Kind::Authentication)))??;
        loop {
            self.poll(io).await?;
            if let Some((aid, short)) = self.peer_commit {
                let band5 = super::band5::primary(self.channel);
                station_control::commit_peer(io, bssid, aid, short, band5, &self.admission).await?;
                self.associated_aid = Some(aid);
                // BSS_CHANGED_ASSOC: connect finish then media connect.
                let interval = self.peer.as_ref().map_or(0, |p| p.bss.beacon_interval);
                self.coex_event(io, CoexEvent::Connect(false)).await?;
                self.coex_event(io, CoexEvent::Media(true, interval))
                    .await?;
                self.bf_assoc(io, bssid).await?;
                if self.extension.is_some() {
                    super::wmm::commit(
                        io,
                        self.hal_profile(self.data_profile),
                        self.wmm,
                        short,
                        &self.admission,
                    )
                    .await?;
                }
                self.admission.run(|| {
                    self.peer_commit = None;
                    self.phase = Phase::FourWay;
                    Ok(())
                })?;
            }
            if self.established && (self.tx_ba_grant.is_none() || self.tx_ba.settled()) {
                attempt.armed = false;
                return Ok(());
            }
            self.environment.pause().await;
        }
    }
    /// `mac80211.c` `BSS_CHANGED_ASSOC` -> `bf.c::rtw_bf_assoc` on the bound
    /// N2xV association: MU beamformee when the local MU advertisement and
    /// the AP's MU beamformer bit agree (`bfer_mu_max_num` 1, this single
    /// station), else SU when the AP is an SU beamformer. The shared
    /// negotiation only keeps MU beamformee alongside SU beamformee (the
    /// association request drops both without the AP's SU beamformer bit,
    /// `mlme.c::ieee80211_add_vht_ie`), so MU is bound exactly when it was
    /// advertised (`mu_mimo_owner`).
    async fn bf_assoc(&mut self, io: &mut impl Io, bssid: [u8; 6]) -> Result<(), Error> {
        if self.vht.is_none() || self.bfee.is_some() {
            return Ok(());
        }
        let Some(vht) = self
            .plan
            .as_ref()
            .and_then(JoinPlan::negotiated_phy)
            .and_then(|p| p.vht())
            .filter(|v| v.su_beamformee())
        else {
            return Ok(());
        };
        let did = io.station_gate()?.did();
        let b = if vht.mu_beamformee() {
            self.associated_aid
                .and_then(|aid| super::bf::Bfee::mu(did, bssid, aid))
        } else {
            vht.peer_sounding_dimensions()
                .and_then(|s| super::bf::Bfee::su(did, bssid, s))
        };
        let Some(b) = b else {
            return Ok(());
        };
        crate::rtw88::firmware_transport::enclosed(|op| self.admission.run(op), async {
            io.station_allowed()?;
            super::bf::phy_init(io).await?;
            if b.is_mu() {
                super::bf::enable_mu(io, did, b).await
            } else {
                super::bf::enable_su(io, did, b).await
            }
        })
        .await?;
        self.mu_group = super::bf::MuGroup::default();
        self.bfee = Some(b);
        Ok(())
    }
    /// `vht.c::ieee80211_process_mu_groups` -> `BSS_CHANGED_MU_GROUPS` ->
    /// `rtw_bf_set_gid_table`: a VHT Group ID Management frame from the AP
    /// reprograms the MU STA tables only while the bound role is MU, and only
    /// when membership or position changed. `true` when the frame was one.
    async fn gid_management(&mut self, io: &mut impl Io, bytes: &[u8]) -> Result<bool, Error> {
        let (Some(b), Some(ap)) = (self.bfee, self.peer.as_ref().map(|p| p.bss.bssid)) else {
            return Ok(false);
        };
        if !b.is_mu() {
            return Ok(false);
        }
        let Some(g) = super::bf::gid_management(bytes, self.own, ap) else {
            return Ok(false);
        };
        if g != self.mu_group {
            super::bf::set_gid(io, &g).await?;
            self.mu_group = g;
        }
        Ok(true)
    }
    pub(super) async fn send(&mut self, io: &mut impl Io, frame: &[u8]) -> Result<(), Error> {
        let admission = self.admission.clone();
        let result = crate::rtw88::firmware_transport::enclosed(|op| admission.run(op), async {
            Ok(self.send_inner(io, frame).await)
        })
        .await
        .map_err(Error::Native)
        .and_then(|result| result);
        // Closure happens after run releases the publication lock; stopping
        // inside it would re-enter that lock. Fatal native/key errors cannot
        // leave established metadata visible until an unrelated later poll.
        if !self.admission.teardown_pending()
            && result.as_ref().is_err_and(|error| {
                !matches!(
                    error,
                    Error::Busy | Error::Profile | Error::Transport(packet::Error::Busy)
                )
            })
        {
            self.fail(io);
        }
        result
    }
    /// Coded DATA requires the current N2xC continuation. A revoked or
    /// mismatched one downgrades to the uncoded base HT profile.
    pub(super) fn coding_live(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if !self.data_profile.ldpc && !self.data_profile.stbc {
            return Ok(());
        }
        let gate = io.station_gate()?;
        if self
            .coding
            .as_ref()
            .is_some_and(|(g, _)| g.check(&gate).is_ok())
        {
            return Ok(());
        }
        self.coding = None;
        self.coding_restore |= self.data_profile.ldpc;
        let p = self.data_profile.uncoded();
        // Callers already run inside the current admission.
        io.packet_profile(self.hal_profile(p))?;
        self.data_profile = p;
        Ok(())
    }
    /// All-TID routing requires the current N2xQ continuation. A revoked or
    /// mismatched one returns every frame to BE/TID0 under the base gate.
    pub(super) fn qos_live(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if self.data_profile.acs == 0 {
            return Ok(());
        }
        let gate = io.station_gate()?;
        if self
            .qos
            .as_ref()
            .is_some_and(|(g, _)| g.check(&gate).is_ok())
        {
            return Ok(());
        }
        self.qos = None;
        let p = super::packet_format::DataProfile {
            acs: 0,
            ..self.data_profile
        };
        io.packet_profile(self.hal_profile(p))?;
        self.data_profile = p;
        Ok(())
    }
    /// Firmware RA fallback requires the current N2xF continuation. A
    /// revoked or mismatched one returns DATA to the fixed rate.
    pub(super) fn fallback_live(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if !self.data_profile.fallback {
            return Ok(());
        }
        let gate = io.station_gate()?;
        if self
            .fallback
            .as_ref()
            .is_some_and(|g| g.check(&gate).is_ok())
        {
            return Ok(());
        }
        self.fallback = None;
        let p = super::packet_format::DataProfile {
            fallback: false,
            ..self.data_profile
        };
        io.packet_profile(self.hal_profile(p))?;
        self.data_profile = p;
        Ok(())
    }
    async fn send_inner(&mut self, io: &mut impl Io, frame: &[u8]) -> Result<(), Error> {
        self.coding_live(io)?;
        self.qos_live(io)?;
        self.fallback_live(io)?;
        self.txrx_1ss_live(io)?;
        if !admitted(frame, self.own) {
            return Err(Error::Profile);
        }
        self.tracking.tx_bytes = self.tracking.tx_bytes.saturating_add(frame.len() as u64);
        self.rx_agg.tx(frame.len());
        self.coex.traffic.tx_cnt = self.coex.traffic.tx_cnt.saturating_add(1);
        self.coex.traffic.tx_bytes = self
            .coex
            .traffic
            .tx_bytes
            .saturating_add(frame.len() as u64);
        let tid = self.data_tid(frame);
        if let Some(g) = &self.tx_ba_grant {
            // Linux starts originator BA only for actual non-VO DATA demand.
            self.tx_ba.want(tid, g.tids());
        }
        if self.tx_ba.active(tid).is_some() {
            alloc::boxed::Box::pin(self.send_batch_inner(io, &[frame])).await?;
            return Ok(());
        }
        if !self.ready() || !io.packet_ready() {
            return Err(Error::Busy);
        }
        if !admitted(frame, self.own) {
            return Err(Error::Profile);
        }
        let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
        let native = if let Some(security) = &mut self.security {
            if self.data_profile.qos {
                security.transmit_ethernet_qos(frame, tid)?
            } else {
                security.transmit_ethernet(frame)?
            }
        } else {
            if !admitted(frame, self.own) {
                return Err(Error::Profile);
            }
            let mut bytes = vec![if self.data_profile.qos { 0x88 } else { 8 }, 1, 0, 0];
            bytes.extend_from_slice(&peer);
            bytes.extend_from_slice(&self.own);
            bytes.extend_from_slice(&frame[..6]);
            let sequence = if self.tx_ba_grant.is_some() && self.data_profile.qos {
                let s = self.qos_sequence[usize::from(tid)];
                self.qos_sequence[usize::from(tid)] = (s + 1) & 4095;
                s
            } else {
                let s = self.sequence;
                self.sequence = (s + 1) & 4095;
                s
            };
            bytes.extend_from_slice(&(sequence << 4).to_le_bytes());
            if self.data_profile.qos {
                bytes.extend_from_slice(&[tid, 0]);
            }
            bytes.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            bytes.extend_from_slice(&frame[12..]);
            bytes
        };
        let rts = self
            .protection
            .as_ref()
            .is_some_and(|g| native.len() as u64 > u64::from(g.threshold()));
        self.transmit(io, native, if rts { Kind::RtsData } else { Kind::Data })?;
        if rts {
            self.data_drain = Some((self.now()?, None));
        }
        Ok(())
    }
}
#[path = "station_tx_amsdu.rs"]
mod amsdu;
#[path = "station_rx_agg.rs"]
mod rx_agg;
#[path = "station_tx_ba.rs"]
mod tx;
/// The primary is passive-only (cfg80211 RADAR / NO_IR) under `policy`.
/// Only a 5GHz primary can be: 2.4GHz admission refuses DFS / NO_IR rules.
pub(super) fn passive_only(policy: Option<&Arc<RegulatoryDomain>>, channel: u8) -> bool {
    super::band5::primary(channel)
        && policy.is_some_and(|p| {
            super::channel_policy::any_frequency(channel)
                .is_some_and(|c| witness::passive_only(p, c))
        })
}
/// `ht.c::ieee80211_send_smps_action(sdata, smps, ap, ap)`: DA = BSSID =
/// the AP, HT category, `WLAN_HT_ACTION_SMPS`, `WLAN_HT_SMPS_CONTROL_STATIC`
/// (1) or `_DISABLED` (0). The sequence number is filled at transmit.
fn smps_action(own: [u8; 6], ap: [u8; 6], static_smps: bool) -> Vec<u8> {
    let mut b = vec![0xd0, 0, 0, 0];
    b.extend_from_slice(&ap);
    b.extend_from_slice(&own);
    b.extend_from_slice(&ap);
    b.extend_from_slice(&[0, 0, 7, 1, u8::from(static_smps)]);
    b
}
pub(super) fn admitted(frame: &[u8], own: [u8; 6]) -> bool {
    (14..=1514).contains(&frame.len())
        && frame[6..12] == own
        && frame[..6] != [0; 6]
        && u16::from_be_bytes([frame[12], frame[13]]) >= 0x600
        && !matches!(
            u16::from_be_bytes([frame[12], frame[13]]),
            0x888e | 0x80f3 | 0x8137
        )
}
fn ethernet(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> Option<Vec<u8>> {
    ethernet_profile(frame, own, peer, false, false)
}
fn ethernet_profile(
    frame: &[u8],
    own: [u8; 6],
    peer: [u8; 6],
    qos: bool,
    ht: bool,
) -> Option<Vec<u8>> {
    let header = if frame.first() == Some(&0x88)
        && qos
        && frame.get(24..26).is_some_and(|q| {
            q[1] == 0
                && if ht {
                    q[0] & 0x90 == 0 && matches!(q[0] & 0x60, 0 | 0x60)
                } else {
                    q[0] == 0
                }
        }) {
        26
    } else {
        24
    };
    if !(header + 8..=header + 1508).contains(&frame.len())
        || frame[0] != if header == 26 { 0x88 } else { 8 }
        || frame[1] & 0xc7 != 2
        || frame[22] & 15 != 0
        || frame[10..16] != peer
        || (frame[4..10] != own && frame[4] & 1 == 0)
        || frame[16] & 1 != 0
        || frame[16..22] == [0; 6]
        || frame[header..header + 6] != [0xaa, 0xaa, 3, 0, 0, 0]
    {
        return None;
    }
    let proto = u16::from_be_bytes([frame[header + 6], frame[header + 7]]);
    if proto < 0x600 || matches!(proto, 0x888e | 0x80f3 | 0x8137) {
        return None;
    }
    let mut bytes = Vec::with_capacity(frame.len() - 18);
    bytes.extend_from_slice(&frame[4..10]);
    bytes.extend_from_slice(&frame[16..22]);
    bytes.extend_from_slice(&frame[header + 6..]);
    Some(bytes)
}
fn plaintext_eapol(b: &[u8], own: [u8; 6], ap: [u8; 6]) -> bool {
    let at = if b.first() == Some(&0x88) { 26 } else { 24 };
    b.len() >= at + 12
        && matches!(b[0], 8 | 0x88)
        && b[22] & 15 == 0
        && b[1] & 0xc7 == 2
        && b[4..10] == own
        && b[10..16] == ap
        && b[16..22] == ap
        && (at != 26 || b[24] & 0xf0 == 0 && b[25] == 0)
        && b[at..at + 8] == [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]
        && (1..=3).contains(&b[at + 8])
        && b[at + 9] == 3
        && usize::from(u16::from_be_bytes([b[at + 10], b[at + 11]])) + at + 12 == b.len()
}
