//! The concurrent P2P GO vif's AP owner beside a live home station. Linux
//! mt7921 runs a P2P_GO as one more AP `mt792x_vif` (`mt7921_add_interface`
//! BSS/OMAC/BMC, `mt7921_start_ap`/`mt7921_stop_ap`) on the shared chanctx;
//! NARF opens the same identity as a second AP owner with its own role
//! `State` next to the home role.
//!
//! A GO operation runs the unchanged AP owner code on the GO vif: `enter_go`
//! swaps the GO's `ap::Owner` and `State` into the session's AP/role slots
//! for the operation's lifetime and its guard swaps them back on completion
//! or cancellation (drop). The home station owner (`Session::station`) stays
//! in place; the AP code never touches it. The shared RX capture epoch, TX
//! completion FIFO and channel stay device-wide:
//!
//! - **RX demux.** A GO step hands copies of the home station (its peer
//!   WCID, or its BSSID as transmitter) to the home `demuxed` queue; the home
//!   station's receive and waits hand GO copies (a GO peer's WCID, the GO
//!   address as receiver, or a broadcast probe request) to the GO's queue
//!   (`mt792x_rx_get_wcid` keeps delivering every vif).
//! - **Receive floor.** The GO admits copies `floor..=current`: a home fence
//!   moves the shared epoch without fencing the GO. A GO fence while the
//!   capture stays open for the home station marks the GO `fenced`; it
//!   renews again before its port reopens (`open_ap_capture`).
//! - **TX completions.** `data_pending` entries carry `PendingOwner::Go`;
//!   the home owner's waits credit a GO completion to the GO (`credit_go`)
//!   and the GO's waits credit a station completion to the home link.
//! - **Channel.** Same channel only: beside an associated home station the
//!   GO requires the home grant's primary channel (no 6 GHz) and leaves the
//!   device-global tuning to the home owner; beside an idle home station it
//!   tunes the radio (no reset) and the home join must then use the GO's
//!   channel. NoA/opportunistic PS is not offloaded on mt7921
//!   (`mt76_connac_mcu_set_p2p_oppps` is mt7615-only).
//! - **Failure.** A failed GO role is never reset in place: the WFSYS reset
//!   would retire the home association. It stays `Failed` until a verified
//!   recovery/removal retires both owners (`retire_go`).
use super::ap::{validate_settings, Owner};
use super::group_link::PendingOwner;
use super::{Backend, CapturedData, Error, Session, Stage, State};
use crate::mt7921::association::ap::Plan;
use crate::mt7921::vif_slots::Vif;
use alloc::sync::Arc;
use core::ops::{Deref, DerefMut};
use narf_wireless::ap_control::ApControlAuthority;

/// Captured packets the GO may hold before the oldest drop.
const DEMUX_DEPTH: usize = 64;

/// The concurrent GO vif's AP owner and its own role state
/// (`RadioReady` = vif reserved, no native command; `AccessPoint` after
/// START; `Failed` until verified recovery). While a GO operation runs the
/// two slots hold the swapped-out home AP owner (`None`) and home state.
#[derive(Debug)]
pub(super) struct GoOwner {
    vif: Vif,
    own: [u8; 6],
    ap: Option<Owner>,
    state: State,
    swapped: bool,
}

/// The session with the GO swapped into its AP/role slots.
pub(super) struct GoRole<'a, B: Backend> {
    session: &'a mut Session<B>,
}
impl<B: Backend> Deref for GoRole<'_, B> {
    type Target = Session<B>;
    fn deref(&self) -> &Session<B> {
        self.session
    }
}
impl<B: Backend> DerefMut for GoRole<'_, B> {
    fn deref_mut(&mut self) -> &mut Session<B> {
        self.session
    }
}
impl<B: Backend> Drop for GoRole<'_, B> {
    fn drop(&mut self) {
        self.session.swap_go();
    }
}

fn push_demuxed(owner: &mut Owner, packet: CapturedData) {
    if owner.demuxed.len() >= DEMUX_DEPTH {
        owner.demuxed.pop_front();
    }
    owner.demuxed.push_back(packet);
}

/// Whether a decoded copy belongs to a live GO (`owner` in `state`): a GO
/// peer's WCID, the GO address as receiver, or a broadcast probe request
/// (which the station owner never consumes).
fn go_owns(owner: &Owner, state: &State, native: &super::scan::NativeRx<'_>) -> bool {
    if !matches!(state, State::AccessPoint { .. }) || !owner.activated {
        return false;
    }
    let frame = native.frame;
    let (Some(receiver), Some(transmitter)) = (frame.get(4..10), frame.get(10..16)) else {
        return false;
    };
    let transmitter: [u8; 6] = transmitter.try_into().unwrap();
    owner
        .peers
        .get(transmitter)
        .is_some_and(|peer| u16::from(peer.wcid) == native.wcid)
        || receiver == owner.plan.own
        || frame[0] == 0x40 && receiver == [0xff; 6]
}

impl<B: Backend> Session<B> {
    fn swap_go(&mut self) {
        if let Some(go) = self.go.as_mut() {
            core::mem::swap(&mut self.ap_owner, &mut go.ap);
            core::mem::swap(&mut self.state, &mut go.state);
            go.swapped = !go.swapped;
        }
    }
    /// True while a GO operation holds the AP/role slots.
    pub(super) fn go_role(&self) -> bool {
        self.go.as_ref().is_some_and(|go| go.swapped)
    }
    /// Run the AP owner on the GO vif.
    pub(super) fn enter_go(&mut self) -> Result<GoRole<'_, B>, Error> {
        if self.go_role() || self.group_role() || self.go.is_none() || self.ap_owner.is_some() {
            return Err(Error::Bounds);
        }
        // Only a settled home station role can share the radio.
        if !matches!(
            self.state,
            State::RadioReady(_) | State::ScanReady(_) | State::Associated { .. }
        ) {
            return Err(Error::Busy);
        }
        self.swap_go();
        Ok(GoRole { session: self })
    }

    /// Reserve the GO vif `vif` with own address `own` (Linux
    /// `mt7921_add_interface` for a P2P_GO vif happens at START here). One
    /// GO at a time and never beside a group client link
    /// (`if_comb_chanctx_base`: three interfaces including the P2P device);
    /// no home AP. No native command is sent.
    pub(super) fn open_go(&mut self, vif: Vif, own: [u8; 6]) -> Result<(), Error> {
        if vif == Vif::HOME || vif == self.station.link.vif() || self.go_role() {
            return Err(Error::Bounds);
        }
        if own == [0; 6] || own[0] & 1 != 0 {
            return Err(Error::Bounds);
        }
        if self.go.is_some() || self.group.is_some() || self.ap_owner.is_some() {
            return Err(Error::Busy);
        }
        let mut info = match self.state {
            State::RadioReady(info) | State::ScanReady(info) | State::Associated { info, .. } => {
                info
            }
            _ => return Err(Error::Busy),
        };
        info.capabilities.mac = own;
        self.go = Some(GoOwner {
            vif,
            own,
            ap: None,
            state: State::RadioReady(info),
            swapped: false,
        });
        Ok(())
    }
    /// The GO's vif and role state (`None` without a GO owner).
    pub(super) fn go_state(&self) -> Option<(Vif, State)> {
        let go = self.go.as_ref()?;
        Some((go.vif, if go.swapped { self.state } else { go.state }))
    }
    /// Retire the GO owner after a verified MAC/firmware reset (every vif's
    /// BSS/WTBL is gone) or once it is idle. Never inside a GO operation.
    pub(super) fn retire_go(&mut self) {
        if !self.go_role() {
            self.go = None;
        }
    }
    /// Close an idle GO owner that never sent a native command.
    pub(super) fn close_go(&mut self) -> Result<(), Error> {
        let go = self.go.as_ref().ok_or(Error::Bounds)?;
        if go.swapped || go.ap.is_some() || !matches!(go.state, State::RadioReady(_)) {
            return Err(Error::Busy);
        }
        if self.data_pending.go_owned() != 0 {
            return Err(Error::Busy);
        }
        self.go = None;
        Ok(())
    }

    /// The GO's AP plan while it runs (for the home owner's channel and
    /// RX gates).
    pub(super) fn go_plan(&self) -> Option<&Plan> {
        let go = self.go.as_ref().filter(|go| !go.swapped)?;
        go.ap.as_ref().map(|owner| owner.plan.as_ref())
    }
    /// One shared channel: the home station's grant must carry the GO's
    /// primary channel (no 6 GHz; the GO is 2.4/5 GHz 20 MHz only).
    pub(super) fn shares_go_channel(
        &self,
        permission: crate::mt7921::association::TxPermission,
    ) -> bool {
        self.go_plan()
            .is_none_or(|plan| permission.six.is_none() && permission.permits(plan.channel))
    }
    /// A copy-time epoch the AP owner admits: the current epoch for the
    /// home AP (unchanged), `floor..=current` for the concurrent GO.
    pub(super) fn ap_epoch_admits(&self, owner: &Owner, epoch: u64) -> bool {
        epoch != 0
            && if owner.plan.vif == Vif::HOME {
                epoch == self.receive_epoch
            } else {
                epoch >= owner.floor && epoch <= self.receive_epoch
            }
    }
    /// Whether the AP owner `owner` in role `state` is receive-current for
    /// a copy/batch epoch.
    pub(super) fn owner_ap_receive_current(
        &self,
        owner: &Owner,
        state: &State,
        epoch: u64,
    ) -> Result<bool, Error> {
        self.backend.check()?;
        if !matches!(state, State::AccessPoint { .. })
            || !owner.activated
            || !self.ap_epoch_admits(owner, epoch)
        {
            return Ok(false);
        }
        owner.identity.current().map_err(|_| Error::Authority)?;
        self.backend.check_tx_permission(owner.plan.permission)?;
        Ok(true)
    }
    /// The swapped-out GO (home role) under the shared capture epoch.
    pub(super) fn go_receive_current(&self, epoch: u64) -> Result<bool, Error> {
        match self.go.as_ref().filter(|go| !go.swapped) {
            Some(go) => match go.ap.as_ref() {
                Some(owner) => self.owner_ap_receive_current(owner, &go.state, epoch),
                None => Ok(false),
            },
            None => Ok(false),
        }
    }
    /// In the GO role: the swapped-out home station's receive currency.
    fn home_receive_current(&self) -> Result<bool, Error> {
        match self.go.as_ref().filter(|go| go.swapped) {
            Some(go) => self.owner_receive_current(&self.station, &go.state, self.receive_epoch),
            None => Ok(false),
        }
    }

    /// A GO fence (the GO-role `renew_receive_epoch`): the home station's
    /// floor, fragments and BA restart stay untouched; the shared capture
    /// stays open while the home station is current and the GO is marked
    /// fenced instead.
    pub(super) fn renew_go_receive_epoch(&mut self) -> Result<(), Error> {
        self.backend.close_receive_capture(0);
        self.receive_epoch = super::NEXT_RECEIVE_EPOCH
            .fetch_update(
                core::sync::atomic::Ordering::Relaxed,
                core::sync::atomic::Ordering::Relaxed,
                |epoch| epoch.checked_add(1),
            )
            .map_err(|_| Error::Bounds)?;
        let epoch = self.receive_epoch;
        let home = self.home_receive_current().unwrap_or(false)
            && self.backend.open_receive_capture(epoch).is_ok();
        if let Some(owner) = self.ap_owner.as_mut() {
            owner.floor = epoch;
            owner.fenced = home;
        }
        Ok(())
    }
    /// Open the AP owner's port on the shared capture. A GO fenced while
    /// the capture stayed open for the home station first moves its floor
    /// past every copy captured during its own fence.
    pub(super) fn open_ap_capture(&mut self) -> Result<(), Error> {
        if self.go_role() && self.ap_owner.as_ref().is_some_and(|owner| owner.fenced) {
            self.renew_go_receive_epoch()?;
            if let Some(owner) = self.ap_owner.as_mut() {
                owner.fenced = false;
            }
        }
        self.backend.open_receive_capture(self.receive_epoch)
    }
    /// Close the AP owner's port. In the GO role the shared capture stays
    /// open while the home station is current.
    pub(super) fn close_ap_capture(&mut self, epoch: u64) {
        self.backend.close_receive_capture(epoch);
        if self.go_role() && self.home_receive_current().unwrap_or(false) {
            let _ = self.backend.open_receive_capture(self.receive_epoch);
        }
    }
    /// An AP-owner FIFO entry: the GO's own in the GO role.
    pub(super) fn push_ap_pending(&mut self) {
        let now = self.backend.now_ns();
        if self.go_role() {
            self.data_pending.push_go(now);
        } else {
            self.data_pending.push_back(now);
        }
    }
    /// Retire the front FIFO entry for an AP-owner wait. In the GO role a
    /// home station entry is credited to the home link (`tx_credit`) and
    /// `None` returned; otherwise the completion is the AP owner's.
    pub(super) fn retire_ap_completion(
        &mut self,
        completion: crate::mt7921::packet_tx::Completion,
    ) -> Option<crate::mt7921::packet_tx::Completion> {
        match self.data_pending.pop_owner() {
            Some(PendingOwner::Station(link)) if self.go_role() => {
                if link == self.station.link
                    && self.station.tx_credit.len() < crate::mt7921::packet_tx::PIPELINE
                {
                    self.station.tx_credit.push_back(completion.status);
                }
                None
            }
            _ => Some(completion),
        }
    }
    /// Credit a GO entry's terminal status retired by a home-owner wait.
    pub(super) fn credit_go(&mut self, status: u8) {
        if let Some(owner) = self
            .go
            .as_mut()
            .filter(|go| !go.swapped)
            .and_then(|go| go.ap.as_mut())
        {
            if owner.tx_credit.len() < crate::mt7921::packet_tx::PIPELINE {
                owner.tx_credit.push_back(status);
            }
        }
    }
    /// In the GO role: apply credited completions (a failure fails the GO
    /// data path).
    pub(super) fn settle_go_credit(&mut self) -> Result<(), Error> {
        if !self.go_role() {
            return Ok(());
        }
        while let Some(status) = self
            .ap_owner
            .as_mut()
            .and_then(|owner| owner.tx_credit.pop_front())
        {
            if status != 0 {
                return Err(Error::Rejected(status));
            }
        }
        Ok(())
    }
    /// In the GO role, the next copy for the AP receive loop: the GO's own
    /// demuxed copies first; a ring copy of the home station goes to the
    /// home `demuxed` queue.
    pub(super) fn next_ap_copy(&mut self) -> Result<Option<CapturedData>, Error> {
        if !self.go_role() {
            return self.backend.receive_data_captured();
        }
        if let Some(packet) = self
            .ap_owner
            .as_mut()
            .and_then(|owner| owner.demuxed.pop_front())
        {
            return Ok(Some(packet));
        }
        for _ in 0..16 {
            let Some(packet) = self.backend.receive_data_captured()? else {
                return Ok(None);
            };
            if self.home_owns_copy(&packet) {
                if self.station.demuxed.len() >= DEMUX_DEPTH {
                    self.station.demuxed.pop_front();
                }
                self.station.demuxed.push_back(packet);
                continue;
            }
            return Ok(Some(packet));
        }
        Ok(None)
    }
    /// In the GO role: the home station's peer WCID, or (without a GO peer
    /// WCID) its BSSID as transmitter.
    fn home_owns_copy(&self, packet: &CapturedData) -> bool {
        let Some(go) = self.go.as_ref().filter(|go| go.swapped) else {
            return false;
        };
        if !matches!(go.state, State::Associated { .. }) {
            return false;
        }
        let Some(native) = super::scan::rx_native_with_amsdu(&packet.bytes) else {
            return false;
        };
        if native.wcid == u16::from(self.station.link.peer()) {
            return true;
        }
        let go_peer = self.ap_owner.as_ref().is_some_and(|owner| {
            owner
                .peers
                .addresses()
                .into_iter()
                .filter_map(|mac| owner.peers.get(mac))
                .any(|peer| u16::from(peer.wcid) == native.wcid)
        });
        !go_peer
            && self.station.bss.as_ref().is_some_and(|bss| {
                native.frame.get(10..16) == Some(&bss.bssid[..])
                    && native.frame.get(4..10) != self.ap_owner.as_ref().map(|o| &o.plan.own[..])
            })
    }
    /// In the home role: whether a decoded copy belongs to the live GO.
    pub(super) fn go_owns_rx(&self, native: &super::scan::NativeRx<'_>) -> bool {
        self.go.as_ref().filter(|go| !go.swapped).is_some_and(|go| {
            go.ap
                .as_ref()
                .is_some_and(|o| go_owns(o, &go.state, native))
        })
    }
    /// In the home role: queue an original copy for the GO.
    pub(super) fn forward_to_go(&mut self, packet: CapturedData) {
        if let Some(owner) = self
            .go
            .as_mut()
            .filter(|go| !go.swapped)
            .and_then(|go| go.ap.as_mut())
        {
            push_demuxed(owner, packet);
        }
    }
    /// The station-wait split helper: route a ring copy to the swapped-out
    /// GO if it owns it (`wait_station_rx`).
    pub(super) fn split_go(go: &mut Option<GoOwner>, packet: CapturedData) -> Option<CapturedData> {
        let Some(go) = go.as_mut().filter(|go| !go.swapped) else {
            return Some(packet);
        };
        let state = go.state;
        let Some(owner) = go.ap.as_mut() else {
            return Some(packet);
        };
        if super::scan::rx_native_with_amsdu(&packet.bytes)
            .is_some_and(|native| go_owns(owner, &state, &native))
        {
            push_demuxed(owner, packet);
            return None;
        }
        Some(packet)
    }

    /// START the GO on its vif (`mt7921_add_interface` DEV_INFO/BSS, then
    /// `mt7921_start_ap`: BSS with CONNECTION_P2P_GO, BMC STA_REC, beacon
    /// offload) without a WFSYS reset, then open its port
    /// (`commit_ap_start`). Returns the GO's receive epoch.
    pub(super) async fn start_go(
        &mut self,
        authority: Arc<ApControlAuthority>,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<u64, Error> {
        validate_settings(&config, &settings)?;
        if authority.mode() != 9 || !authority.has_reservation() {
            return Err(Error::Authority);
        }
        if self.p2p_rf_busy() {
            return Err(Error::Busy);
        }
        let (vif, own) = {
            let go = self.go.as_ref().ok_or(Error::Bounds)?;
            (go.vif, go.own)
        };
        let identity = authority.identity().map_err(|_| Error::Authority)?;
        if identity.mac() != own {
            return Err(Error::Authority);
        }
        let policy = self.backend.regulatory_domain()?;
        let mut role = self.enter_go()?;
        let info = match role.state {
            State::RadioReady(info) => info,
            _ => return Err(Error::Busy),
        };
        let mut plan = Plan::prepare(info, config, &policy)?;
        plan.vif = vif;
        plan.network = crate::mt7921::p2p_wire::Network::P2p;
        // The home role's state sits in the GO slot while the GO runs.
        let home = role.go.as_ref().map(|go| go.state).ok_or(Error::Bounds)?;
        let tune = match home {
            State::Associated { .. } => {
                let live = role.station.permission.ok_or(Error::Busy)?;
                if live.six.is_some() || !live.permits(plan.channel) {
                    return Err(Error::Busy);
                }
                false
            }
            State::RadioReady(_) | State::ScanReady(_) => true,
            _ => return Err(Error::Busy),
        };
        let plan = Arc::new(plan);
        role.backend.check_tx_permission(plan.permission)?;
        role.ap_owner = Some(Owner {
            info,
            plan: plan.clone(),
            identity,
            peers: super::ap_peer::Peers::default(),
            default_group: None,
            pending_plan: None,
            events: alloc::collections::VecDeque::new(),
            start_settings: Some(settings),
            activated: false,
            pending: Some(authority.clone()),
            floor: 0,
            fenced: false,
            demuxed: alloc::collections::VecDeque::new(),
            tx_credit: alloc::collections::VecDeque::new(),
        });
        role.stage(Stage::ApStart);
        role.boot_started = Some(role.backend.now_ns());
        let result = role
            .start_ap_inner(info, &plan, &authority, tune)
            .await
            .and_then(|()| role.check_ap_request(&authority));
        role.boot_started = None;
        if let Err(error) = result {
            role.state = State::Failed {
                stage: Stage::ApStart,
                error,
            };
            return Err(error);
        }
        role.state = State::AccessPoint {
            info,
            frequency_mhz: plan.config.frequency_mhz,
        };
        role.commit_ap_start(&authority)
    }

    /// STOP the GO without a reset (`mt7921_stop_ap`, peer `sta_remove`,
    /// `mt792x_remove_interface`): drain the FIFO, delete every peer
    /// STA_REC/WTBL, BSS abort, BSS (with its beacon) and DEV_INFO disable.
    /// The software CCMP keys of its peers retire with them. The GO role
    /// returns to `RadioReady`; a failure leaves it `Failed`.
    pub(super) async fn stop_go(&mut self) -> Result<(), Error> {
        let mut role = self.enter_go()?;
        let (plan, info) = match (&role.state, role.ap_owner.as_ref()) {
            (State::RadioReady(_), None) => return Ok(()),
            (State::AccessPoint { .. }, Some(owner)) => (owner.plan.clone(), owner.info),
            _ => return Err(Error::Busy),
        };
        role.renew_go_receive_epoch()?;
        if let Some(owner) = role.ap_owner.as_mut() {
            owner.activated = false;
        }
        role.stage(Stage::ApStop);
        let result = async {
            role.ap_drain_packets().await?;
            let peers = role.ap_owner.as_ref().ok_or(Error::Busy)?.peers.addresses();
            for mac in peers {
                let peer = role
                    .ap_owner
                    .as_ref()
                    .and_then(|owner| owner.peers.get(mac))
                    .ok_or(Error::Bounds)?;
                let record = crate::mt7921::ap_wire::delete_peer_on(
                    plan.vif,
                    mac,
                    peer.wcid,
                    peer.config.aid,
                )?;
                role.exchange(super::station::Command::Unified { id: 3 }, &record)
                    .await?;
                if role.ap_keys.has_pair(mac) {
                    role.ap_keys
                        .remove(super::ap_crypto::Target::Pairwise(mac))
                        .map_err(|_| Error::Bounds)?;
                }
                role.ap_owner
                    .as_mut()
                    .ok_or(Error::Busy)?
                    .peers
                    .retire(mac)?;
            }
            role.notify(
                super::station::Command::Ce {
                    id: crate::mt7921::ap_wire::CE_BSS_ABORT,
                    query: false,
                },
                &crate::mt7921::vif_slots::on_bss(plan.vif, [0; 4]),
            )
            .await?;
            role.confirm_command_progress().await?;
            role.exchange(
                super::station::Command::Unified { id: 2 },
                &super::ap::role_bss(&plan, false)?,
            )
            .await?;
            let mut dev = [0; 16];
            crate::mt7921::cmd::encode_uni_dev_info_update(
                plan.vif.omac(),
                0,
                false,
                plan.own,
                &mut dev,
            )
            .ok_or(Error::Bounds)?;
            role.exchange(super::station::Command::Unified { id: 1 }, &dev)
                .await
                .map(|_| ())
        }
        .await;
        match result {
            Ok(()) => {
                role.ap_keys.clear_active();
                role.ap_owner = None;
                role.state = State::RadioReady(info);
                Ok(())
            }
            Err(error) => {
                role.state = State::Failed {
                    stage: Stage::ApStop,
                    error,
                };
                Err(error)
            }
        }
    }

    /// Run one AP control request (beacon, stations, keys, management or
    /// control-port TX) on the GO. Every failure stays in the GO role.
    pub(super) async fn go_request(
        &mut self,
        authority: Arc<ApControlAuthority>,
        request: super::boot_ap::Request,
    ) -> Result<super::boot_ap::Reply, Error> {
        if authority.mode() != 9 {
            return Err(Error::Authority);
        }
        let mut role = self.enter_go()?;
        super::boot_ap::apply_go(&mut role, authority, request).await
    }
    /// One GO data step (TX, RX, events) and its pending events.
    pub(super) fn step_go_network(
        &mut self,
        tx: Option<&[u8]>,
    ) -> Result<(super::PacketStep, alloc::vec::Vec<super::ApRxEvent>), Error> {
        let mut role = self.enter_go()?;
        let step = role.step_ap_network(tx)?;
        let mut events = alloc::vec::Vec::new();
        for _ in 0..64 {
            let Some(event) = role.pop_ap_event()? else {
                break;
            };
            events.push(event);
        }
        Ok((step, events))
    }
    /// The GO's peer addresses (`NL80211_CMD_GET_STATION` dump).
    pub(super) fn go_station_macs(&self) -> alloc::vec::Vec<[u8; 6]> {
        self.go
            .as_ref()
            .filter(|go| !go.swapped)
            .and_then(|go| go.ap.as_ref())
            .map(|owner| owner.peers.addresses())
            .unwrap_or_default()
    }
}
