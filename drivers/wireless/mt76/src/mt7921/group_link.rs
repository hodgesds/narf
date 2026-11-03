//! The concurrent P2P group vif's station owner. Linux mt7921 keeps one
//! `mt792x_vif` (BSS/OMAC/WMM from `mt7921_add_interface`) and one
//! `mt792x_sta` (peer WCID from `mt76_wcid_alloc`) per vif; NARF opens the
//! same identity as a second `StationLink` with its own role `State` next to
//! the home link.
//!
//! A group operation runs the unchanged station owner code on the group
//! link: `enter_group` swaps the group's `StationLink` and `State` into the
//! session's station slots for the operation's lifetime and its guard swaps
//! them back on completion or cancellation (drop). Every native record the
//! station code builds is keyed by `self.station.link` (bss_idx, OMAC, WMM,
//! peer/BMC WCID), so the home link's records stay byte-identical. The
//! shared RX capture epoch, TX completion pipeline and channel/power grant
//! stay device-wide: both owners share one channel context (single-channel
//! concurrency, `shares_channel_context`). Any verified reset retires the
//! group owner with the home link (`retire_group_link`).
use super::{Backend, Error, GroupOwner, Session, State, StationLink};
use crate::mt7921::association::{Security, TxPermission};
use crate::mt7921::p2p_wire::Network;
use crate::mt7921::vif_slots::{Link, Vif};
use core::ops::{Deref, DerefMut};

/// Captured packets one link may hold for its owner before the oldest drop.
const DEMUX_DEPTH: usize = 64;

/// One device-wide data/management TX FIFO (`data_pending`) whose entries
/// carry their owner: `Some(link)` for a station owner's frame, `None` for
/// a non-station owner (AP, P2P device). The native token pipeline retires
/// in submission order, so the front entry owns the next completion.
#[derive(Debug, Default)]
pub(super) struct DataPending {
    entries: alloc::collections::VecDeque<(u64, Option<Link>)>,
}
impl DataPending {
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }
    /// The oldest entry's submission time.
    pub(super) fn front(&self) -> Option<&u64> {
        self.entries.front().map(|(started, _)| started)
    }
    pub(super) fn pop_front(&mut self) -> Option<u64> {
        self.entries.pop_front().map(|(started, _)| started)
    }
    pub(super) fn pop_owner(&mut self) -> Option<Option<Link>> {
        self.entries.pop_front().map(|(_, owner)| owner)
    }
    /// A non-station owner's entry.
    pub(super) fn push_back(&mut self, started: u64) {
        self.entries.push_back((started, None));
    }
    /// A station owner's entry.
    pub(super) fn push_owned(&mut self, started: u64, link: Link) {
        self.entries.push_back((started, Some(link)));
    }
    /// The oldest entry `link` waits on (its own or a non-station one).
    pub(super) fn oldest_for(&self, link: Link) -> Option<u64> {
        self.entries
            .iter()
            .find(|(_, owner)| owner.is_none_or(|owner| owner == link))
            .map(|(started, _)| *started)
    }
    /// Entries a station owner still owns.
    pub(super) fn owned_by(&self, link: Link) -> usize {
        self.entries
            .iter()
            .filter(|(_, owner)| *owner == Some(link))
            .count()
    }
}

/// Whether a decoded RX copy belongs to the other associated station
/// owner: its peer WCID (`mt792x_rx_get_wcid`), or, for a copy without
/// this owner's WCID, a transmitter equal to the other owner's BSSID (a
/// group-addressed or WTBL-miss copy of that BSS) when that BSS is not
/// also this owner's.
fn owns_rx(
    other: &GroupOwner,
    (own_wcid, own_bssid): (u16, Option<[u8; 6]>),
    native: &super::scan::NativeRx<'_>,
) -> bool {
    if !matches!(other.state, State::Associated { .. }) {
        return false;
    }
    if native.wcid == u16::from(other.station.link.peer()) {
        return true;
    }
    native.wcid != own_wcid
        && other.station.bss.as_ref().is_some_and(|bss| {
            Some(bss.bssid) != own_bssid && native.frame.get(10..16) == Some(&bss.bssid[..])
        })
}
fn push_demuxed(other: &mut GroupOwner, packet: super::CapturedData) {
    if other.station.demuxed.len() >= DEMUX_DEPTH {
        other.station.demuxed.pop_front();
    }
    other.station.demuxed.push_back(packet);
}

/// The session with the group link swapped into its station owner. Dropping
/// it (normal return or a cancelled borrowed future) restores the home
/// owner, so the home role can never be left behind a group operation.
pub(super) struct GroupRole<'a, B: Backend> {
    session: &'a mut Session<B>,
}
impl<B: Backend> Deref for GroupRole<'_, B> {
    type Target = Session<B>;
    fn deref(&self) -> &Session<B> {
        self.session
    }
}
impl<B: Backend> DerefMut for GroupRole<'_, B> {
    fn deref_mut(&mut self) -> &mut Session<B> {
        self.session
    }
}
impl<B: Backend> Drop for GroupRole<'_, B> {
    fn drop(&mut self) {
        self.session.swap_group();
    }
}

impl<B: Backend> Session<B> {
    fn swap_group(&mut self) {
        if let Some(group) = self.group.as_mut() {
            core::mem::swap(&mut self.station, &mut group.station);
            core::mem::swap(&mut self.state, &mut group.state);
        }
    }
    /// True while a group operation holds the station slots.
    pub(super) fn group_role(&self) -> bool {
        self.station.link != Link::HOME
    }
    /// Run the station owner on the group link `link`.
    pub(super) fn enter_group(&mut self, link: Link) -> Result<GroupRole<'_, B>, Error> {
        if self.group_role() || self.group_link() != Some(link) {
            return Err(Error::Bounds);
        }
        // A cancelled home operation leaves `Running`/`Failed`; only a
        // settled home station role can share the radio.
        if !matches!(
            self.state,
            State::RadioReady(_) | State::ScanReady(_) | State::Associated { .. }
        ) {
            return Err(Error::Busy);
        }
        self.swap_group();
        Ok(GroupRole { session: self })
    }

    /// Open the group vif `vif`'s station owner with own address `own`: the
    /// lowest free peer WCID not owned by the home link, another station
    /// link or the AP peer table. One group link at a time (Linux
    /// `if_comb_chanctx_base`: two STATION|P2P_CLIENT interfaces). No native
    /// command is sent; the group role starts `RadioReady`.
    pub(super) fn open_group_link(&mut self, vif: Vif, own: [u8; 6]) -> Result<Link, Error> {
        if vif == Vif::HOME || vif == self.station.link.vif() || self.group_role() {
            return Err(Error::Bounds);
        }
        if own == [0; 6] || own[0] & 1 != 0 {
            return Err(Error::Bounds);
        }
        if self.group.is_some() {
            return Err(Error::Busy);
        }
        let mut info = match self.state {
            State::RadioReady(info) | State::ScanReady(info) | State::Associated { info, .. } => {
                info
            }
            _ => return Err(Error::Busy),
        };
        info.capabilities.mac = own;
        let foreign = self
            .ap_owner
            .as_ref()
            .map_or(0, |owner| owner.peers.reserved());
        let peer = self.wtbl.alloc(foreign)?;
        let link = match Link::new(vif, peer) {
            Ok(link) => link,
            Err(error) => {
                self.wtbl.free(peer);
                return Err(error);
            }
        };
        self.group = Some(GroupOwner {
            station: StationLink::new(link),
            state: State::RadioReady(info),
        });
        Ok(link)
    }
    pub(super) fn group_link(&self) -> Option<Link> {
        if self.group_role() {
            return Some(self.station.link);
        }
        self.group.as_ref().map(|group| group.station.link)
    }
    /// The group role's state (`None` without a group owner).
    pub(super) fn group_state(&self) -> Option<State> {
        if self.group_role() {
            return Some(self.state);
        }
        self.group.as_ref().map(|group| group.state)
    }
    /// Publish the group vif (Linux `mt7921_add_interface` ->
    /// `mt76_connac_mcu_uni_add_dev(enable = true)`: DEV_INFO then BSS on
    /// the vif's OMAC/WMM with its BMC WCID, INFRA_STA for a station or
    /// P2P_CLIENT vif). The group role becomes `ScanReady`.
    pub(super) async fn start_group_link(&mut self, vif: Vif, own: [u8; 6]) -> Result<Link, Error> {
        let link = self.open_group_link(vif, own)?;
        let result = async {
            let dev = super::scan::station_device_record_on(vif, own, true)?;
            self.exchange(super::station::Command::Unified { id: 1 }, &dev)
                .await?;
            let bss = super::scan::station_bss_record_on(vif, true);
            self.exchange(super::station::Command::Unified { id: 2 }, &bss)
                .await?;
            Ok(())
        }
        .await;
        let group = self.group.as_mut().ok_or(Error::Bounds)?;
        let State::RadioReady(info) = group.state else {
            return Err(Error::Busy);
        };
        group.state = match result {
            Ok(()) => State::ScanReady(info),
            Err(error) => State::Failed {
                stage: super::Stage::ScanSetup,
                error,
            },
        };
        result.map(|()| link)
    }
    /// Retire an idle published group vif (Linux `mt792x_remove_interface`
    /// -> `uni_add_dev(enable = false)`: BSS then DEV_INFO) and free its
    /// WCID. An associated group link must leave first; a failed one is
    /// retired only by verified recovery.
    pub(super) async fn stop_group_link(&mut self, link: Link) -> Result<(), Error> {
        if self.group_role() {
            return Err(Error::Bounds);
        }
        let group = self.group.as_ref().ok_or(Error::Bounds)?;
        if group.station.link != link {
            return Err(Error::Bounds);
        }
        let info = match group.state {
            State::RadioReady(_) => return self.close_group_link(link),
            State::ScanReady(info) => info,
            _ => return Err(Error::Busy),
        };
        let vif = link.vif();
        let result = async {
            let bss = super::scan::station_bss_record_on(vif, false);
            self.exchange(super::station::Command::Unified { id: 2 }, &bss)
                .await?;
            let dev = super::scan::station_device_record_on(vif, info.capabilities.mac, false)?;
            self.exchange(super::station::Command::Unified { id: 1 }, &dev)
                .await?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                self.retire_group_link();
                Ok(())
            }
            Err(error) => {
                if let Some(group) = self.group.as_mut() {
                    group.state = State::Failed {
                        stage: super::Stage::Shutdown,
                        error,
                    };
                }
                Err(error)
            }
        }
    }
    /// Close an unpublished idle group owner: no native DEV/BSS, BSS, key,
    /// permission or queued TX.
    pub(super) fn close_group_link(&mut self, link: Link) -> Result<(), Error> {
        if self.group_role() {
            return Err(Error::Bounds);
        }
        let group = self.group.as_ref().ok_or(Error::Bounds)?;
        if group.station.link != link {
            return Err(Error::Bounds);
        }
        let station = &group.station;
        if !matches!(group.state, State::RadioReady(_))
            || station.bss.is_some()
            || station.security.is_some()
            || station.permission.is_some()
            || !station.tx_fragments.is_empty()
            || !station.control_pending.is_empty()
            || !station.tx_credit.is_empty()
            || self.data_pending.owned_by(link) != 0
        {
            return Err(Error::Busy);
        }
        self.retire_group_link();
        Ok(())
    }
    /// True while the group owner holds native state: a published vif, an
    /// association (BSS or key) or a failed role awaiting recovery.
    pub(super) fn group_published(&self) -> bool {
        self.group.as_ref().is_some_and(|group| {
            !matches!(group.state, State::RadioReady(_))
                || group.station.bss.is_some()
                || group.station.security.is_some()
        })
    }
    /// Retire the group owner after a verified MAC/firmware reset or once
    /// it is idle: its WCID returns to the shared map. Recovery never runs
    /// inside a group operation (the guard restores the home owner first).
    pub(super) fn retire_group_link(&mut self) {
        if self.group_role() {
            return;
        }
        if let Some(group) = self.group.take() {
            self.wtbl.free(group.station.link.peer());
        }
    }

    /// The other (swapped-out) live station owner's channel grant.
    pub(super) fn other_station_permission(&self) -> Option<TxPermission> {
        self.group
            .as_ref()
            .filter(|other| matches!(other.state, State::Associated { .. } | State::Running(_)))
            .and_then(|other| other.station.permission)
    }
    /// One shared channel context: a join next to a live station owner
    /// must request that owner's exact grant (channel, width, power and
    /// regulatory domain), mac80211 `ieee80211_find_chanctx` reuse with an
    /// identical chandef. 6 GHz stays home-only: its CLC power type
    /// (`mt7921_regd_set_6ghz_power_type`) is device-wide.
    pub(super) fn shares_channel_context(&self, permission: TxPermission) -> bool {
        if self.group_role() && permission.six.is_some() {
            return false;
        }
        self.other_station_permission()
            .is_none_or(|live| live == permission)
    }
    /// Whether a decoded copy belongs to the other (swapped-out) station
    /// owner (`owns_rx`).
    pub(super) fn other_owns_rx(&self, native: &super::scan::NativeRx<'_>) -> bool {
        let own = self.own_rx_identity();
        self.group
            .as_ref()
            .is_some_and(|other| owns_rx(other, own, native))
    }
    fn own_rx_identity(&self) -> (u16, Option<[u8; 6]>) {
        (
            u16::from(self.station.link.peer()),
            self.station.bss.as_ref().map(|bss| bss.bssid),
        )
    }
    /// Queue an original RX copy for the other station owner; its own
    /// `receive_ethernet` drains it before the shared ring.
    pub(super) fn forward_to_other(&mut self, packet: super::CapturedData) {
        if let Some(other) = self.group.as_mut() {
            push_demuxed(other, packet);
        }
    }

    /// A station wait over the shared raw RX ring (auth/SAE/assoc/EAPOL):
    /// every drained copy the other station owner owns goes to that
    /// owner's demux queue (Linux `mt76_rx` -> `mt792x_rx_get_wcid` keeps
    /// delivering every vif while one vif's MLME waits); `f` sees only the
    /// remaining copies, at most 16 per poll. Without a group owner this is
    /// the former `wait` over `receive_data`.
    pub(super) async fn wait_station_rx<T>(
        &mut self,
        ms: u64,
        mut f: impl FnMut(&mut B, &[u8]) -> Result<Option<T>, Error>,
    ) -> Result<T, Error> {
        let own = self.own_rx_identity();
        self.wait_split(ms, |backend, other| {
            for _ in 0..16 {
                let Some(packet) = backend.receive_data_captured()? else {
                    break;
                };
                if let Some(other) = other.as_mut() {
                    if super::scan::rx_native_with_amsdu(&packet.bytes)
                        .is_some_and(|native| owns_rx(other, own, &native))
                    {
                        push_demuxed(other, packet);
                        continue;
                    }
                }
                if let Some(value) = f(backend, &packet.bytes)? {
                    return Ok(Some(value));
                }
            }
            Ok(None)
        })
        .await
    }

    /// Whether a copy captured under `epoch` can belong to `station`: not
    /// before that owner's own last fence, not after the current stamp.
    /// With one owner the floor is always the current epoch (every renewal
    /// moves it), i.e. the former `epoch == receive_epoch`.
    pub(super) fn epoch_admits(&self, station: &StationLink, epoch: u64) -> bool {
        epoch != 0 && epoch >= station.epoch && epoch <= self.receive_epoch
    }

    /// Retire the front `data_pending` entry for `completion` (the native
    /// token FIFO completes in submission order). An entry of the other
    /// station owner is credited to that owner and `None` returned, so one
    /// owner's waits never consume the other's completion; an entry of a
    /// retired owner is discarded. This owner's (or a non-station owner's)
    /// entry returns the completion.
    pub(super) fn retire_data(
        &mut self,
        completion: crate::mt7921::packet_tx::Completion,
    ) -> Option<crate::mt7921::packet_tx::Completion> {
        match self.data_pending.pop_owner() {
            Some(Some(link)) if link != self.station.link => {
                if let Some(other) = self
                    .group
                    .as_mut()
                    .filter(|other| other.station.link == link)
                {
                    if other.station.tx_credit.len() < crate::mt7921::packet_tx::PIPELINE {
                        other.station.tx_credit.push_back(completion.status);
                    }
                }
                None
            }
            _ => Some(completion),
        }
    }

    /// Associate the group link as a P2P client (or a second station when
    /// `network` is infrastructure) through the station owner's join.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn associate_group(
        &mut self,
        link: Link,
        bss: &super::ScanBss,
        ssid: &[u8],
        security: Security,
        permission: TxPermission,
        extra_ies: &[u8],
        network: Network,
    ) -> Result<u16, Error> {
        let result = {
            let mut role = self.enter_group(link)?;
            role.associate_station_as(bss, ssid, security, permission, extra_ies, network)
                .await
        };
        // The join renewed the shared capture epoch; reopen it for the home.
        let capture = self.sync_receive_capture();
        let aid = result?;
        capture?;
        Ok(aid)
    }
    /// Leave the group link's association (deauth, key/WCID/BSS retirement
    /// on the group vif); the group role returns to `ScanReady`.
    pub(super) async fn disassociate_group(&mut self, link: Link) -> Result<(), Error> {
        let result = {
            let mut role = self.enter_group(link)?;
            role.disassociate_station().await
        };
        let capture = self.sync_receive_capture();
        result?;
        capture.map(|_| ())
    }
    /// One data/key service step on the group link (TX, rekey, RX).
    pub(super) fn step_group_network(
        &mut self,
        link: Link,
        tx: Option<&[u8]>,
    ) -> Result<super::PacketStep, Error> {
        let mut role = self.enter_group(link)?;
        role.step_network(tx)
    }
}
