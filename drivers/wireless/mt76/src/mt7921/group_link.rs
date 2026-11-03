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
    pub(super) fn other_owns_wcid(&self, wcid: u16) -> bool {
        self.group.as_ref().is_some_and(|other| {
            matches!(other.state, State::Associated { .. })
                && u16::from(other.station.link.peer()) == wcid
        })
    }
    /// Queue an original RX copy for the other station owner; its own
    /// `receive_ethernet` drains it before the shared ring.
    pub(super) fn forward_to_other(&mut self, packet: super::CapturedData) {
        if let Some(other) = self.group.as_mut() {
            if other.station.demuxed.len() >= DEMUX_DEPTH {
                other.station.demuxed.pop_front();
            }
            other.station.demuxed.push_back(packet);
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
