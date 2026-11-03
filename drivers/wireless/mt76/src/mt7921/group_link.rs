//! The concurrent P2P group vif's station owner. Linux mt7921 keeps one
//! `mt792x_vif` (BSS/OMAC/WMM from `mt7921_add_interface`) and one
//! `mt792x_sta` (peer WCID from `mt76_wcid_alloc`) per vif; NARF opens the
//! same identity as a second `StationLink` next to the home link.
//!
//! This module only allocates and retires that identity. It sends no native
//! command: the group vif's DEV_INFO/BSS records, association and RX demux
//! belong to the NEW_INTERFACE path. Any verified reset retires it with the
//! home link (`retire_group_link`).
use super::{Backend, Error, Session, StationLink};
use crate::mt7921::vif_slots::{Link, Vif};

impl<B: Backend> Session<B> {
    /// Open the group vif `vif`'s station owner: the lowest free peer WCID
    /// not owned by the home link, another station link or the AP peer
    /// table. One group link at a time (Linux `if_comb_chanctx_base`:
    /// two STATION|P2P_CLIENT interfaces).
    pub(super) fn open_group_link(&mut self, vif: Vif) -> Result<Link, Error> {
        if vif == Vif::HOME || vif == self.station.link.vif() {
            return Err(Error::Bounds);
        }
        if self.group.is_some() {
            return Err(Error::Busy);
        }
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
        self.group = Some(StationLink::new(link));
        Ok(link)
    }
    pub(super) fn group_link(&self) -> Option<Link> {
        self.group.as_ref().map(|group| group.link)
    }
    /// Close an idle group owner: no BSS, key, permission or queued TX.
    /// An associated group link must leave first.
    pub(super) fn close_group_link(&mut self, link: Link) -> Result<(), Error> {
        let group = self.group.as_ref().ok_or(Error::Bounds)?;
        if group.link != link {
            return Err(Error::Bounds);
        }
        if group.bss.is_some()
            || group.security.is_some()
            || group.permission.is_some()
            || !group.tx_fragments.is_empty()
            || !group.control_pending.is_empty()
        {
            return Err(Error::Busy);
        }
        self.retire_group_link();
        Ok(())
    }
    /// True while the group owner holds an association (BSS or key).
    pub(super) fn group_associated(&self) -> bool {
        self.group
            .as_ref()
            .is_some_and(|group| group.bss.is_some() || group.security.is_some())
    }
    /// Retire the group owner after a verified MAC/firmware reset or once
    /// it is idle: its WCID returns to the shared map.
    pub(super) fn retire_group_link(&mut self) {
        if let Some(group) = self.group.take() {
            self.wtbl.free(group.link.peer());
        }
    }
}
