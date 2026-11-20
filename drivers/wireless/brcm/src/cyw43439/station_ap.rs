// SPDX-License-Identifier: GPL-2.0-or-later
//! The primary AP owner borrows the initialized physical transport; it never
//! aliases a station BSSID, credential, key or current RF grant as an AP.
use super::*;
use crate::brcmfmac::ap_scope::Policy;

pub(crate) struct Channel {
    pub(crate) primary: u8,
    pub(crate) chanspec: u16,
    pub(crate) power_dbm: u8,
}
impl<R: Fullmac> Station<R> {
    pub(crate) fn ap_station_busy(&self) -> bool {
        self.operation
            || self.bssid.is_some()
            || self.roam.is_some()
            || self.connection.is_some()
            || self.external.is_some()
    }

    /// Primary 20 MHz channel of the live association, if any: the
    /// policy-granted channel of the current `connection` (set on
    /// association and on roam confirmation, cleared on disconnect and
    /// while a firmware roam is in progress). `None` while unassociated
    /// or mid-roam, when no STA channel constrains a new AP.
    pub(crate) fn associated_primary_channel(&self) -> Option<u8> {
        self.connection.map(|grant| grant.primary_channel())
    }
    pub(crate) fn ap_channel(&self, policy: &Policy, primary: u8) -> Result<Channel, Error> {
        // No `R::PRIMARY_AP` gate here: `prepare_in` calls this on the
        // rebound secondary station as well, whose runtime is a
        // `vif_bsscfg::Bsscfg` (`PRIMARY_AP` stays false for a bsscfg by
        // design — it is an interface-0 authority). The authority gates
        // live in the callers (`Session::prepare` requires `PRIMARY_AP`;
        // `prepare_secondary` requires a non-primary `Scope` and
        // `Scope::admits` requires `SECONDARY_AP`); the channel itself is
        // constrained by the policy, the domain and the channel list below.
        if self.operation
            || self.bssid.is_some()
            || self.roam.is_some()
            || self.connection.is_some()
            || self.external.is_some()
            || !policy.current()
            || !Arc::ptr_eq(policy.domain(), &self.domain)
            || !self.channels.contains(&primary)
        {
            return Err(Error::Authority);
        }
        let power_dbm = channel_power(&self.domain, primary).ok_or(Error::Unsupported)?;
        let chanspec = channel::encode20(primary).ok_or(Error::Unsupported)?;
        Ok(Channel {
            primary,
            chanspec,
            power_dbm,
        })
    }
    /// Only after the actual AP stop/peer/flow/current-source receipts and
    /// native configuration restoration. This erases no unknown DMA owner.
    pub(crate) fn ap_forget_station_context(&mut self) {
        self.bssid = None;
        self.connection = None;
        self.external = None;
        self.protection = None;
        self.roam = None;
        self.cache.clear();
        self.mfp_verified = false;
        self.ht_verified = false;
        self.vht_verified = false;
        self.power_save = false;
        self.reset_wmm();
    }
}
