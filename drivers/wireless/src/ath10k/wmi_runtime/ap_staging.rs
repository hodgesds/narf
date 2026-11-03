// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux early-AP group-key software staging, without installed-key claims.
use super::{ap, ap_key, Error, Hif, HostMemory, HttMemory, Radio};
use alloc::boxed::Box;
use narf_wireless::{ap_control::ApEmissionAuthority, OwnedKey};
impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) fn ap_prune_staging(&mut self) {
        if self
            .ap_staging
            .as_ref()
            .is_some_and(|staging| !staging.current())
        {
            self.ap_staging = None;
        }
    }
    pub(in crate::ath10k) fn ap_retire_staging(&mut self) {
        self.ap_staging = None;
    }
    fn ap_stage_owner(&mut self) -> Result<&mut ap::Staging, Error> {
        if !self.ap_supported()
            || self.ap_exists()
            || self.station.peer.is_some()
            || self.roc.is_some()
            || self.scan_pending.is_some()
            || self.failed
        {
            return Err(Error::Unsupported);
        }
        self.htt
            .wmi
            .htc
            .transport
            .check_current()
            .map_err(crate::ath10k::control::Error::from)
            .map_err(super::htt::Error::from)?;
        if self
            .ap_staging
            .as_ref()
            .is_some_and(|staging| !staging.current())
        {
            self.ap_staging = None;
        }
        Ok(self
            .ap_staging
            .get_or_insert_with(|| Box::new(ap::Staging::default())))
    }
    pub(in crate::ath10k) fn ap_stage_key(
        &mut self,
        key: OwnedKey,
        source: ApEmissionAuthority,
    ) -> Result<(), Error> {
        let checked = ap_key::Key::new(key.params())?;
        if checked.peer.is_some() || !source.current() {
            return Err(Error::Unsupported);
        }
        let staging = self.ap_stage_owner()?;
        if let Some(index) = staging
            .keys
            .iter()
            .position(|(old, _)| old.params().idx == key.params().idx)
        {
            if staging.keys[index].0.params() == key.params() {
                return Ok(());
            }
            staging.keys[index] = (key, source);
        } else {
            if staging.keys.len() == 4 {
                return Err(Error::Unsupported);
            }
            staging.keys.try_reserve(1).map_err(|_| Error::NoMemory)?;
            staging.keys.push((key, source));
        }
        Ok(())
    }
    pub(in crate::ath10k) fn ap_stage_default(
        &mut self,
        index: u8,
        flags: (bool, bool, bool, bool),
        source: ApEmissionAuthority,
    ) -> Result<(), Error> {
        if flags != (false, true, false, false) || !source.current() {
            return Err(Error::Unsupported);
        }
        let staging = self.ap_stage_owner()?;
        if !staging
            .keys
            .iter()
            .any(|(key, _)| key.params().idx == index)
        {
            return Err(Error::Unsupported);
        }
        staging.default = Some((index, source));
        Ok(())
    }
    pub(in crate::ath10k) fn ap_stage_delete(
        &mut self,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), Error> {
        if index > 3 || pairwise || peer.is_some() {
            return Err(Error::Unsupported);
        }
        let staging = self.ap_stage_owner()?;
        let index_in_list = staging
            .keys
            .iter()
            .position(|(key, _)| key.params().idx == index)
            .ok_or(Error::Unsupported)?;
        staging.keys.remove(index_in_list);
        if staging
            .default
            .as_ref()
            .is_some_and(|(old, _)| *old == index)
        {
            staging.default = None;
        }
        Ok(())
    }
}
