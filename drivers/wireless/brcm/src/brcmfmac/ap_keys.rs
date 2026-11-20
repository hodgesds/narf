// SPDX-License-Identifier: GPL-2.0-or-later
//! Native CCMP transactions. PRIMARY ADD supplies the native GTK transmit
//! selection; Linux's SET_DEFAULT_KEY is a WEP-only command, not a CCMP
//! selector. Software default metadata cannot select an older native GTK.
use super::{
    ap::Session,
    ap_key::{self, Installed},
    ap_native::{self, Guard, Phase},
};
use crate::cyw43439::{fullmac::Fullmac, runtime::Error, station::Station};
use narf_wireless::{ap_control::ApEmissionAuthority, KeyParams};

impl Session {
    async fn key_quiet<R: Fullmac>(&mut self, station: &mut Station<R>) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            // busy=true already denies newly consumed Ethernet copies.
            // Existing TX IDs still require their actual native terminals.
            let idle = self.prefix(&mut station.runtime)?;
            if idle && station.runtime.ap_quiet()? && self.prefix(&mut station.runtime)? {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    }

    pub(crate) async fn add_key<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
        key: &KeyParams,
        source: ApEmissionAuthority,
    ) -> Result<(), Error> {
        ap_key::validate(key)?;
        self.current()?;
        if !self.plan.config.privacy || self.phase != Phase::Formed {
            return Err(Error::Unsupported);
        }
        let peer = if key.pairwise {
            Some(
                self.peers
                    .iter()
                    .position(|peer| Some(peer.mac) == key.peer && peer.associated && !peer.removed)
                    .ok_or(Error::Firmware((-30i32) as u32))?,
            )
        } else {
            None
        };
        let old = peer.map_or_else(
            || self.group.iter().find(|old| old.index == key.idx),
            |index| self.peers[index].key.as_ref(),
        );
        if old.is_some_and(|old| old.same_retry(key)) {
            // Validate the new caller too, but retain the original install
            // actor/receipt. An identical retry never rewrites PN/RSC.
            self.command_capture(source, peer.map(|index| &self.peers[index]))?;
            return Ok(());
        }
        let original = self.command_capture(source, peer.map(|index| &self.peers[index]))?;
        let operation = self.operation()?;
        self.group_data.advance().map_err(|_| Error::Failed)?;
        if let Some(index) = peer {
            self.peers[index]
                .data
                .advance()
                .map_err(|_| Error::Failed)?;
            self.peers[index]
                .key_epoch
                .advance()
                .map_err(|_| Error::Failed)?;
            self.peers[index].key = None;
        } else {
            self.selected_group = None;
            self.default_source = None;
            self.native_group = None;
            self.group.retain(|old| old.index != key.idx);
        }
        self.key_quiet(station).await?;
        original.current().map_err(|_| Error::Authority)?;
        // Remember before publication: cancellation or a missing response
        // cannot establish that firmware did not consume this material.
        self.history.lock().remember(key)?;
        let receipt = ap_native::install_key(&mut station.runtime, &original, key).await?;
        if !self.prefix(&mut station.runtime)? {
            return Err(Error::Busy);
        }
        original.current().map_err(|_| Error::Authority)?;
        let installed = Installed::from_receipt(key, receipt)?;
        if let Some(index) = peer {
            // No association/authorization is recreated here. Loss handled
            // in prefix invalidates original.peer before this publication.
            self.peers[index].key = Some(installed);
        } else {
            self.group.push(installed);
            self.native_group = Some(key.idx);
        }
        self.busy = false;
        operation.finish();
        Ok(())
    }

    pub(crate) fn default_key(
        &mut self,
        index: u8,
        _unicast: bool,
        multicast: bool,
        management: bool,
        beacon: bool,
        source: ApEmissionAuthority,
    ) -> Result<(), Error> {
        self.current()?;
        if self.busy
            || !self.plan.config.privacy
            || !multicast
            || management
            || beacon
            || self.native_group != Some(index)
            || !self
                .group
                .iter()
                .any(|key| key.index == index && key.current())
        {
            return Err(Error::Unsupported);
        }
        self.command_capture(source.clone(), None)?;
        self.group_data.advance().map_err(|_| Error::Failed)?;
        self.selected_group = Some(index);
        self.default_source = Some(source);
        Ok(())
    }

    pub(crate) async fn delete_key<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
        source: ApEmissionAuthority,
    ) -> Result<(), Error> {
        if pairwise {
            if index != 0 || peer.is_none() {
                return Err(Error::Unsupported);
            }
            // Linux has no peer-selective OFF encoding. A complete actual
            // SCB removal is the conservative pairwise delete boundary.
            return self.remove_station(station, peer, 3, source).await;
        }
        if peer.is_some() {
            return Err(Error::Unsupported);
        }
        let body = ap_key::off_group(index)?;
        if !self.group.iter().any(|key| key.index == index) {
            return Err(Error::Firmware((-30i32) as u32));
        }
        let original = self.command_capture(source, None)?;
        let operation = self.operation()?;
        self.group_data.advance().map_err(|_| Error::Failed)?;
        self.group.retain(|key| key.index != index);
        if self.selected_group == Some(index) {
            self.selected_group = None;
            self.default_source = None;
        }
        if self.native_group == Some(index) {
            self.native_group = None;
        }
        self.key_quiet(station).await?;
        ap_native::set_var(
            &mut station.runtime,
            &Guard::Program(&original),
            "wsec_key",
            &body,
        )
        .await?;
        self.prefix(&mut station.runtime)?;
        original.current().map_err(|_| Error::Authority)?;
        self.busy = false;
        operation.finish();
        Ok(())
    }
}
