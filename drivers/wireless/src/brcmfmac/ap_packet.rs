// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed original Ethernet/control owners through the completed native input
//! prefix and matching msgbuf terminal. Firmware retains CCMP/PN/replay/SCB.
use super::{
    ap::Session,
    ap_scope::{Capture, Use},
    ap_tx::Ticket,
};
use crate::cyw43439::{fullmac::Fullmac, runtime::Error, station::Station};
use alloc::vec::Vec;
use narf_wireless::{ap_control::ApEmissionAuthority, ControlPortTxRequest};

impl Session {
    pub(crate) fn data_capture(&self, bytes: &[u8]) -> Result<Capture, Error> {
        self.current()?;
        if !self.active() || self.busy || !(14..=1514).contains(&bytes.len()) {
            return Err(Error::Busy);
        }
        let target: [u8; 6] = bytes[..6].try_into().unwrap();
        let mut original;
        if target[0] & 1 == 0 {
            let peer = self
                .peers
                .iter()
                .find(|peer| peer.mac == target)
                .ok_or(Error::Unsupported)?;
            if !peer.data_current(self.plan.config.privacy) {
                return Err(Error::Authority);
            }
            original = self.capture(Use::Data, Some(target), Some(peer));
            original
                .sources
                .push(peer.authorization.clone().ok_or(Error::Authority)?);
            if let Some(key) = &peer.key {
                original.sources.push(key.source.clone());
                original.key = Some(key.epoch.capture());
            }
        } else {
            // The firmware's per-SCB ports remain authoritative. This
            // bounded host owner also refuses group DATA until every known
            // associated peer has a current port (and PTK for a secure BSS).
            let mut peers = self
                .peers
                .iter()
                .filter(|peer| peer.associated && !peer.removed)
                .peekable();
            if peers.peek().is_none() {
                return Err(Error::Authority);
            }
            original = self.capture(Use::Data, Some(target), None);
            original.data = Some(self.group_data.capture());
            for peer in peers {
                if !peer.data_current(self.plan.config.privacy) {
                    return Err(Error::Authority);
                }
                original
                    .sources
                    .push(peer.authorization.clone().ok_or(Error::Authority)?);
                if let Some(key) = &peer.key {
                    original.sources.push(key.source.clone());
                }
            }
            if self.plan.config.privacy {
                let key = self
                    .group
                    .iter()
                    .find(|key| {
                        Some(key.index) == self.selected_group
                            && Some(key.index) == self.native_group
                            && key.current()
                    })
                    .ok_or(Error::Authority)?;
                original.key = Some(key.epoch.capture());
                original.sources.push(key.source.clone());
                original
                    .sources
                    .push(self.default_source.clone().ok_or(Error::Authority)?);
            }
        }
        if !original.transmit(bytes) {
            return Err(Error::Malformed);
        }
        original.current().map_err(|_| Error::Authority)?;
        Ok(original)
    }

    /// Caller retains original across Busy and never recaptures a successor
    /// peer/key for the same queued frame after the actual prefix is applied.
    pub(crate) fn begin_data<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
        bytes: &[u8],
        original: &Capture,
    ) -> Result<Ticket, Error> {
        if self.busy
            || !self.active()
            || !self.base.same_role(original)
            || !original.transmit(bytes)
        {
            return Err(Error::Authority);
        }
        original.current().map_err(|_| Error::Authority)?;
        if !self.prefix(&mut station.runtime)? {
            return Err(Error::Busy);
        }
        original.current().map_err(|_| Error::Authority)?;
        station
            .runtime
            .ap_send(bytes, crate::ath11k::tx_hdr::classify8021d(bytes), original)
    }

    pub(crate) async fn control<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
        request: &ControlPortTxRequest,
        source: ApEmissionAuthority,
    ) -> Result<bool, Error> {
        if !self.active()
            || !self.plan.settings.control_port.over_nl80211
            || !matches!(request.ethertype, 0x888e | 0x88c7)
            || !(4..=1500).contains(&request.pdu().len())
            || request.wait_for_ack
        {
            return Err(Error::Unsupported);
        }
        let peer = self
            .peers
            .iter()
            .find(|peer| peer.mac == request.dest && peer.associated && !peer.removed)
            .ok_or(Error::Unsupported)?;
        if request.no_encrypt && peer.key.is_some()
            || request.ethertype == 0x88c7 && !peer.data_current(self.plan.config.privacy)
        {
            return Err(Error::Unsupported);
        }
        let mut original = self.capture(Use::Control, Some(peer.mac), Some(peer));
        original.sources.push(source);
        if request.ethertype == 0x88c7 {
            original
                .sources
                .push(peer.authorization.clone().ok_or(Error::Authority)?);
        }
        if let Some(key) = &peer.key {
            if !key.current() {
                return Err(Error::Authority);
            }
            original.key = Some(key.epoch.capture());
            original.sources.push(key.source.clone());
        }
        let mut bytes = Vec::with_capacity(14 + request.pdu().len());
        bytes.extend_from_slice(&request.dest);
        bytes.extend_from_slice(&self.plan.own);
        bytes.extend_from_slice(&request.ethertype.to_be_bytes());
        bytes.extend_from_slice(request.pdu());
        original.current().map_err(|_| Error::Authority)?;
        let operation = self.operation()?;
        let deadline = narf_time::Deadline::after_ms(2000);
        let ticket = loop {
            original.current().map_err(|_| Error::Authority)?;
            if self.prefix(&mut station.runtime)? {
                match station.runtime.ap_send(&bytes, 0, &original) {
                    Ok(ticket) => break ticket,
                    Err(Error::Busy) => {}
                    Err(error) => return Err(error),
                }
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        };
        loop {
            self.prefix(&mut station.runtime)?;
            if ticket.terminal().map_err(|_| Error::Failed)? {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
        original.current().map_err(|_| Error::Authority)?;
        self.busy = false;
        operation.finish();
        // Matching TX_STATUS proves terminal DMA retirement, not an
        // independently source-backed over-air ACK. Status is unadvertised.
        Ok(false)
    }
}
