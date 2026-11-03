// SPDX-License-Identifier: GPL-2.0-or-later
//! SDPCM firmware-SME AP transport ownership. Native PIO copy and firmware
//! MAC/SCB/crypto authority remain distinct; this supplies no air ACK.
use super::*;
use crate::brcmfmac::{ap_scope::Capture, ap_tx::Ticket};

pub(super) struct Owner {
    original: Capture,
    next: u32,
}
impl Owner {
    fn admits(&self, original: &Capture) -> Result<(), Error> {
        if !self.original.same_role(original) {
            return Err(Error::Authority);
        }
        self.original.role_current().map_err(|_| Error::Authority)?;
        original.current().map_err(|_| Error::Authority)
    }
}
impl<T: PacketTransport> Runtime<T> {
    pub(crate) async fn command_ap(
        &mut self,
        original: &Capture,
        direction: ioctl::Direction,
        command: u32,
        input: &[u8],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        if !original.lifecycle() || !original.belongs_to(&self.ap_live) {
            return Err(Error::Authority);
        }
        original.current().map_err(|_| Error::Authority)?;
        self.command_scoped(direction, command, input, maximum, Some(original))
            .await
    }
    pub(crate) fn ap_enter(&mut self, original: Capture) -> Result<(), Error> {
        if self.failed
            || self.stopped
            || self.ap.is_some()
            || self.pending.is_some()
            || !self.events.is_empty()
            || !self.data.is_empty()
        {
            return Err(Error::Busy);
        }
        if !original.lifecycle() || !original.belongs_to(&self.ap_live) {
            return Err(Error::Authority);
        }
        original.current().map_err(|_| Error::Authority)?;
        if !self.ap_completed_prefix()? {
            return Err(Error::Busy);
        }
        original.current().map_err(|_| Error::Authority)?;
        self.ap = Some(alloc::boxed::Box::new(Owner { original, next: 1 }));
        Ok(())
    }
    pub(crate) fn ap_completed_prefix(&mut self) -> Result<bool, Error> {
        if self.failed || self.stopped {
            return Err(Error::Failed);
        }
        if self.pending.is_some() || !self.events.is_empty() || !self.data.is_empty() {
            return Ok(false);
        }
        self.transport
            .as_mut()
            .ok_or(Error::Failed)?
            .completed_prefix()
            .map_err(Into::into)
    }
    pub(crate) fn ap_quiet(&mut self) -> Result<bool, Error> {
        // Every accepted PIO borrow completed synchronously; this is only
        // host transport quiet. It never asserts firmware MAC/RX-key quiet.
        self.ap_completed_prefix()
    }
    pub(crate) fn ap_retire_peer(&mut self, peer: [u8; 6]) -> Result<bool, Error> {
        if self.ap.is_none() || peer == [0; 6] || peer[0] & 1 != 0 {
            return Err(Error::Unsupported);
        }
        // No host flow ring or retained TX ID exists on synchronous SDPCM.
        // Session separately requires actual native SCB absence/epochs.
        self.ap_completed_prefix()
    }
    pub(crate) fn ap_leave(&mut self) -> Result<bool, Error> {
        if self.ap.is_none() {
            return Ok(true);
        }
        if !self.ap_completed_prefix()? {
            return Ok(false);
        }
        self.ap = None;
        Ok(true)
    }
    pub(crate) fn ap_send(
        &mut self,
        bytes: &[u8],
        priority: u8,
        original: &Capture,
    ) -> Result<Ticket, Error> {
        if self.failed || self.stopped {
            return Err(Error::Failed);
        }
        if !original.transmit(bytes) || !original.belongs_to(&self.ap_live) {
            return Err(Error::Authority);
        }
        self.ap
            .as_ref()
            .ok_or(Error::Unsupported)?
            .admits(original)?;
        // Retain original before consuming any physical prefix. Session must
        // process actual queued peer/key/loss/control data before retry; no
        // transport method silently discards it or captures a fresh target.
        let mut idle = false;
        for _ in 0..4 {
            if !self.events.is_empty() || !self.data.is_empty() {
                return Err(Error::Busy);
            }
            let count = self.poll()?;
            if !self.events.is_empty() || !self.data.is_empty() {
                return Err(Error::Busy);
            }
            if count == 0 && self.ap_completed_prefix()? {
                idle = true;
                break;
            }
        }
        if !idle {
            return Err(Error::Busy);
        }
        self.ap.as_ref().ok_or(Error::Failed)?.admits(original)?;
        let id = self.ap.as_ref().ok_or(Error::Failed)?.next;
        let next = id
            .checked_add(1)
            .filter(|value| *value < u32::MAX)
            .ok_or(Error::Failed)?;
        self.send_data_inner(bytes, priority, Some(original))?;
        self.ap.as_mut().ok_or(Error::Failed)?.next = next;
        // Only the actual fully copied PIO packet yields this terminal. It
        // releases the host byte borrow; no air ACK/MAC/FIFO claim follows.
        Ok(Ticket::pio_copied(id, original.clone()))
    }
}
