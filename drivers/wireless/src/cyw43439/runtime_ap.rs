// SPDX-License-Identifier: GPL-2.0-or-later
//! SDPCM firmware-SME AP transport ownership. Native PIO copy and firmware
//! MAC/SCB/crypto authority remain distinct; this supplies no air ACK.
use super::*;
use crate::brcmfmac::{ap_scope::Capture, ap_tx::Ticket};

pub(super) struct Owner {
    /// Firmware interface this firmware-SME AP owns (BDC `flags2`).
    ifidx: u8,
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
    fn ap_owner(&self, ifidx: u8) -> Option<&Owner> {
        if ifidx == 0 {
            self.ap.as_deref()
        } else {
            self.vif_ap.iter().find(|owner| owner.ifidx == ifidx)
        }
    }
    fn ap_owner_mut(&mut self, ifidx: u8) -> Option<&mut Owner> {
        if ifidx == 0 {
            self.ap.as_deref_mut()
        } else {
            self.vif_ap.iter_mut().find(|owner| owner.ifidx == ifidx)
        }
    }
    /// The AP interface owns an ifidx whose secondary data is queued.
    pub(crate) fn ap_owns_if(&self, ifidx: u8) -> bool {
        self.ap_owner(ifidx).is_some()
    }
    /// Native input of `ifidx` the AP owner has not consumed yet: the
    /// primary queues for interface 0, the demux records of a secondary.
    fn ap_input_pending(&self, ifidx: u8) -> bool {
        if ifidx == 0 {
            !self.events.is_empty() || !self.data.is_empty()
        } else {
            self.vif.has_events_for(ifidx) || self.vif.has_data_for(ifidx)
        }
    }
    pub(crate) async fn command_ap(
        &mut self,
        original: &Capture,
        direction: ioctl::Direction,
        command: u32,
        input: &[u8],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        self.command_ap_if(0, original, direction, command, input, maximum)
            .await
    }
    /// `brcmf_cfg80211_start_ap` dcmds on `ifp->ifidx` (BCDC
    /// `BCDC_DCMD_IF_SHIFT`). A secondary ifidx must be open.
    pub(crate) async fn command_ap_if(
        &mut self,
        ifidx: u8,
        original: &Capture,
        direction: ioctl::Direction,
        command: u32,
        input: &[u8],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        if !original.lifecycle() || !original.belongs_to(&self.ap_live) {
            return Err(Error::Authority);
        }
        if ifidx != 0 && !self.vif.is_open(ifidx) {
            return Err(Error::Authority);
        }
        original.current().map_err(|_| Error::Authority)?;
        self.command_scoped(ifidx, direction, command, input, maximum, Some(original))
            .await
    }
    pub(crate) fn ap_enter(&mut self, original: Capture) -> Result<(), Error> {
        self.ap_enter_if(0, original)
    }
    /// One AP owner per firmware interface. A secondary AP needs only its
    /// own open ifidx free of queued records; interface 0 keeps its
    /// original whole-queue requirement.
    pub(crate) fn ap_enter_if(&mut self, ifidx: u8, original: Capture) -> Result<(), Error> {
        if self.failed
            || self.stopped
            || self.ap_owner(ifidx).is_some()
            || self.pending.is_some()
            || self.ap_input_pending(ifidx)
        {
            return Err(Error::Busy);
        }
        if ifidx != 0 && !self.vif.is_open(ifidx) {
            return Err(Error::Authority);
        }
        if !original.lifecycle() || !original.belongs_to(&self.ap_live) {
            return Err(Error::Authority);
        }
        original.current().map_err(|_| Error::Authority)?;
        if !self.ap_completed_prefix_if(ifidx)? {
            return Err(Error::Busy);
        }
        original.current().map_err(|_| Error::Authority)?;
        let owner = Owner {
            ifidx,
            original,
            next: 1,
        };
        if ifidx == 0 {
            self.ap = Some(alloc::boxed::Box::new(owner));
        } else {
            self.vif_ap.push(owner);
        }
        Ok(())
    }
    pub(crate) fn ap_completed_prefix(&mut self) -> Result<bool, Error> {
        self.ap_completed_prefix_if(0)
    }
    pub(crate) fn ap_completed_prefix_if(&mut self, ifidx: u8) -> Result<bool, Error> {
        if self.failed || self.stopped {
            return Err(Error::Failed);
        }
        if self.pending.is_some() || self.ap_input_pending(ifidx) {
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
        self.ap_retire_peer_if(0, peer)
    }
    pub(crate) fn ap_retire_peer_if(&mut self, ifidx: u8, peer: [u8; 6]) -> Result<bool, Error> {
        if self.ap_owner(ifidx).is_none() || peer == [0; 6] || peer[0] & 1 != 0 {
            return Err(Error::Unsupported);
        }
        // No host flow ring or retained TX ID exists on synchronous SDPCM.
        // Session separately requires actual native SCB absence/epochs.
        self.ap_completed_prefix_if(ifidx)
    }
    pub(crate) fn ap_leave(&mut self) -> Result<bool, Error> {
        self.ap_leave_if(0)
    }
    pub(crate) fn ap_leave_if(&mut self, ifidx: u8) -> Result<bool, Error> {
        if self.ap_owner(ifidx).is_none() {
            return Ok(true);
        }
        if !self.ap_completed_prefix_if(ifidx)? {
            return Ok(false);
        }
        if ifidx == 0 {
            self.ap = None;
        } else {
            self.vif_ap.retain(|owner| owner.ifidx != ifidx);
        }
        Ok(true)
    }
    pub(crate) fn ap_send(
        &mut self,
        bytes: &[u8],
        priority: u8,
        original: &Capture,
    ) -> Result<Ticket, Error> {
        self.ap_send_if(0, bytes, priority, original)
    }
    pub(crate) fn ap_send_if(
        &mut self,
        ifidx: u8,
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
        self.ap_owner(ifidx)
            .ok_or(Error::Unsupported)?
            .admits(original)?;
        // Retain original before consuming any physical prefix. Session must
        // process actual queued peer/key/loss/control data before retry; no
        // transport method silently discards it or captures a fresh target.
        let mut idle = false;
        for _ in 0..4 {
            if self.ap_input_pending(ifidx) {
                return Err(Error::Busy);
            }
            let count = self.poll()?;
            if self.ap_input_pending(ifidx) {
                return Err(Error::Busy);
            }
            if count == 0 && self.ap_completed_prefix_if(ifidx)? {
                idle = true;
                break;
            }
        }
        if !idle {
            return Err(Error::Busy);
        }
        let owner = self.ap_owner(ifidx).ok_or(Error::Failed)?;
        owner.admits(original)?;
        let id = owner.next;
        let next = id
            .checked_add(1)
            .filter(|value| *value < u32::MAX)
            .ok_or(Error::Failed)?;
        self.send_data_inner(ifidx, bytes, priority, Some(original))?;
        self.ap_owner_mut(ifidx).ok_or(Error::Failed)?.next = next;
        // Only the actual fully copied PIO packet yields this terminal. It
        // releases the host byte borrow; no air ACK/MAC/FIFO claim follows.
        Ok(Ticket::pio_copied(id, original.clone()))
    }
}
