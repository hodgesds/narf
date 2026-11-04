// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained per-firmware/physical-peer LPS template bookkeeping. This is not
//! permission to issue H2C, wake hardware, or enable autonomous transmission.
use super::{lps_wire, power, station_control::Peer};
use alloc::{sync::Arc, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    State,
    Exhausted,
    Source(power::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    Add(u8),
    General,
    Ready,
    Delete(u8),
    Removed,
    Uncertain,
}
#[derive(Clone, Copy, Debug)]
struct Pending {
    id: u8,
    operation: u8,
    command_done: bool,
    response: bool,
}

/// Created only by the same actual fresh WCPU owner. IDs are never reused in
/// that firmware epoch, including after failed/cancelled ADD/DEL; a physical
/// reset/new verified firmware owner is required after namespace exhaustion.
pub(super) struct Namespace {
    epoch: u64,
    next: u16,
    counters: Arc<IrqSafeSpinLock<lps_wire::Counters>>,
}
impl Namespace {
    pub(super) fn after_firmware(epoch: u64) -> Option<Self> {
        (epoch != 0).then(|| Self {
            epoch,
            next: 0,
            counters: Arc::new(IrqSafeSpinLock::new(lps_wire::Counters::default())),
        })
    }
    /// The namespace of the next verified image on the same WCPU (a WoW
    /// firmware swap): ids restart, the epoch never repeats.
    pub(super) fn next(&self) -> Option<Self> {
        Self::after_firmware(self.epoch.checked_add(1)?)
    }
    pub(super) fn reserve(
        &mut self,
        peer: Peer,
        association: u64,
        aid: u16,
        wmm: bool,
    ) -> Result<Packets, Error> {
        peer.current().map_err(Error::Source)?;
        if association == 0 {
            return Err(Error::State);
        }
        let frames = lps_wire::templates(peer.own(), peer.bssid(), aid, wmm).ok_or(Error::State)?;
        if self.next > 252 {
            return Err(Error::Exhausted);
        }
        let ids = [
            self.next as u8,
            (self.next + 1) as u8,
            (self.next + 2) as u8,
        ];
        // Reserve before any await/publication. Error or cancellation cannot
        // return a possibly installed firmware identity to another peer.
        self.next += 3;
        Ok(Packets {
            epoch: self.epoch,
            counters: self.counters.clone(),
            association,
            peer,
            ids,
            frames,
            stage: Stage::Add(0),
            pending: None,
        })
    }
}
pub(super) struct Packets {
    counters: Arc<IrqSafeSpinLock<lps_wire::Counters>>,
    epoch: u64,
    association: u64,
    peer: Peer,
    ids: [u8; 3],
    frames: [Vec<u8>; 3],
    stage: Stage,
    pending: Option<Pending>,
}
impl Packets {
    /// Metadata/actual sealed peer check only. Native must additionally keep
    /// original firmware/device/PS-program, net identity and awake/transition
    /// source scopes current; matching addresses alone never rebind this set.
    pub(super) fn current(&self, epoch: u64, association: u64) -> Result<(), Error> {
        if epoch != self.epoch
            || association != self.association
            || matches!(self.stage, Stage::Removed | Stage::Uncertain)
        {
            return Err(Error::State);
        }
        self.peer.current().map_err(Error::Source)
    }
    pub(super) fn prepare_rpwm(&self, previous: u16, state: u8) -> Option<lps_wire::Request> {
        self.counters.lock().prepare(previous, state)
    }
    pub(super) fn rpwm_published(&self, request: lps_wire::Request) -> bool {
        self.counters.lock().published(request)
    }
    pub(super) fn cpwm_completed(&self, request: lps_wire::Request, ldm: u32, cpwm: u16) -> bool {
        self.counters.lock().completed(request, ldm, cpwm)
    }
    pub(super) fn stage(&self) -> Stage {
        self.stage
    }
    pub(super) fn pending(&self) -> Option<(u8, u8)> {
        self.pending.map(|p| (p.id, p.operation))
    }
    /// The NULL data template id (keep-alive reuses it).
    pub(super) fn null_id(&self) -> u8 {
        self.ids[1]
    }
    pub(super) fn ready(&self) -> bool {
        self.stage == Stage::Ready && self.pending.is_none()
    }
    /// Arm before the actual command future. That future's exact native
    /// publication/DONE and copied C2H remain independent required receipts.
    pub(super) fn begin_add(&mut self) -> Result<Vec<u8>, Error> {
        let Stage::Add(index) = self.stage else {
            return Err(Error::State);
        };
        if self.pending.is_some() {
            return Err(Error::State);
        }
        let id = self.ids[usize::from(index)];
        let bytes =
            lps_wire::add_packet(id, &self.frames[usize::from(index)]).ok_or(Error::State)?;
        self.pending = Some(Pending {
            id,
            operation: 0,
            command_done: false,
            response: false,
        });
        Ok(bytes)
    }
    pub(super) fn command_done(&mut self, id: u8, operation: u8) -> Result<(), Error> {
        let pending = self.pending.as_mut().ok_or(Error::State)?;
        if pending.id != id || pending.operation != operation || pending.command_done {
            return Err(Error::State);
        }
        pending.command_done = true;
        self.advance();
        Ok(())
    }
    /// Feed only original native C2H MAC1/OFLD1/function2 captured after the
    /// actual issued request's prefix fence. Other ids/ops are unrelated.
    pub(super) fn response(&mut self, bytes: &[u8]) -> Result<bool, Error> {
        let Some(pending) = self.pending.as_mut() else {
            return Ok(false);
        };
        if !lps_wire::packet_response(bytes, pending.id, pending.operation) {
            return Ok(false);
        }
        if pending.response {
            return Err(Error::State);
        }
        pending.response = true;
        self.advance();
        Ok(true)
    }
    fn advance(&mut self) {
        if !self.pending.is_some_and(|p| p.command_done && p.response) {
            return;
        }
        self.pending = None;
        self.stage = match self.stage {
            Stage::Add(index) if index < 2 => Stage::Add(index + 1),
            Stage::Add(_) => Stage::General,
            Stage::Delete(index) if index < 2 => Stage::Delete(index + 1),
            Stage::Delete(_) => Stage::Removed,
            _ => Stage::Uncertain,
        };
    }
    pub(super) fn general(&self) -> Result<[u8; 6], Error> {
        if self.stage != Stage::General || self.pending.is_some() {
            return Err(Error::State);
        }
        lps_wire::general(self.ids).ok_or(Error::State)
    }
    /// Only after real GENERAL_PKT DONE_ACK for this original exact body.
    pub(super) fn general_done(&mut self, body: [u8; 6]) -> Result<(), Error> {
        if self.general()? != body {
            return Err(Error::State);
        }
        self.stage = Stage::Ready;
        Ok(())
    }
    pub(super) fn begin_retire(&mut self) {
        // Caller first proves actual active/no-autonomous-PS state, or takes
        // a nonemitting physical reset instead. Metadata cleanup grants no RF.
        self.pending = None;
        self.stage = Stage::Delete(0);
    }
    pub(super) fn begin_delete(&mut self) -> Result<[u8; 4], Error> {
        let Stage::Delete(index) = self.stage else {
            return Err(Error::State);
        };
        if self.pending.is_some() {
            return Err(Error::State);
        }
        let id = self.ids[usize::from(index)];
        let bytes = lps_wire::delete_packet(id).ok_or(Error::State)?;
        self.pending = Some(Pending {
            id,
            operation: 1,
            command_done: false,
            response: false,
        });
        Ok(bytes)
    }
    /// Unknown firmware storage/command state never opens the PS owner. Keep
    /// this same set and all actual native command/DMA owners until cleanup
    /// receipts or physical reset; Namespace never recycles these identities.
    pub(super) fn uncertain(&mut self) {
        self.stage = Stage::Uncertain;
    }
}
