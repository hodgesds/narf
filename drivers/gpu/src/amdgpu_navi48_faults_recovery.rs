//! Re-arm only after coordinated retirement of all three owned kernel rings.
use super::*;

/// Fault evidence accumulated during containment, including late vectors and
/// overflow latch sweeps. Counts and the last record remain sticky on re-arm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    /// Faults without client attribution: graphics, compute, SDMA0 bits 0..2.
    pub queues: u8,
    /// Union of observed client VMIDs, for diagnostics only. VMIDs can be
    /// reused before a late IV arrives and are independent on each hub.
    pub vmids: u16,
    /// Nonzero PASIDs from client IVs. A full set requires device recovery;
    /// silently discarding attribution could replay a faulting address space.
    pub pasids: [u16; 16],
    /// Latches and IVs without a PASID cannot establish guilt. Cancel matching
    /// jobs only on their hub ([GFX, MM]), without blaming another client.
    pub unattributed_vmids: [u16; 2],
    /// Poison, VMID0/foreign contexts or unowned queues need device recovery.
    pub device_reset: bool,
}
impl Scope {
    pub(super) fn latch(&mut self, hub: Hub, protection: Protection) {
        if protection.raw != 0 {
            self.client(hub, protection.vmid, 0);
        }
    }
    fn client(&mut self, hub: Hub, vmid: u8, pasid: u16) {
        if (1..=7).contains(&vmid) {
            self.vmids |= 1 << vmid;
            if pasid == 0 {
                self.unattributed_vmids[hub_index(hub)] |= 1 << vmid;
            } else if !self.pasids.contains(&pasid) {
                match self.pasids.iter_mut().find(|p| **p == 0) {
                    Some(slot) => *slot = pasid,
                    None => self.device_reset = true,
                }
            }
        } else {
            self.device_reset = true;
        }
    }
    pub(crate) fn guilty(&self, pasid: u16) -> bool {
        pasid != 0 && self.pasids.contains(&pasid)
    }
    pub(crate) fn unattributed(&self, hub: Hub, vmid: u8) -> bool {
        vmid < 16 && self.unattributed_vmids[hub_index(hub)] & (1 << vmid) != 0
    }
    fn event_client(&mut self, record: Record, hub: Hub) {
        match record.event {
            Some(event) => self.client(hub, event.vector.vmid, event.vector.pasid),
            None => self.device_reset = true,
        }
    }
    fn queue(&mut self, record: Record, ring: u8) {
        match record.event.map(|e| e.vector.vmid) {
            Some(1..=7) => self.event_client(record, Hub::Gfx),
            Some(0) => self.queues |= 1 << ring,
            _ => self.device_reset = true,
        }
    }
    fn observe(&mut self, record: Record) {
        match record.kind {
            Kind::Command {
                me,
                pipe: 0,
                queue: 0,
                ..
            } if me < 2 => self.queue(record, me),
            Kind::Sdma {
                instance: 0,
                queue: 0,
                ..
            } => self.queue(record, 2),
            Kind::Vm { hub, .. } => self.event_client(record, hub),
            Kind::Shader { .. } => self.event_client(record, Hub::Gfx),
            Kind::Latched { hub } => match record.protection {
                Some(protection) if protection.raw != 0 => self.latch(hub, protection),
                _ => self.device_reset = true,
            },
            _ => self.device_reset = true,
        }
    }
}
fn hub_index(hub: Hub) -> usize {
    match hub {
        Hub::Gfx => 0,
        Hub::Mm => 1,
    }
}
impl<I: Io> Engine<I> {
    pub(super) fn record(&mut self, record: Record) {
        if self.status.count == u64::MAX {
            self.status.recovery.device_reset = true;
        } else {
            self.status.count += 1;
        }
        self.status.recovery.observe(record);
        self.status.first.get_or_insert(record);
        self.status.last = Some(record);
    }
    pub(super) fn begin_recovery(&mut self) -> Result<u64, Error> {
        if self.status.state != State::Contained || self.status.mask_error.is_some() {
            return Err(Error::Busy);
        }
        if self.status.recovery.device_reset || self.status.count == 0 {
            return Err(Error::DeviceResetRequired);
        }
        self.status.state = State::Recovering;
        self.recovery_mark = self.status.count;
        Ok(self.recovery_mark)
    }
    pub(super) fn rearm(&mut self, mark: u64) -> Result<Scope, Error> {
        if self.status.state != State::Recovering || mark != self.recovery_mark {
            return Err(Error::Busy);
        }
        let scope = self.status.recovery;
        let result = if scope.device_reset || self.status.recoveries == u64::MAX {
            Err(Error::DeviceResetRequired)
        } else {
            self.rearm_inner()
        };
        match result {
            Ok(()) => {
                self.status.state = State::Armed;
                self.status.recovery = Scope::default();
                self.status.recoveries += 1;
                Ok(scope)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                self.status.mask_error = self.mask().err();
                Err(e)
            }
        }
    }
    fn rearm_inner(&mut self) -> Result<(), Error> {
        let (layout, clients, controls) = (self.layout, self.owned_clients, self.controls);
        self.access(|io| {
            for hub in [Hub::Gfx, Hub::Mm] {
                let (at, _) = layout.latch(hub);
                if hub == Hub::Gfx {
                    checked(io.read(at))?;
                }
                if checked(io.read(at))? != 0 {
                    return Err(Error::DeviceResetRequired);
                }
            }
            for (i, (at, _)) in layout.controls(clients).enumerate() {
                if checked(io.read(at))? != controls[i] {
                    return Err(Error::Readback);
                }
            }
            Ok(())
        })?;
        self.status.state = State::Arming;
        for (i, (at, mask)) in layout.controls(clients).enumerate() {
            self.access(|io| {
                let value = controls[i] | mask;
                io.write(at, value);
                if checked(io.read(at))? != value {
                    return Err(Error::Readback);
                }
                Ok(())
            })?;
        }
        self.access(|_| Ok(()))
    }
}
