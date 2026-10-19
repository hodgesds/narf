//! Re-arm only after coordinated retirement of all three owned kernel rings.
use super::*;

/// Fault evidence accumulated during containment, including late vectors and
/// overflow latch sweeps. Counts and the last record remain sticky on re-arm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    /// Faults without client attribution: graphics, compute, SDMA0 bits 0..2.
    pub queues: u8,
    /// Faulting client VMIDs, used to exclude their jobs from replay.
    pub vmids: u16,
    /// Poison, VMID0/foreign contexts or unowned queues need device recovery.
    pub device_reset: bool,
}
impl Scope {
    pub(super) fn latch(&mut self, protection: Protection) {
        if protection.raw != 0 {
            self.client(protection.vmid);
        }
    }
    fn client(&mut self, vmid: u8) {
        if (1..=7).contains(&vmid) {
            self.vmids |= 1 << vmid;
        } else {
            self.device_reset = true;
        }
    }
    fn queue(&mut self, record: Record, ring: u8) {
        match record.event.map(|e| e.vector.vmid) {
            Some(vmid @ 1..=7) => self.client(vmid),
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
            Kind::Vm { .. } | Kind::Shader { .. } | Kind::Latched { .. } => {
                let vmid = match record.kind {
                    Kind::Latched { .. } => record.protection.map(|p| p.vmid),
                    _ => record.event.map(|e| e.vector.vmid),
                };
                match vmid {
                    Some(vmid @ 1..=7) => self.vmids |= 1 << vmid,
                    _ => self.device_reset = true,
                }
            }
            _ => self.device_reset = true,
        }
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
