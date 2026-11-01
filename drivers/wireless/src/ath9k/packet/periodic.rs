// SPDX-License-Identifier: GPL-2.0-or-later
//! Same Packet retains all mappings/tickets through periodic PHY work.
//! No healthy partial mutation escapes this bounded source continuation.
use super::*;
use crate::ath9k::periodic::{self, Context as PeriodicContext, Io};
struct Raw<'a, P>(&'a P);
impl<P: Port> Io for Raw<'_, P> {
    fn read(&self, register: u64) -> Result<u32, Error> {
        self.0.periodic_read(register)
    }
    fn write(&self, register: u64, value: u32) -> Result<(), Error> {
        self.0.periodic_write(register, value)
    }
    fn now_us(&self) -> u64 {
        self.0.now_us()
    }
    fn delay_us(&self, us: u64) {
        self.0.delay_us(us);
    }
}
impl<P: Port> PeriodicContext for Raw<'_, P> {
    fn publish(&self, live: periodic::Live) -> Result<(), Error> {
        self.0.periodic_install(live)
    }
    fn failed(&self) {
        self.0.periodic_failed();
    }
}
impl<P: Port> Packet<P> {
    pub(in crate::ath9k) fn periodic_epoch(&mut self) {
        if let Some(owner) = &mut self.periodic {
            owner.peer_epoch();
        } else {
            self.periodic_checked = false;
        }
    }
    pub(in crate::ath9k) fn periodic_bound(&self) -> bool {
        self.periodic.is_some()
    }
    pub(in crate::ath9k) fn periodic_beacon(&mut self, rssi: i8) {
        if let Some(owner) = &mut self.periodic {
            owner.beacon(rssi);
        }
    }
    /// `eligible` proves the Radio has drained RX to genuine idle and has
    /// no software/native original/control/security continuation to commit.
    /// The sole exception is a timed-out sample: clear only DO_CAL under real
    /// all-QCU idle, retaining every old ticket and its unchanged coefficients.
    pub(in crate::ath9k) fn periodic_service(&mut self, eligible: bool) -> Result<(), Error> {
        let result = self.periodic_inner(eligible);
        if result.is_err() {
            self.port.periodic_failed();
            self.phase = Phase::Failed;
        }
        result
    }
    /// Pure CPU observation for an external enqueue/copy attempt. An expired
    /// sample defers admission without native I/O or a crypto reservation;
    /// the retained bounded poll worker owns the actual quiet retry.
    pub(in crate::ath9k) fn periodic_deferred(&self) -> Result<bool, Error> {
        match &self.periodic {
            Some(owner) => owner.urgent_retry(self.port.now_us()),
            None => Ok(false),
        }
    }
    fn periodic_inner(&mut self, eligible: bool) -> Result<(), Error> {
        if self.phase != Phase::Running {
            return Ok(());
        }
        if self.periodic.is_none() {
            if !eligible || self.periodic_checked || self.ht.is_none() {
                return Ok(());
            }
            self.periodic_checked = true;
            // S1 has a static initial-coefficient authority. Never silently
            // combine it with the distinct P program or reinterpret S1 bytes.
            if self.ps.is_some() {
                return Ok(());
            }
            let Some(source) = self.port.periodic_grant() else {
                return Ok(());
            };
            self.check_transmit()?;
            let saved = match self.periodic_park(false) {
                Ok(saved) => saved,
                Err(Error::Busy) => {
                    self.periodic_checked = false;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            self.port.bind_periodic(&source)?;
            let (report, wide) = self.port.periodic_initial()?;
            let raw = Raw(&self.port);
            self.periodic = Some(periodic::Owner::new(&raw, report, wide)?);
            self.periodic_restore(saved)?;
        }
        let mut owner = self.periodic.take().ok_or(Error::State)?;
        let result = (|| {
            let raw = Raw(&self.port);
            let urgent = owner.urgent_retry(raw.now_us())?;
            if !eligible && !urgent {
                return Ok(());
            }
            let Some(work) = owner.work(&raw)? else {
                return Ok(());
            };
            if !urgent && (self.pending.is_some() || self.pair.is_some() || self.held.is_some()) {
                return Ok(());
            }
            let saved = match self.periodic_park(true) {
                Ok(saved) => saved,
                Err(Error::Busy) if !urgent => return Ok(()),
                Err(Error::Busy) => return Err(Error::Timeout),
                Err(error) => return Err(error),
            };
            owner.run(&raw, work)?;
            if owner.blocked() {
                // Source loadnf can take222ms. Use the scheduler's responsive
                // bounded primitive with the same retained token/deadline,
                // not a private register spin or an invented load receipt.
                let mut terminal = None;
                let complete = narf_scheduler::responsive_spin_until(
                    || {
                        let step = (|| {
                            raw.delay_us(10);
                            let work = owner.work(&raw)?.ok_or(Error::State)?;
                            owner.run(&raw, work)
                        })();
                        if let Err(error) = step {
                            terminal = Some(error);
                            return true;
                        }
                        !owner.blocked()
                    },
                    narf_time::Deadline::after_us(222_000),
                );
                if let Some(error) = terminal {
                    return Err(error);
                }
                if !complete || owner.blocked() {
                    return Err(Error::Timeout);
                }
            }
            self.periodic_restore(saved)
        })();
        self.periodic = Some(owner);
        result
    }
    fn periodic_park(&self, bound: bool) -> Result<u32, Error> {
        let read = |register| {
            if bound {
                self.port.periodic_read(register)
            } else {
                self.port.read(register)
            }
        };
        let write = |register, value| {
            if bound {
                self.port.periodic_write(register, value)
            } else {
                self.port.write(register, value)
            }
        };
        if read(QTXE)? & 0x3ff != 0 {
            return Err(Error::Busy);
        }
        for queue in 0..QUEUES {
            if read(QSTS + queue * 4)? & 3 != 0 {
                return Err(Error::Busy);
            }
        }
        let saved = read(DIAG)?;
        write(DIAG, saved | RX_PARK)?;
        if read(DIAG)? & RX_PARK != RX_PARK {
            return Err(Error::Descriptor);
        }
        let mut terminal = None;
        let idle = narf_scheduler::responsive_spin_until(
            || match read(0x806c) {
                Ok(value) if value & 0x01f00000 == 0 => true,
                Ok(_) => {
                    self.port.delay_us(10);
                    false
                }
                Err(error) => {
                    terminal = Some(error);
                    true
                }
            },
            narf_time::Deadline::after_us(2000),
        );
        if let Some(error) = terminal {
            return Err(error);
        }
        if !idle {
            return Err(Error::Timeout);
        }
        Ok(saved)
    }
    fn periodic_restore(&self, saved: u32) -> Result<(), Error> {
        self.port.periodic_write(DIAG, saved)?;
        if self.port.periodic_read(DIAG)? != saved {
            return Err(Error::Descriptor);
        }
        self.check_transmit()
    }
}
