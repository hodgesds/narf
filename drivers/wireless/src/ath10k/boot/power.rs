// SPDX-License-Identifier: GPL-2.0-or-later
//! QCA6174/9377 host PCI sleep vote, not station RF power save.
//!
//! Linux7.2 pci.c::ath10k_pci_{wake,sleep,ps_timer}: every MMIO operation
//! owns an awake reference. Zero references plus a genuine native-idle pass
//! permit a60ms grace period; pending native work keeps the vote asserted.
//! A released host wake vote is never called a firmware sleep receipt.
use super::{Ath10kMmio, BmiError, BusDeviceCap, Cap, HwRev, Mmio, RegisterOp, Write};

const GRACE_NS: u64 = 60_000_000;
// Linux relies on actual interrupts while asleep. Retain NARF's existing
// 10ms missed-edge backstop after the60ms no-MMIO grace, rather than defeating
// sleep by reading every register from the idle pump every1/10ms.
const BACKSTOP_NS: u64 = GRACE_NS + 10_000_000;
const WAKE_US: u64 = 30_000;

pub(super) trait Raw {
    fn read(&mut self, register: u64) -> Result<u32, BmiError>;
    fn write(&mut self, register: u64, value: u32) -> Result<(), BmiError>;
    fn now(&self) -> u64;
    fn wait_on(&mut self, register: u64) -> Result<(), BmiError> {
        let mut failure = None;
        let complete = narf_scheduler::responsive_spin_until(
            || match self.read(register) {
                Ok(u32::MAX) => {
                    failure = Some(BmiError::DeviceGone);
                    true
                }
                Ok(value) if value & 7 == 3 => true,
                Ok(_) => false,
                Err(error) => {
                    failure = Some(error);
                    true
                }
            },
            narf_time::Deadline::after_us(WAKE_US),
        );
        match failure {
            Some(error) => Err(error),
            None if complete => Ok(()),
            None => Err(BmiError::Timeout),
        }
    }
}

/// Borrowed original authority. Each raw wake/status/payload access invokes
/// the same current executable sources and exact original PCI capability.
/// No wake poll recursively enters an accessor that already requires awake.
struct Authorized<'a, I> {
    cap: &'a Cap<BusDeviceCap, Write>,
    io: &'a mut I,
    sources: Option<&'a crate::ath10k::firmware_source::Source>,
}
impl<I: Ath10kMmio> Authorized<'_, I> {
    fn access(&mut self, offset: u64, value: Option<u32>) -> Result<u32, BmiError> {
        let operation = RegisterOp {
            io: self.io,
            offset,
            value,
        };
        match self.sources {
            Some(source) => source
                .invoke_boot(|| self.cap.invoke(operation))
                .map_err(|_| BmiError::DeviceGone)?
                .map_err(|_| BmiError::Pci),
            None => self.cap.invoke(operation).map_err(|_| BmiError::Pci),
        }
    }
}
impl<I: Ath10kMmio> Raw for Authorized<'_, I> {
    fn read(&mut self, register: u64) -> Result<u32, BmiError> {
        self.access(register, None)
    }
    fn write(&mut self, register: u64, value: u32) -> Result<(), BmiError> {
        self.access(register, Some(value)).map(|_| ())
    }
    fn now(&self) -> u64 {
        narf_time::wall::monotonic_ns()
    }
}

#[derive(Clone, Copy, Debug)]
struct Idle {
    since: u64,
    vote_at: u64,
    backstop: u64,
    signal: u64,
}
#[derive(Debug)]
pub(super) struct Owner {
    local: Option<u64>,
    enabled: bool,
    awake: bool,
    references: u32,
    failed: bool,
    eligible: bool,
    idle: Option<Idle>,
    deferred: bool,
    terminal: bool,
}
impl Owner {
    pub(super) fn new(hardware: HwRev) -> Self {
        Self {
            local: matches!(hardware, HwRev::Qca6174 | HwRev::Qca9377).then_some(0x80000),
            enabled: false,
            awake: false,
            references: 0,
            failed: false,
            eligible: false,
            idle: None,
            deferred: false,
            terminal: false,
        }
    }
    pub(super) fn current(&self) -> bool {
        !self.failed
    }
    fn activate(&mut self, raw: &mut impl Raw, delivered: bool) -> Result<(), BmiError> {
        if self.failed || self.enabled || self.terminal {
            return Err(BmiError::BadResponse);
        }
        if self.local.is_none() || !delivered {
            return Ok(());
        }
        self.enabled = true;
        self.acquire(raw)?;
        self.release()?;
        Ok(())
    }
    fn fail<T>(&mut self, error: BmiError) -> Result<T, BmiError> {
        self.failed = true;
        self.eligible = false;
        self.idle = None;
        Err(error)
    }
    fn acquire(&mut self, raw: &mut impl Raw) -> Result<(), BmiError> {
        if self.failed {
            return Err(BmiError::DeviceGone);
        }
        if !self.enabled {
            return Ok(());
        }
        let Some(next) = self.references.checked_add(1) else {
            return self.fail(BmiError::BadResponse);
        };
        let local = self.local.ok_or(BmiError::Unsupported)?;
        let result = (|| {
            if !self.awake {
                raw.write(local + 4, 1)?;
                if raw.read(local + 4)? & 1 == 0 {
                    return Err(BmiError::BadResponse);
                }
                raw.wait_on(local)?;
            }
            if raw.read(local)? & 7 != 3 {
                return Err(BmiError::DeviceGone);
            }
            Ok(())
        })();
        if let Err(error) = result {
            return self.fail(error);
        }
        self.awake = true;
        self.references = next;
        Ok(())
    }
    fn release(&mut self) -> Result<(), BmiError> {
        if !self.enabled {
            return Ok(());
        }
        let Some(next) = self.references.checked_sub(1) else {
            return self.fail(BmiError::BadResponse);
        };
        self.references = next;
        Ok(())
    }
    fn access<T>(
        &mut self,
        raw: &mut impl Raw,
        operation: impl FnOnce(&mut dyn Raw) -> Result<T, BmiError>,
    ) -> Result<T, BmiError> {
        if !self.enabled {
            return operation(raw);
        }
        self.idle = None;
        self.acquire(raw)?;
        let result = operation(raw);
        self.release()?;
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.fail(error),
        }
    }
    pub(super) fn hint(&mut self, eligible: bool) {
        self.eligible = eligible && !self.terminal;
        if !self.eligible {
            self.idle = None;
        }
    }
    fn quiet(&mut self, now: u64, signal: u64) -> Result<(), BmiError> {
        if !self.enabled || !self.eligible || self.references != 0 || self.failed {
            self.idle = None;
            return Ok(());
        }
        let (Some(vote_at), Some(backstop)) =
            (now.checked_add(GRACE_NS), now.checked_add(BACKSTOP_NS))
        else {
            return self.fail(BmiError::BadResponse);
        };
        self.idle = Some(Idle {
            since: now,
            vote_at,
            backstop,
            signal,
        });
        Ok(())
    }
    fn idle_poll(&mut self, raw: &mut impl Raw, signal: u64) -> Result<bool, BmiError> {
        if self.failed {
            return Err(BmiError::DeviceGone);
        }
        let Some(idle) = self.idle else {
            return Ok(false);
        };
        if !self.enabled || !self.eligible || self.references != 0 || signal != idle.signal {
            self.idle = None;
            return Ok(false);
        }
        let now = raw.now();
        if now < idle.since {
            return self.fail(BmiError::BadResponse);
        }
        if now >= idle.backstop {
            self.idle = None;
            return Ok(false);
        }
        if now >= idle.vote_at && self.awake {
            let local = self.local.ok_or(BmiError::Unsupported)?;
            let result = raw.write(local + 4, 0).and_then(|_| {
                if raw.read(local + 4)? & 1 != 0 {
                    Err(BmiError::BadResponse)
                } else {
                    Ok(())
                }
            });
            if let Err(error) = result {
                return self.fail(error);
            }
            // This is the actual host-vote readback, not an RTC sleep ACK.
            self.awake = false;
        }
        Ok(true)
    }
    fn terminal_cleanup(&mut self, raw: &mut impl Raw) -> Result<(), BmiError> {
        if self.references != 0 {
            return self.fail(BmiError::BadResponse);
        }
        // PciBoot has already retired the generation and closed HIF/RF before
        // detaching an expired executable scope. Only the original still-live
        // PCI cap may now wake hardware for CE halt/BME-off/ordered flushing.
        self.terminal = true;
        self.eligible = false;
        self.idle = None;
        self.deferred = false;
        self.failed = false;
        self.awake = false;
        if self.local.is_some() {
            self.enabled = true;
            self.acquire(raw)?;
            self.release()?;
        }
        // The old reset-to-ROM algorithm must access its explicit reset
        // registers while RTC/link state changes. Keep the proven host wake
        // vote pinned, but leave those terminal-only raw accesses under the
        // original PCI invocation, not runtime's already-awake assumption.
        self.enabled = false;
        Ok(())
    }
    fn stop(&mut self, raw: &mut impl Raw) -> Result<(), BmiError> {
        if self.references != 0 || self.failed {
            return Err(BmiError::BadResponse);
        }
        if self.enabled || self.terminal && self.local.is_some() {
            let local = self.local.ok_or(BmiError::Unsupported)?;
            raw.write(local + 4, 0)?;
            if raw.read(local + 4)? & 1 != 0 {
                return self.fail(BmiError::BadResponse);
            }
        }
        self.enabled = false;
        self.awake = false;
        self.eligible = false;
        self.idle = None;
        self.deferred = false;
        Ok(())
    }
}

impl<I: Ath10kMmio> Mmio<I> {
    pub(super) fn access_register(
        &mut self,
        offset: u64,
        value: Option<u32>,
    ) -> Result<u32, BmiError> {
        let Self {
            cap,
            io,
            sources,
            power,
        } = self;
        let mut raw = Authorized {
            cap,
            io,
            sources: sources.as_ref(),
        };
        match power {
            Some(owner) => owner.access(&mut raw, |raw| match value {
                Some(value) => raw.write(offset, value).map(|_| 0),
                None => raw.read(offset),
            }),
            None => raw.access(offset, value),
        }
    }
    pub(super) fn activate_power(&mut self, delivered: bool) -> Result<(), BmiError> {
        let Self {
            cap,
            io,
            sources,
            power,
        } = self;
        let mut raw = Authorized {
            cap,
            io,
            sources: sources.as_ref(),
        };
        if let Some(owner) = power {
            owner.activate(&mut raw, delivered)?;
        }
        Ok(())
    }
    pub(super) fn idle_power_poll(&mut self, signal: u64) -> Result<bool, BmiError> {
        let Self {
            cap,
            io,
            sources,
            power,
        } = self;
        let mut raw = Authorized {
            cap,
            io,
            sources: sources.as_ref(),
        };
        match power {
            Some(owner) => owner.idle_poll(&mut raw, signal),
            None => Ok(false),
        }
    }
    pub(super) fn idle_power_hint(&mut self, eligible: bool) {
        if let Some(owner) = &mut self.power {
            owner.hint(eligible);
        }
    }
    pub(super) fn power_quiet(&mut self, signal: u64) -> Result<(), BmiError> {
        if let Some(owner) = &mut self.power {
            owner.quiet(narf_time::wall::monotonic_ns(), signal)?;
        }
        Ok(())
    }
    pub(super) fn mark_power_deferred(&mut self, deferred: bool) {
        if let Some(owner) = &mut self.power {
            owner.deferred = deferred;
        }
    }
    pub(super) fn take_power_deferred(&mut self) -> bool {
        self.power
            .as_mut()
            .is_some_and(|owner| core::mem::take(&mut owner.deferred))
    }
    pub(super) fn terminal_power_cleanup(&mut self) -> Result<(), BmiError> {
        let Self {
            cap,
            io,
            sources,
            power,
        } = self;
        let mut raw = Authorized {
            cap,
            io,
            sources: sources.as_ref(),
        };
        if let Some(owner) = power {
            owner.terminal_cleanup(&mut raw)?;
        }
        Ok(())
    }
    pub(super) fn stop_power(&mut self) -> Result<(), BmiError> {
        let Self {
            cap,
            io,
            sources,
            power,
        } = self;
        let mut raw = Authorized {
            cap,
            io,
            sources: sources.as_ref(),
        };
        if let Some(owner) = power {
            owner.stop(&mut raw)?;
        }
        Ok(())
    }
}

impl super::PciBoot {
    pub(in crate::ath10k) fn host_idle_supported(&self) -> bool {
        !self.retired
            && self.hif_live
            && self.msi.is_some()
            && self.mmio.power.as_ref().is_some_and(|owner| owner.enabled)
    }
    pub(in crate::ath10k) fn host_idle_hint(&mut self, eligible: bool) {
        self.mmio
            .idle_power_hint(eligible && !self.retired && self.hif_live && self.msi.is_some());
    }
    pub(in crate::ath10k) fn take_host_idle_deferred(&mut self) -> bool {
        self.mmio.take_power_deferred()
    }
    pub(super) fn start_host_power(&mut self) -> Result<(), BmiError> {
        self.mmio.activate_power(self.msi.is_some())?;
        if let Some(link) = self.saved_aspm {
            let cap = self.mmio.cap;
            let device = self.device;
            let restore = || {
                crate::qualcomm_pci::invoke(&cap, || {
                    narf_bus::pci_express::clear_and_set_link_control(
                        &cap,
                        &device,
                        narf_bus::pci_express::LNKCTL_ASPMC,
                        link & narf_bus::pci_express::LNKCTL_ASPMC,
                    )
                    .map_err(|_| BmiError::Pci)?;
                    // Same helper with a zero update reads back the actual
                    // configuration word without inventing an ASPM receipt.
                    let actual =
                        narf_bus::pci_express::clear_and_set_link_control(&cap, &device, 0, 0)
                            .map_err(|_| BmiError::Pci)?;
                    if actual & narf_bus::pci_express::LNKCTL_ASPMC
                        != link & narf_bus::pci_express::LNKCTL_ASPMC
                    {
                        return Err(BmiError::Pci);
                    }
                    Ok(())
                })
                .map_err(|_| BmiError::Pci)?
            };
            match &self.mmio.sources {
                Some(source) => source
                    .invoke_boot(restore)
                    .map_err(|_| BmiError::DeviceGone)??,
                None => restore()?,
            }
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "power_tests.rs"]
mod tests;
