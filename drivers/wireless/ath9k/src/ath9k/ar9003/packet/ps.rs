// SPDX-License-Identifier: GPL-2.0-or-later
//! Real EDMA/control/IRQ half of N46S. Radio retains the existing AP notice,
//! TIM/epoch, authenticated buffered DATA and terminal-ACK ownership rules.
use super::*;
use crate::ath9k::ps;
use alloc::sync::Arc;
impl<P: Port> Packet<P> {
    pub(super) fn ps_unmark(&self, frame: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if frame.get(1).is_some_and(|flag| flag & 0x10 != 0) {
            Ok(Some(
                descriptor::ps_unmark(frame, self.ps.as_ref().ok_or(Error::State)?)
                    .map_err(|_| Error::Packet)?,
            ))
        } else {
            Ok(None)
        }
    }
    pub(super) fn enable_ps(&mut self, source: &Arc<ps::Grant>) -> Result<(), Error> {
        if self.phase != Phase::Running
            || self.pending.is_some()
            || source.ar9003_wa().is_none()
            || self
                .port
                .ps_grant()
                .is_none_or(|current| !Arc::ptr_eq(&current, source))
            || self
                .ps
                .as_ref()
                .is_some_and(|old| !Arc::ptr_eq(old, source))
        {
            return Err(Error::State);
        }
        source.readback(&self.port)?;
        self.port.bind_ps(source)?;
        self.ps = Some(source.clone());
        if self.irq.is_none() {
            // Polled ownership is real: PCI INTx stays disabled and the
            // station worker has its existing bounded1ms deadline.
            self.irq = Some(irq::enable(
                &self.port,
                false,
                self.mci.lock().mci_enabled(),
            )?);
            self.ps_irq_created = true;
        }
        let mask = irq::power_save(&self.port, self.irq.ok_or(Error::State)?, true)?;
        self.full_imr = mask.imr;
        self.irq = Some(mask);
        Ok(())
    }
    pub(super) fn ps_receive_on(&self) -> Result<(), Error> {
        self.ps.as_ref().ok_or(Error::State)?.check()?;
        let old = self.port.read(DIAG)?;
        self.port.write(DIAG, old & !RX_PARK)?;
        if self.port.read(DIAG)? & RX_PARK != 0 {
            return Err(Error::Descriptor);
        }
        Ok(())
    }
    pub(super) fn ps_timers(&mut self, plan: ps::tim::Plan) -> Result<(), Error> {
        self.ps.as_ref().ok_or(Error::State)?.readback(&self.port)?;
        self.ps_timers_valid = false;
        for (register, value) in plan.registers {
            // hw.c::ath9k_hw_set_sta_beacon_timers AUTOSLEEP arm:
            // BEACON_TIMEOUT_VAL10 <<3 rather than no-auto minimum1.
            let value = if register == 0x80d8 { 80 << 21 } else { value };
            self.port.write(register, value)?;
            if self.port.read(register)? != value {
                return Err(Error::Descriptor);
            }
        }
        let rssi = (self.port.read(0x8018)? & !0xff00) | (10 << 8);
        let mode = self.port.read(0x8240)? | 0x31;
        self.port.write(0x8018, rssi)?;
        self.port.write(0x8240, mode)?;
        if self.port.read(0x8018)? != rssi || self.port.read(0x8240)? != mode {
            return Err(Error::Descriptor);
        }
        let mask = irq::power_save(&self.port, self.irq.ok_or(Error::State)?, true)?;
        self.irq = Some(mask);
        self.full_imr = mask.imr;
        self.ps_timers_valid = true;
        Ok(())
    }
    pub(super) fn ps_awake_mode(&mut self) -> Result<(), Error> {
        self.ps_receive_on()?;
        self.ps_timers_valid = false;
        let mode = self.port.read(0x8240)? & !0x31;
        self.port.write(0x8240, mode)?;
        if self.port.read(0x8240)? != mode {
            return Err(Error::Descriptor);
        }
        let mask = irq::power_save(&self.port, self.irq.ok_or(Error::State)?, false)?;
        if self.ps_irq_created {
            irq::kill(&self.port, false)?;
            self.irq = None;
            self.ps_irq_created = false;
        } else {
            self.irq = Some(mask);
            self.full_imr = mask.imr;
        }
        Ok(())
    }
    pub(super) fn ps_sleep(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || self.pending.is_some() || !self.ps_timers_valid {
            return Err(Error::Busy);
        }
        self.check_transmit()?;
        self.ps.as_ref().ok_or(Error::State)?.check()?;
        self.port.network_sleep()
    }
    pub(super) fn ps_tsf(&self) -> Result<u64, Error> {
        self.ps.as_ref().ok_or(Error::State)?.check()?;
        for _ in 0..8 {
            let high = self.port.read(0x8050)?;
            let low = self.port.read(0x804c)?;
            if self.port.read(0x8050)? == high {
                return Ok((u64::from(high) << 32) | u64::from(low));
            }
        }
        Err(Error::Descriptor)
    }
    pub(super) fn submit_ps(
        &mut self,
        frame: &[u8],
        ap: [u8; 6],
        aid: u16,
        basic: usize,
    ) -> Result<u64, Error> {
        let source = self.ps.clone().ok_or(Error::State)?;
        let local = self.local;
        self.submit_with(frame, |address| {
            descriptor::transmit_ps(frame, local, ap, aid, address, basic, &source)
        })
    }
    pub(super) fn sleep_service(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || self.ps.is_none() {
            return Ok(());
        }
        if let Some(observation) = self.port.mci_network_sleep()? {
            self.mci
                .lock()
                .sleep_period(observation, self.port.now_us())?;
        }
        Ok(())
    }
}
