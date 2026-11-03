// SPDX-License-Identifier: GPL-2.0-or-later
//! System sleep and inactive power save share the retained transition owner.
use super::*;
use narf_power::{
    device_pm::DevicePmError,
    system_pm::{AsyncSystemPm, SystemPmFuture},
};

struct PrepareGuard<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> {
    device: Arc<Device<I, M, E>>,
    committed: bool,
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Drop
    for PrepareGuard<I, M, E>
{
    fn drop(&mut self) {
        if !self.committed {
            self.device
                .lifecycle
                .pm_rollback
                .store(true, Ordering::Release);
        }
        self.device
            .lifecycle
            .pm_preparing
            .store(false, Ordering::Release);
        if let Some(signal) = self.device.environment.interrupt() {
            signal.raise();
        }
    }
}

impl<I, M, E> Device<I, M, E>
where
    I: Port<Buffer = M> + 'static,
    M: Memory + 'static,
    E: recovery::Rebuild<I, M> + 'static,
{
    pub(crate) async fn prepare_sleep(self: &Arc<Self>) -> Result<(), Error> {
        self.prepare_sleep_as(supervisor::Operation::Suspend).await
    }
    pub(crate) async fn prepare_sleep_as(
        self: &Arc<Self>,
        operation: supervisor::Operation,
    ) -> Result<(), Error> {
        {
            let _requests = self.lifecycle.pm_requests.lock().await;
            if self.lifecycle.pm_preparing.swap(true, Ordering::AcqRel) {
                return Err(Error::Busy);
            }
            self.lifecycle.pm_rollback.store(false, Ordering::Release);
        }
        let mut guard = PrepareGuard {
            device: self.clone(),
            committed: false,
        };
        let result = self.transition(operation).await;
        if result.is_err() {
            let _ = self.transition(supervisor::Operation::Resume).await;
        }
        guard.committed = true;
        result
    }

    /// Called by the same retained worker after an abandoned system-PM
    /// prepare. Existing hardware work completes before its resume is queued.
    pub(crate) fn service_sleep_rollback(self: &Arc<Self>) {
        if self.removed.load(Ordering::Acquire) {
            return;
        }
        let Some(_requests) = self.lifecycle.pm_requests.try_lock() else {
            return;
        };
        if self.lifecycle.pm_preparing.load(Ordering::Acquire)
            || !self.lifecycle.pm_rollback.load(Ordering::Acquire)
            || self.work.try_lock().is_none_or(|slot| slot.is_some())
        {
            return;
        }
        if self.schedule(supervisor::Operation::Resume).is_ok() {
            self.lifecycle.pm_rollback.store(false, Ordering::Release);
        }
    }

    async fn transition(self: &Arc<Self>, operation: supervisor::Operation) -> Result<(), Error> {
        // The caller can drive existing work without depending on another
        // scheduler task (including when a synchronous PM bridge polls it).
        loop {
            match self.schedule(operation) {
                Ok(waiter) => return waiter.await,
                Err(Error::Busy) => {
                    core::future::poll_fn(|cx| {
                        self.poll_transition(cx);
                        if self.work.try_lock().is_some_and(|slot| slot.is_none()) {
                            core::task::Poll::Ready(())
                        } else {
                            core::task::Poll::Pending
                        }
                    })
                    .await
                }
                Err(reason) => return Err(reason),
            }
        }
    }
    pub(super) async fn sleep_once(
        &self,
        system: bool,
        activity: Option<u64>,
        wow: bool,
    ) -> Result<bool, Error> {
        let _control = self.lifecycle.control.lock().await;
        if self.removed.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        if activity.is_some_and(|old| old != self.lifecycle.activity_ms.load(Ordering::Acquire)) {
            return Ok(false);
        }
        if self.lifecycle.suspended.load(Ordering::Acquire)
            || self.lifecycle.inactive.load(Ordering::Acquire)
        {
            if !self.lifecycle.sleep_complete.load(Ordering::Acquire) {
                return Err(Error::State);
            }
            if system {
                self.lifecycle.suspended.store(true, Ordering::Release);
            }
            return Ok(false);
        }
        let mut storage = self.prepared.lock().await;
        if !system
            && storage
                .as_ref()
                .is_none_or(|owner| owner.station_phase() != station::Phase::Passive)
        {
            return Ok(false);
        }
        // rtl_op_suspend -> rtl_op_stop -> rtl8821ae_card_disable with
        // support_remote_wakeup && enter_pnp_sleep: the linked RTL8821AE
        // station hands its association to the WoWLAN firmware while the
        // prepared mutex still excludes every host packet path. Any failure
        // leaves the owner Failed for the cold card-disable below.
        let mut armed = None;
        if wow && system {
            let config = self.lifecycle.wowlan.lock().clone();
            if let (Some(config), Some(owner)) = (config, storage.as_mut()) {
                if let Ok(image) = self.environment.wowlan_image() {
                    if owner
                        .wow_suspend(&self.environment, &config, &image)
                        .await
                        .is_ok()
                    {
                        armed = Some(owner.take_ae_mailbox());
                    }
                }
            }
        }
        // The retained Work slot owns this guard until terminal completion.
        struct Transition<'a>(&'a lifecycle::Lifecycle);
        impl Drop for Transition<'_> {
            fn drop(&mut self) {
                self.0.rebuilding.store(false, Ordering::Release);
            }
        }
        let _transition = Transition(&self.lifecycle);
        let generation = {
            let publication = self.admission.publication.lock();
            if system {
                self.lifecycle.suspended.store(true, Ordering::Release);
            }
            self.admission.abort.store(true, Ordering::Release);
            self.lifecycle.rebuilding.store(true, Ordering::Release);
            let next = self.lifecycle.advance();
            self.commit_close(publication);
            next?
        };
        if let Some(owner) = storage.as_mut() {
            owner.abort_station();
            self.withdraw_interrupts(owner);
            if !owner.retire().await {
                return Err(Error::State);
            }
        } else {
            self.environment.deliver(false);
        }
        self.lifecycle.drain_publications().await?;
        {
            let mut state = self.state.lock().await;
            state.clear();
            state.epoch = 0;
        }
        storage.take();
        drop(storage);
        match armed {
            Some(mailbox) => self.environment.wow_parked(mailbox)?,
            None => self.environment.power_down().await?,
        }
        if self.lifecycle.generation() != generation {
            return Err(Error::State);
        }
        self.lifecycle.sleep_complete.store(true, Ordering::Release);
        if !system {
            self.lifecycle.inactive.store(true, Ordering::Release);
        }
        Ok(true)
    }
}

pub(super) struct SystemPm {
    pub(super) device: Weak<Native>,
    pub(super) config: IrqSafeSpinLock<Option<narf_bus::pci::SavedPciConfig>>,
    /// Armed RTL8821AE WoWLAN PCI wake route; the function is in D3hot
    /// while this is held.
    pub(super) wake: IrqSafeSpinLock<Option<narf_power::pci_wake::PciWake>>,
}
async fn pci_settle() {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
        narf_bus::pci::PM_D3HOT_DELAY_MS * 1_000_000,
    ))
    .await;
}
impl SystemPm {
    async fn transition(&self, operation: supervisor::Operation) -> Result<(), DevicePmError> {
        let Some(device) = self.device.upgrade() else {
            return Ok(());
        };
        if device.removed.load(Ordering::Acquire) {
            return Ok(());
        }
        device
            .transition(operation)
            .await
            .map_err(|_| DevicePmError::DriverError)
    }
}
impl narf_power::device_pm::DevicePmOps for SystemPm {
    fn suspend(&self) -> Result<(), DevicePmError> {
        let Some(device) = self.device.upgrade() else {
            return Ok(());
        };
        if device.removed.load(Ordering::Acquire) || self.wake.lock().is_some() {
            // The WoWLAN prepare saved config before its D3hot entry.
            return Ok(());
        }
        if !device.lifecycle.suspended.load(Ordering::Acquire)
            || !device.lifecycle.sleep_complete.load(Ordering::Acquire)
        {
            return Err(DevicePmError::Busy);
        }
        let config = device
            .environment
            .firmware()
            .native()
            .suspend_config()
            .map_err(|_| DevicePmError::DriverError)?;
        *self.config.lock() = Some(config);
        Ok(())
    }
    fn resume(&self) -> Result<(), DevicePmError> {
        let Some(device) = self.device.upgrade() else {
            return Ok(());
        };
        if device.removed.load(Ordering::Acquire) || self.wake.lock().is_some() {
            // D0 + config restore of the WoWLAN D3hot needs the async settle
            // (`resume_from_suspend`).
            return Ok(());
        }
        let config = self.config.lock().as_ref().cloned();
        let Some(config) = config else { return Ok(()) };
        device
            .environment
            .firmware()
            .native()
            .resume_config(&config)
            .map_err(|_| DevicePmError::DriverError)?;
        *self.config.lock() = None;
        Ok(())
    }
}
impl AsyncSystemPm for SystemPm {
    fn prepare_suspend<'a>(&'a self) -> SystemPmFuture<'a> {
        Box::pin(async move {
            let Some(device) = self.device.upgrade() else {
                return Ok(());
            };
            if device.removed.load(Ordering::Acquire) {
                return Ok(());
            }
            device.prepare_sleep().await.map_err(|reason| {
                if reason == Error::Busy {
                    DevicePmError::Busy
                } else {
                    DevicePmError::DriverError
                }
            })
        })
    }
    /// RTL8821AE with a retained WoWLAN configuration and an admitted PCI
    /// wake route for `target`: the WoWLAN suspend, then (Linux PCI core
    /// `pci_pm_suspend_noirq` / `pci_prepare_to_sleep`) save config, arm
    /// PME (whose PMCSR write also clears PME status, Linux
    /// `_rtl8821ae_clear_pci_pme_status`) and enter D3hot. Otherwise, or if
    /// the WoWLAN branch fell back to card-disable, the normal suspend.
    fn prepare_suspend_target<'a>(
        &'a self,
        target: narf_power::system_pm::SystemSleepState,
    ) -> SystemPmFuture<'a> {
        Box::pin(async move {
            let Some(device) = self.device.upgrade() else {
                return Ok(());
            };
            if device.removed.load(Ordering::Acquire) {
                return Ok(());
            }
            let firmware = device.environment.firmware();
            let native = firmware.native();
            let route = if device.lifecycle.wowlan.lock().is_some()
                && device.environment.firmware().device_id() == super::super::regs::RTL_DEV_8821AE
            {
                native.wake_route(target).ok()
            } else {
                None
            };
            let operation = if route.is_some() {
                supervisor::Operation::WowSuspend
            } else {
                supervisor::Operation::Suspend
            };
            device.prepare_sleep_as(operation).await.map_err(|reason| {
                if reason == Error::Busy {
                    DevicePmError::Busy
                } else {
                    DevicePmError::DriverError
                }
            })?;
            let Some(mut route) = route else {
                return Ok(());
            };
            if device.environment.power_state.load(Ordering::Acquire) != 3 {
                return Ok(()); // cold card-disable fallback: D0 as before
            }
            // Armed firmware without a wake route keeps D0 (no wake source);
            // resume still runs the WoWLAN prologue and cold rebuild.
            let Ok(config) = native.suspend_config() else {
                return Ok(());
            };
            *self.config.lock() = Some(config);
            if route
                .arm(target, narf_bus::pci::pme::WakeState::D3Hot)
                .is_err()
            {
                return Ok(());
            }
            if native
                .set_pci_power(narf_bus::pci::PciPowerState::D3Hot)
                .is_err()
            {
                let _ = route.disarm();
                return Ok(());
            }
            pci_settle().await;
            *self.wake.lock() = Some(route);
            Ok(())
        })
    }
    /// The WoWLAN D3hot exit (`pci_pm_resume_noirq`: D0, settle, restore
    /// config, disarm PME/GPE) before the resume transition, whose
    /// `power_down` runs `_rtl8821ae_wowlan_initialize_adapter`'s wake
    /// reason and disable commands, then the cold rebuild. The stack then
    /// observes the disconnect (`ieee80211_resume_disconnect`).
    fn resume_from_suspend<'a>(&'a self) -> SystemPmFuture<'a> {
        Box::pin(async move {
            let route = self.wake.lock().take();
            if let Some(mut route) = route {
                let Some(device) = self.device.upgrade() else {
                    route.quarantine();
                    return Ok(());
                };
                let firmware = device.environment.firmware();
                let native = firmware.native();
                if native
                    .set_pci_power(narf_bus::pci::PciPowerState::D0)
                    .is_err()
                {
                    route.quarantine();
                    return Err(DevicePmError::DriverError);
                }
                pci_settle().await;
                if native.pci_power() != Ok(Some(narf_bus::pci::PciPowerState::D0)) {
                    route.quarantine();
                    return Err(DevicePmError::DriverError);
                }
                let config = self.config.lock().take();
                if let Some(config) = config {
                    native
                        .resume_config(&config)
                        .map_err(|_| DevicePmError::DriverError)?;
                }
                if route.disarm().is_err() {
                    // The wake GPE lease stays retained; no new generation
                    // may start over an unreleased route.
                    route.quarantine();
                    return Err(DevicePmError::DriverError);
                }
            }
            self.transition(supervisor::Operation::Resume).await
        })
    }
}
