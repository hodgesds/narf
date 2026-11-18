// SPDX-License-Identifier: GPL-2.0-or-later
//! Mounted below interface: explicit original-owner BE NBTH lifecycle APIs.
use super::*;
use crate::rtlwifi::rtl8723be::tracking as thermal;

/// This view exists only while this native lifecycle/control+Prepared owner
/// deliberately restores its original BB program. Admission is already closed
/// to packets; the exact retained joint/firmware/NAPC/PCI sources still gate
/// every effect. It is not an error-cleanup authority or caller boolean.
struct RestoreEnvironment<'a, I: Port<Buffer = M>, M: Memory, E: Environment> {
    device: &'a Device<I, M, E>,
    generation: u64,
}
impl<I: Port<Buffer = M>, M: Memory, E: Environment> Environment
    for RestoreEnvironment<'_, I, M, E>
{
    fn domain(&self) -> Result<narf_wireless::reg::RegulatoryDomain, Error> {
        self.device.environment.domain()
    }
    fn preparation_failed(&self) -> bool {
        self.device.removed.load(Ordering::Acquire)
            || self.device.lifecycle.generation() != self.generation
            || self.device.environment.preparation_failed()
    }
    fn now_ms(&self) -> u64 {
        self.device.environment.now_ms()
    }
    fn fresh_nonce(&self) -> Option<[u8; 32]> {
        self.device.environment.fresh_nonce()
    }
    async fn pause(&self) {
        self.device.environment.pause().await;
    }
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Device<I, M, E> {
    fn be_thermal_current(&self, generation: u64) -> Result<(), Error> {
        if !self.published.load(Ordering::Acquire)
            || self.removed.load(Ordering::Acquire)
            || self.lifecycle.generation() != generation
            || self.lifecycle.rebuilding.load(Ordering::Acquire)
            || self.lifecycle.suspended.load(Ordering::Acquire)
            || self.lifecycle.inactive.load(Ordering::Acquire)
            || self.environment.preparation_failed()
        {
            return Err(Error::State);
        }
        Ok(())
    }
    pub(in crate::rtlwifi) async fn enable_be_thermal_tracking(&self) -> Result<bool, Error> {
        let _control = self.lifecycle.control.lock().await;
        let mut storage = self.prepared.lock().await;
        let owner = storage.as_mut().ok_or(Error::State)?;
        let current = self.lifecycle.generation();
        self.be_thermal_current(current)?;
        if self.admission.closed.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        // Load/validate the optional signed asset before retiring anything.
        let Some(grant) = owner.be_tracking_prepare(&self.environment)? else {
            return Ok(false);
        };
        if owner.be_tracking_bound() {
            return Ok(true);
        }
        let generation = {
            let _publication = self.admission.publication.lock();
            self.be_thermal_current(current)?;
            if self.admission.closed.load(Ordering::Acquire) {
                return Err(Error::State);
            }
            let generation = self.lifecycle.advance()?;
            self.admission.closed.store(true, Ordering::Release);
            generation
        };
        let mut attempt = Attempt {
            device: self,
            owner: Some(owner.station_cancellation()),
            generation,
            armed: true,
        };
        self.lifecycle.drain_publications().await?;
        owner.be_tracking_retire_publications()?;
        self.state.lock().await.clear();
        grant.with_current(|| {
            self.be_thermal_current(generation)
                .map_err(|_| super::super::prepare::Error::State)?;
            let domain = self
                .environment
                .domain()
                .map_err(|_| super::super::prepare::Error::State)?;
            grant
                .permission_for(&domain, grant.facts().permission().operating())
                .map_err(super::super::prepare::Error::Power)?;
            let _publication = self.admission.publication.lock();
            self.be_thermal_current(generation)
                .map_err(|_| super::super::prepare::Error::State)?;
            // Every old lease/token was retired. Prepared remains exclusively
            // locked until joint Base+State installation, so no new frame or
            // captured publication can observe a partial replacement.
            self.admission.closed.store(false, Ordering::Release);
            Ok(())
        })?;
        if let Err(error) = owner.be_tracking_install(grant, &self.environment) {
            owner.abort_station();
            return Err(error);
        }
        self.be_thermal_current(generation)?;
        attempt.armed = false;
        Ok(true)
    }
    pub(in crate::rtlwifi) async fn restore_be_thermal_tracking(&self) -> Result<(), Error> {
        let _control = self.lifecycle.control.lock().await;
        let mut storage = self.prepared.lock().await;
        let owner = storage.as_mut().ok_or(Error::State)?;
        let current = self.lifecycle.generation();
        self.be_thermal_current(current)?;
        if self.admission.closed.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        if !owner.be_tracking_bound() {
            return Ok(());
        }
        let generation = {
            let _publication = self.admission.publication.lock();
            let generation = self.lifecycle.advance()?;
            self.admission.closed.store(true, Ordering::Release);
            generation
        };
        let mut attempt = Attempt {
            device: self,
            owner: Some(owner.station_cancellation()),
            generation,
            armed: true,
        };
        self.lifecycle.drain_publications().await?;
        // Restore under the OLD joint source. This view checks actual retained
        // native generation/removal while packet admission stays closed.
        let environment = RestoreEnvironment {
            device: self,
            generation,
        };
        owner.be_tracking_wake_for_restore(&environment).await?;
        owner.be_tracking_retire_publications()?;
        self.state.lock().await.clear();
        owner.be_tracking_restore(&environment).await?;
        self.be_thermal_current(generation)?;
        {
            let _publication = self.admission.publication.lock();
            self.be_thermal_current(generation)?;
            self.admission.closed.store(false, Ordering::Release);
        }
        attempt.armed = false;
        Ok(())
    }
    pub(super) async fn be_tracked_lps(&self, owner: &mut Prepared<I, M>, enter: bool) -> bool {
        if !owner.be_tracking_bound() {
            return false;
        }
        if owner
            .be_tracking_leisure(enter, &self.environment)
            .await
            .is_err()
        {
            owner.abort_station();
            self.close();
        }
        true
    }
    /// Called with native control and Prepared held, after admission closure.
    /// A partial/failed owner is never rolled back through this deliberate API.
    pub(super) async fn be_restore_for_lifecycle(
        &self,
        owner: &mut Prepared<I, M>,
    ) -> Result<(), Error> {
        if !owner.be_tracking_bound() {
            return Ok(());
        }
        let generation = self.lifecycle.generation();
        self.lifecycle.drain_publications().await?;
        let environment = RestoreEnvironment {
            device: self,
            generation,
        };
        owner.be_tracking_wake_for_restore(&environment).await?;
        owner.be_tracking_retire_publications()?;
        owner.be_tracking_restore(&environment).await
    }
}
impl Native {
    pub(in crate::rtlwifi) fn be_thermal_tracking_request(
        &self,
    ) -> Result<thermal::Request, Error> {
        let firmware = self.environment.firmware().identity().ok_or(Error::State)?;
        let storage = self.prepared.try_lock().ok_or(Error::Busy)?;
        storage
            .as_ref()
            .ok_or(Error::State)?
            .be_tracking_request(firmware, &self.environment)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "tracking_native_tests.rs"]
mod tests;
