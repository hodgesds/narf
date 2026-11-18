// SPDX-License-Identifier: GPL-2.0-or-later
//! Mounted below prepare::station: explicit BE NBTH installation/lifecycle.
//! Ordinary NAPC, EE NETH and original BB restoration never mint this grant.
use super::*;
use crate::rtlwifi::{
    rtl8723be::{envelope::Operating, tracking as thermal},
    station_power::{Base, Grant as PowerGrant},
};
#[derive(Clone, Copy)]
pub(crate) enum Notice {
    Scan(bool),
    Connect(bool),
    Ips(bool),
    Leisure(bool),
}
impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    pub(crate) async fn be_tracking_notify(
        &mut self,
        notice: Notice,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        let base = self.station.calibration.clone();
        let permission = self.station_grant();
        let qualified = base
            .as_ref()
            .is_some_and(|base| base.rtl8723be_tracking().is_some());
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: qualified,
        };
        let result = {
            let future = async {
                match notice {
                    Notice::Scan(start) => self.be8723_scan_notify(start).await,
                    Notice::Connect(start) => self.be8723_connect_notify(start).await,
                    Notice::Ips(off) => self.be8723_ips_notify(off).await,
                    Notice::Leisure(true) => self.enter_leisure().await,
                    Notice::Leisure(false) => self.leave_leisure().await,
                }
            };
            let mut future = core::pin::pin!(future);
            let future = core::future::poll_fn(|cx| {
                if qualified
                    && (environment.preparation_failed()
                        || environment
                            .admission()
                            .is_some_and(|a| a.closed.load(Ordering::Acquire)))
                {
                    return core::task::Poll::Ready(Err(RadioError::State));
                }
                future.as_mut().poll(cx)
            });
            if qualified {
                power_wait(
                    base.ok_or(Error::Profile)?,
                    None,
                    None,
                    None,
                    None,
                    permission.ok_or(Error::State)?,
                    environment,
                    future,
                )
                .await
            } else {
                future.await
            }
        };
        attempt.armed = false;
        if result.is_err() && qualified {
            self.abort_station();
        }
        result.map_err(Error::Radio)
    }
    /// A deliberate serialized restore may need to leave successful LPS
    /// first. The same current joint source encloses that real wake; a failed
    /// calibration/notification is never revived through this path.
    pub(in crate::rtlwifi) async fn be_tracking_wake_for_restore(
        &mut self,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        let Some(state) = self.packet.be8723.tracking.as_ref() else {
            return Ok(());
        };
        if state.uncertain
            || self.station_phase() == Phase::Failed
            || environment.preparation_failed()
        {
            return Err(Error::State);
        }
        self.check_station_policy(environment)?;
        if self.leisure() {
            self.be_tracking_notify(Notice::Leisure(false), environment)
                .await?;
        }
        Ok(())
    }
    pub(in crate::rtlwifi) async fn be_tracking_leisure(
        &mut self,
        enter: bool,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if enter {
            self.be_tracking_restore(environment).await?;
        }
        self.be_tracking_notify(Notice::Leisure(enter), environment)
            .await
    }
    pub(in crate::rtlwifi) fn be_tracking_authority(
        &self,
    ) -> Option<(
        Arc<thermal::Grant>,
        crate::rtlwifi::rtl8723be::envelope::Permission,
    )> {
        let state = self.packet.be8723.tracking.as_ref()?;
        Some((state.grant.clone(), state.grant.facts().permission()))
    }
    pub(in crate::rtlwifi) fn be_tracking_bound(&self) -> bool {
        self.chip == super::super::Chip::Rtl8723be && self.packet.be8723.tracking.is_some()
    }
    pub(in crate::rtlwifi) fn be_tracking_request(
        &self,
        firmware: crate::rtlwifi::firmware_transport::Identity,
        environment: &impl Environment,
    ) -> Result<thermal::Request, Error> {
        if self.chip != super::super::Chip::Rtl8723be {
            return Err(Error::Profile);
        }
        self.check_station_policy(environment)?;
        let base = self
            .station
            .calibration
            .as_ref()
            .and_then(Base::rtl8723be)
            .ok_or(Error::Profile)?;
        let facts = match self.packet.be8723.tracking.as_ref() {
            Some(state) => {
                state.grant.with_current(|| Ok(()))?;
                state.grant.facts()
            }
            None => self.rtl8723be_tracking_facts(base)?,
        };
        base.with_current(|| firmware.invoke(|| Ok(())))?;
        Ok(thermal::request(base, firmware, facts))
    }
    pub(in crate::rtlwifi) fn be_tracking_prepare(
        &self,
        environment: &impl Environment,
    ) -> Result<Option<Arc<thermal::Grant>>, Error> {
        if self.chip != super::super::Chip::Rtl8723be {
            return Err(Error::Profile);
        }
        self.check_station_policy(environment)?;
        if self.be_tracking_bound() {
            let grant = self
                .station
                .calibration
                .as_ref()
                .and_then(Base::rtl8723be_tracking)
                .ok_or(Error::Profile)?;
            self.be_tracking_idle()?;
            grant.with_current(|| Ok(()))?;
            return Ok(Some(grant.clone()));
        }
        self.be_tracking_idle()?;
        let base = self
            .station
            .calibration
            .as_ref()
            .and_then(Base::rtl8723be)
            .ok_or(Error::Profile)?
            .clone();
        let facts = self.rtl8723be_tracking_facts(&base)?;
        environment.rtl8723be_tracking(base, facts)
    }
    fn be_tracking_idle(&self) -> Result<(), Error> {
        if !matches!(
            (self.phase, self.station_phase()),
            (Hardware::MacConfigured, Phase::Dormant)
                | (Hardware::Running, Phase::Passive | Phase::Open)
        ) || self.leisure()
            || (self.phase == Hardware::Running && !self.transmit_ready())
            || self.station.pending.is_some()
            || self.station.deferred_eapol.is_some()
            || self.station.delivered_reply.is_some()
            || !self.station.controls.is_empty()
            || self
                .station
                .security
                .as_ref()
                .is_some_and(|security| security.pending_frame().is_some())
        {
            return Err(Error::Busy);
        }
        Ok(())
    }
    pub(in crate::rtlwifi) fn be_tracking_retire_publications(&mut self) -> Result<(), Error> {
        self.be_tracking_idle()?;
        self.station.retire_receive();
        self.station.incoming.clear();
        self.station.rx_idle = false;
        if self.station.failed.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        Ok(())
    }
    pub(in crate::rtlwifi) fn be_tracking_install(
        &mut self,
        grant: Arc<thermal::Grant>,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        self.be_tracking_idle()?;
        self.check_station_policy(environment)?;
        let old = self.station.calibration.as_ref().ok_or(Error::Profile)?;
        if let Some(installed) = old.rtl8723be_tracking() {
            return if Arc::ptr_eq(installed, &grant) && self.be_tracking_bound() {
                Ok(())
            } else {
                Err(Error::Profile)
            };
        }
        let base = old.rtl8723be().ok_or(Error::Profile)?;
        if !Arc::ptr_eq(base, grant.base())
            || self.station_grant() != Some(PowerGrant::Rtl8723be(grant.facts().permission()))
        {
            return Err(Error::Profile);
        }
        let domain = environment.domain()?;
        grant
            .permission_for(&domain, grant.facts().permission().operating())
            .map_err(|e| Error::Radio(RadioError::Power(e)))?;
        // Retain the new joint source BEFORE any installation access. Failure
        // cannot downgrade packet/publication authority to ordinary NAPC.
        self.station.calibration = Some(Base::Rtl8723beTracking(grant.clone()));
        self.rtl8723be_install_tracking(grant)?;
        self.check_station_policy(environment)
    }
    /// Deliberate restoration, under the OLD current joint program. It keeps
    /// NBTH installed; a different op/measurement requires a complete rebuild.
    pub(in crate::rtlwifi) async fn be_tracking_restore(
        &mut self,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        let Some(state) = self.packet.be8723.tracking.as_ref() else {
            return Ok(());
        };
        let base = self
            .station
            .calibration
            .as_ref()
            .ok_or(Error::Profile)?
            .clone();
        let joint = base.rtl8723be_tracking().ok_or(Error::Profile)?;
        if !Arc::ptr_eq(joint, &state.grant) {
            return Err(Error::Profile);
        }
        let grant = self.station_grant().ok_or(Error::State)?;
        joint
            .permission_for(
                &environment.domain()?,
                joint.facts().permission().operating(),
            )
            .map_err(|error| Error::Radio(RadioError::Power(error)))?;
        if self.phase == Hardware::MacConfigured && self.station_phase() == Phase::Dormant {
            if state.uncertain || state.last.is_some() || state.expected != joint.facts().original()
            {
                return Err(Error::State);
            }
            joint.with_current(|| {
                self.io.authority(false, || {
                    if thermal::Snapshot::read(&self.io)? != joint.facts().original() {
                        return Err(RadioError::Readback);
                    }
                    Ok(())
                })
            })?;
            return Ok(());
        }
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        let result = power_wait(
            base,
            None,
            None,
            None,
            None,
            grant,
            environment,
            self.rtl8723be_restore_tracking(environment),
        )
        .await
        .map_err(Error::Radio);
        attempt.armed = false;
        if result.is_err() {
            self.abort_station();
        }
        result
    }
    pub(super) fn be_tracking_allows_op(
        &self,
        op: Operating,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if let Some(grant) = self
            .station
            .calibration
            .as_ref()
            .and_then(Base::rtl8723be_tracking)
        {
            if op != grant.facts().permission().operating() {
                return Err(Error::Profile);
            }
            grant
                .permission_for(&environment.domain()?, op)
                .map_err(|e| Error::Radio(RadioError::Power(e)))?;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "tracking_station_tests.rs"]
mod tests;

// Concrete inert-actor helpers only: cannot stage metadata on native PciIo.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn shared_native_fixture(
) -> Result<crate::rtlwifi::prepare::packet::be8723::StationFixture, &'static str> {
    let mut h = crate::rtlwifi::prepare::packet::be8723::shared_station_fixture()?;
    h.owner.packet.be8723.tracking.take();
    h.owner.station.calibration = Some(Base::Rtl8723be(h.base.clone()));
    h.owner.station.phase = Phase::Passive;
    // The inert actor's peer/rate metadata bypasses over-air MLME. Mark the
    // same coex peer as reported so native tests can exercise real H2C LPS
    // entry/wake, instead of the source's unlinked successful no-op.
    let coex = h
        .owner
        .rtl8723be_coex
        .as_deref_mut()
        .ok_or("BE coex fixture")?;
    coex.lps.linked = true;
    coex.lps.report_linked = true;
    Ok(h)
}
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn fixture_publication(
    h: &crate::rtlwifi::prepare::packet::be8723::StationFixture,
) -> Publication {
    let model = h.model.clone();
    let pci = crate::rtlwifi::prepare::packet::Publication::model(Arc::new(move || {
        model.authority(true, || Ok(()))
    }));
    Publication {
        pci,
        base: h.owner.station.calibration.clone().unwrap(),
        ht: None,
        protection: None,
        tracking: None,
        antenna: None,
        permission: h.owner.station_grant().unwrap(),
        indices: [0; 8],
        epoch: h.owner.station.epoch.clone(),
        expected: h.owner.station.epoch.load(Ordering::Acquire),
        failed: h.owner.station.failed.clone(),
    }
}
