// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual NASR-qualified original-port and closed-ring continuation. Station
//! MLME/packet opening remains closed until its own AE dispatch is composed.
use super::{
    retained::{Backend, Phase, Retained},
    station_policy::{Grant, Program},
    txpower,
};
use crate::rtlwifi::{
    firmware_native::PciIo,
    firmware_transport::{AeAccess, Error as AccessError},
    prepare::Error,
};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::Ordering;

pub(in crate::rtlwifi) struct State {
    pub(in crate::rtlwifi) program: Arc<Program>,
    pub(in crate::rtlwifi) grant: Grant,
    pub(in crate::rtlwifi) power: txpower::Owner,
    pub(in crate::rtlwifi) receive: Option<u32>,
    pub(in crate::rtlwifi) bcn: Option<u8>,
    pub(in crate::rtlwifi) mac_ready: bool,
    pub(in crate::rtlwifi) live: Arc<core::sync::atomic::AtomicBool>,
}
impl State {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn new(program: Arc<Program>, grant: Grant) -> Self {
        Self::with_live(
            program,
            grant,
            Arc::new(core::sync::atomic::AtomicBool::new(false)),
        )
    }
    fn with_live(
        program: Arc<Program>,
        grant: Grant,
        live: Arc<core::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            program,
            grant,
            power: txpower::Owner::new(),
            receive: None,
            bcn: None,
            mac_ready: false,
            live,
        }
    }
}
struct ActivationAttempt(Arc<Retained<PciIo>>, bool);
impl Drop for ActivationAttempt {
    fn drop(&mut self) {
        if self.1 {
            let _ = self.0.terminal_park();
        }
    }
}
struct Access<I: Backend> {
    root: Arc<Retained<I>>,
    program: Arc<Program>,
    grant: Grant,
}
impl<I: Backend> Access<I> {
    fn checked(&self, operation: &mut dyn FnMut() -> Result<(), AccessError>) -> Result<(), Error> {
        self.program.with_current(|| {
            let domain = self.program.prepared().current_domain()?;
            if self.program.grant_for(&domain)? != self.grant {
                return Err(Error::State);
            }
            let mut result = None;
            self.root.current(self.program.prepared().firmware(), |_| {
                result = Some(operation());
                Ok(())
            })?;
            result.ok_or(Error::State)?.map_err(Error::Access)
        })
    }
    fn finish(&self, result: Result<(), Error>) -> Result<(), AccessError> {
        if result.is_err() {
            let _ = self.root.terminal_park();
        }
        result.map_err(|error| match error {
            Error::Access(error) => error,
            _ => AccessError::Gate,
        })
    }
}
impl<I: Backend> AeAccess for Access<I> {
    fn aspm_profile(&self) -> bool {
        self.program.aspm()
    }
    fn invoke(
        &self,
        operation: &mut dyn FnMut() -> Result<(), AccessError>,
    ) -> Result<(), AccessError> {
        // An outer source/descriptor scope may call scalar PacketIo methods;
        // taking effect_gate here would deadlock that normal nesting.
        self.finish(self.checked(operation))
    }
    fn invoke_effect(
        &self,
        operation: &mut dyn FnMut() -> Result<(), AccessError>,
    ) -> Result<(), AccessError> {
        let result = {
            let _effects = self.root.effect_gate.lock();
            // Actual registration/source/PCI revalidation is INSIDE the gate.
            self.checked(operation)
        };
        // Release the effect gate before attempting terminal cleanup.
        self.finish(result)
    }
}
impl<I: Backend> Retained<I> {
    /// Shared actual claim, exercised by native Rust register/RF actors too.
    /// The exact successful Work/Binding pointer and current signed grant are
    /// required after the mutex wait, before intent or any policy publication.
    pub(super) async fn claim_station_port(
        self: &Arc<Self>,
        program: Arc<Program>,
        grant: Grant,
    ) -> Result<crate::rtlwifi::firmware_transport::PacketIo<I>, Error> {
        let access = Arc::new(Access {
            root: self.clone(),
            program: program.clone(),
            grant,
        });
        let mut retained = self.state.lock().await;
        let domain = program.prepared().current_domain()?;
        if retained.phase != Phase::Prepared
            || !self.registered_for(self.firmware())
            || !retained
                .work
                .as_ref()
                .is_some_and(|work| work.matches_binding(program.prepared()))
            || program.grant_for(domain.as_ref())? != grant
        {
            return Err(Error::State);
        }
        self.station_intent
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::State)?;
        retained.phase = Phase::ResetOnly;
        self.firmware().install_ae_access(access)?;
        retained.port.take().ok_or(Error::State)
    }
}
impl Retained<PciIo> {
    pub(in crate::rtlwifi) async fn activate_station(self: &Arc<Self>) -> Result<(), Error> {
        let _admission = self.admission.lock().await;
        let native = self.native_owner()?;
        let mut attempt = ActivationAttempt(self.clone(), true);
        {
            let mut state = self.state.lock().await;
            if state.phase != Phase::RingsReady || !self.registered_for(self.firmware()) {
                return Err(Error::State);
            }
            // Terminal intent BEFORE the first async lifecycle/Prepared wait.
            state.phase = Phase::ResetOnly;
        }
        let result = native.prepare_ae_station().await;
        let mut state = self.state.lock().await;
        result?;
        if !self.registered_for(self.firmware()) {
            return Err(Error::State);
        }
        // The last current source check and logical activation receipt are
        // in one source invocation. No await follows this commit/disarm.
        let storage = self.transport.get().ok_or(Error::State)?.lock().await;
        let owner = storage.as_ref().ok_or(Error::State)?;
        let (program, grant) = owner.rtl8723ae_program()?;
        program.with_current(|| {
            let domain = program.prepared().current_domain()?;
            if !self.registered_for(self.firmware()) || program.grant_for(&domain)? != grant {
                return Err(Error::State);
            }
            native.commit_ae_station(|| {
                state.phase = Phase::MacReady;
                self.station_live.store(true, Ordering::Release);
                Ok(())
            })
        })?;
        attempt.1 = false;
        Ok(())
    }
    /// Stage-aware retry only before each unique hardware intent. Missing
    /// separately signed records do not replay a completed calibration.
    pub(in crate::rtlwifi) async fn provision_native(
        self: &Arc<Self>,
        op: super::envelope::Operating,
    ) -> Result<(), Error> {
        let phase = self.state.lock().await.phase;
        if matches!(phase, Phase::Allocated | Phase::InputsReady) {
            crate::future_heap::build(|| self.prepare_registered(op)).await?;
        }
        let phase = self.state.lock().await.phase;
        if phase == Phase::Prepared {
            crate::future_heap::build(|| self.prepare_station_transport()).await?;
        }
        let phase = self.state.lock().await.phase;
        if phase == Phase::RingsReady {
            crate::future_heap::build(|| self.activate_station()).await?;
        }
        if self.state.lock().await.phase == Phase::MacReady && self.registered_for(self.firmware())
        {
            Ok(())
        } else {
            Err(Error::State)
        }
    }

    /// Real original PacketIo -> retained DMA32 descriptor rings. NASR is
    /// loaded before the one-shot intent; absence is retryable, uncertainty
    /// after claim is not. BME/CR packet gates/IRQs stay closed throughout.
    pub(in crate::rtlwifi) async fn prepare_station_transport(
        self: &Arc<Self>,
    ) -> Result<(), Error> {
        let _admission = self.admission.lock().await;
        let binding = self.completed_binding().await?;
        let program = Program::registered(binding.clone())?;
        let domain = binding.current_domain()?;
        let grant = program.grant_for(&domain)?;
        let storage = self.transport.get().ok_or(Error::State)?.clone();
        if storage.lock().await.is_some() {
            return Err(Error::State);
        }
        // Allocate every policy/context object BEFORE taking the original port.
        let state = Box::new(State::with_live(
            program.clone(),
            grant,
            self.station_live.clone(),
        ));
        let port = self.claim_station_port(program.clone(), grant).await?;
        let mut prepared = crate::rtlwifi::prepare_native::allocate_ae_port(port, 128)?;
        prepared.adopt_rtl8723ae(state)?;
        // Shared storage owns the complete original port + every DMA page
        // before the first BAR base write. On cancellation it stays terminal.
        let result = program
            .wait(
                grant,
                crate::rtlwifi::prepare_native::prepare_retained(&storage, prepared),
            )
            .await;
        let mut retained = self.state.lock().await;
        let result = result.and_then(|_| {
            program.with_current(|| {
                if self.registered_for(self.firmware()) {
                    Ok(())
                } else {
                    Err(Error::State)
                }
            })
        });
        retained.phase = if result.is_ok() && self.registered_for(self.firmware()) {
            Phase::RingsReady
        } else {
            Phase::ResetOnly
        };
        result
    }
    pub(in crate::rtlwifi) async fn station_request(
        self: &Arc<Self>,
    ) -> Result<super::station_policy::Request, Error> {
        let binding = self.completed_binding().await?;
        Program::request(binding.as_ref())
    }
    pub(in crate::rtlwifi) async fn ht20_station_request(
        self: &Arc<Self>,
    ) -> Result<super::station_policy::Request, Error> {
        let binding = self.completed_binding().await?;
        Program::request_ht20(binding.as_ref())
    }
    pub(in crate::rtlwifi) async fn ht20_aspm_station_request(
        self: &Arc<Self>,
    ) -> Result<super::station_policy::Request, Error> {
        let binding = self.completed_binding().await?;
        Program::request_ht20_aspm(binding.as_ref())
    }
}
