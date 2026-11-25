// SPDX-License-Identifier: GPL-2.0-or-later
//! Registered RTL8723AE preparation, including actual native calibration.
//!
//! The registered PCI capsule owns every operation before its first poll.
//! Dropping a caller requests cancellation; the supervisor drains only the
//! current source stage under current authority. Failed or retired work is
//! retained indefinitely. There is no RF-stop, reset or reclaim receipt here.
use super::{
    checked::QualifiedIo,
    coex, cold_storage, envelope, factory, iqk, mac, phy,
    radio_policy::{ColdBinding, Program, QualifiedProgram, Request},
    retained::{Backend, Phase, Retained},
    txpower,
};
use crate::platform::lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use crate::rtlwifi::{
    firmware_transport::{Io, Stage as FirmwareStage},
    prepare::Error,
};
use alloc::{boxed::Box, sync::Arc};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};

/// Exact source stage retained by the original registered PCI owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Preflight,
    Identity,
    RfMain,
    Iqk,
    Lck,
    Pa,
    PowerChannel,
    Verify,
}
/// Terminal preparation state. Complete grants no station or packet access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Waiting,
    Running(Stage),
    Complete,
    CancelledBeforePoll,
    CancelledAfterStage(Stage),
    /// Pending helper state is retained; Ready(Err) may have destroyed local
    /// source backups. Neither case supplies recovery or reuse authority.
    ResetOnly {
        stage: Stage,
        helper_returned: bool,
    },
}

struct Cancel {
    requested: AtomicBool,
    driver: IrqSafeSpinLock<Option<Waker>>,
}
impl Default for Cancel {
    fn default() -> Self {
        Self {
            requested: AtomicBool::new(false),
            driver: IrqSafeSpinLock::new(None),
        }
    }
}
impl Cancel {
    fn request(&self) {
        self.requested.store(true, Ordering::Release);
        let wake = self.driver.lock().clone();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}
struct Completion {
    result: Option<Result<(), Error>>,
    observer: Option<Waker>,
}
type ResultSlot = Arc<IrqSafeSpinLock<Completion>>;

/// Source state independently retained even when a completed helper has
/// already dropped Backup while returning Err. No recovery claim is made.
struct Scratch {
    iqk: iqk::Owner,
    pa: factory::PaOwner,
    power: txpower::Owner,
    chnlval: u32,
    // Actual factory BT binding; no watchdog/mechanism or H2C is enabled by
    // this preparation-only grant. Linux bt_hw_init's 8723A dispatch is no-op.
    _coex: Option<Box<coex::Owner>>,
}
struct Resources<I: Backend> {
    root: Arc<Retained<I>>,
    io: Arc<QualifiedIo<I>>,
    inputs: Arc<factory::Inputs>,
    cold: cold_storage::Bound,
    op: envelope::Operating,
    scratch: Mutex<Scratch>,
}
type SourceFuture = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

pub(super) struct Work<I: Backend> {
    resources: Arc<Resources<I>>,
    stage: Stage,
    future: SourceFuture,
    cancel: Arc<Cancel>,
    result: ResultSlot,
    status: Status,
    polled: bool,
    completed: Option<Stage>,
}

/// Observation only: hardware work stays in the registered retained capsule.
struct Ticket<I: Backend> {
    _root: Arc<Retained<I>>,
    cancel: Arc<Cancel>,
    result: ResultSlot,
}
impl<I: Backend> Future for Ticket<I> {
    type Output = Result<(), Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut completion = self.result.lock();
        match completion.result {
            Some(result) => Poll::Ready(result),
            None => {
                completion.observer = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}
impl<I: Backend> Drop for Ticket<I> {
    fn drop(&mut self) {
        self.cancel.request();
    }
}

impl<I: Backend> Work<I> {
    pub(super) fn matches_binding(&self, binding: &Binding) -> bool {
        let source: Arc<dyn LivePreparation> = self.resources.clone();
        self.status == Status::Complete && Arc::ptr_eq(&source, &binding.keep)
    }
    fn new(resources: Arc<Resources<I>>) -> Self {
        let future = source_stage(resources.clone(), Stage::Preflight);
        Self {
            resources,
            stage: Stage::Preflight,
            future,
            cancel: Arc::new(Cancel::default()),
            result: Arc::new(IrqSafeSpinLock::new(Completion {
                result: None,
                observer: None,
            })),
            status: Status::Waiting,
            polled: false,
            completed: None,
        }
    }
    fn finish(&mut self, status: Status, result: Result<(), Error>) -> Poll<Result<(), Error>> {
        self.status = status;
        let wake = {
            let mut completion = self.result.lock();
            completion.result = Some(result);
            completion.observer.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
        // Never take/drop future or Resources here, including Ready(Err).
        Poll::Ready(result)
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if let Some(result) = self.result.lock().result {
            return Poll::Ready(result);
        }
        *self.cancel.driver.lock() = Some(cx.waker().clone());
        if self.cancel.requested.load(Ordering::Acquire) && !self.polled {
            let status = self
                .completed
                .map_or(Status::CancelledBeforePoll, Status::CancelledAfterStage);
            return self.finish(status, Err(Error::State));
        }
        self.status = Status::Running(self.stage);
        // The actual resumed poll is inside current firmware/NAPC/NAQR/PCI;
        // each register access independently checks the same sources again.
        self.polled = true;
        let result = self.resources.io.poll(self.future.as_mut(), cx);
        match result {
            Err(error) => self.finish(
                Status::ResetOnly {
                    stage: self.stage,
                    helper_returned: false,
                },
                Err(error),
            ),
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(Err(error))) => self.finish(
                Status::ResetOnly {
                    stage: self.stage,
                    helper_returned: true,
                },
                Err(error),
            ),
            Ok(Poll::Ready(Ok(()))) => {
                if self.cancel.requested.load(Ordering::Acquire) {
                    return self.finish(Status::CancelledAfterStage(self.stage), Err(Error::State));
                }
                let next = match self.stage {
                    Stage::Preflight => Stage::Identity,
                    Stage::Identity => Stage::RfMain,
                    Stage::RfMain => Stage::Iqk,
                    Stage::Iqk => Stage::Lck,
                    Stage::Lck => Stage::Pa,
                    Stage::Pa => Stage::PowerChannel,
                    Stage::PowerChannel => Stage::Verify,
                    Stage::Verify => return self.finish(Status::Complete, Ok(())),
                };
                self.completed = Some(self.stage);
                self.stage = next;
                self.future = source_stage(self.resources.clone(), next);
                self.polled = false;
                // Do not continue into another source stage in this poll.
                // Cancellation at this boundary starts no new helper.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) async fn fixture(
        root: Arc<Retained<I>>,
        program: Arc<QualifiedProgram>,
        database: Arc<crate::platform::regdb::Database>,
        op: envelope::Operating,
    ) -> Result<Self, Error> {
        let state = root.state.lock().await;
        if state.phase != Phase::InputsReady {
            return Err(Error::State);
        }
        let inputs = state.factory.inputs().ok_or(Error::State)?;
        let identity = state.identity.ok_or(Error::State)?;
        let cold = root.cold.bound()?;
        let io = QualifiedIo::bind_fixture(root.clone(), identity, program, database)?;
        let chnlval = cold.chnlval()[0];
        drop(state);
        Ok(Self::new(Arc::new(Resources {
            root,
            io,
            op,
            cold,
            scratch: Mutex::new(Scratch {
                iqk: iqk::Owner::new(),
                pa: factory::PaOwner::default(),
                power: txpower::Owner::new(),
                chnlval,
                _coex: Some(Box::new(coex::Owner::bind(&inputs.adapter().bt))),
            }),
            inputs,
        })))
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn cancel_fixture(&self) {
        self.cancel.request();
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn status_fixture(&self) -> Status {
        self.status
    }
}

#[inline(never)]
fn source_stage<I: Backend>(r: Arc<Resources<I>>, stage: Stage) -> SourceFuture {
    Box::pin(async move {
        let io = &*r.io;
        match stage {
            Stage::Preflight => {
                parked(io)?;
                if r.cold.chnlval()[0] != 0xf401
                    || phy::get_rf(io, phy::Path::A, 0x18, phy::RFREG_OFFSET_MASK).await?
                        != r.cold.chnlval()[0]
                    || io.read8(0x603)? & 4 == 0
                    || phy::get_bb(io, 0x800, 1)? != 0
                    || phy::get_bb(io, 0x900, 1)? != 0
                    || phy::get_bb(io, 0x884, 1 << 10)? != 1
                {
                    return Err(Error::Readback);
                }
            }
            Stage::Identity => {
                mac::station_identity(io, &r.inputs.factory().mac)?;
                // PCIe ASPM remains disabled under the original parked
                // backend; no guessed support_backdoor/link policy is applied.
                // btc_init_hw_config explicitly has an empty 8723A branch.
            }
            Stage::RfMain => phy::rfpath_switch_main(io)?,
            Stage::Iqk => {
                let mut scratch = r.scratch.lock().await;
                scratch.iqk.run(io).await?;
                let report = scratch.iqk.report().ok_or(Error::RadioOff)?;
                if report.candidate == 0xff || report.e94 == 0 {
                    return Err(Error::RadioOff);
                }
            }
            // dm_check_txpower_tracking is a literal no-op on this chip.
            Stage::Lck => phy::lc_calibrate(io).await?,
            Stage::Pa => {
                let mut scratch = r.scratch.lock().await;
                let physical = r.io.factory();
                // SAFETY: original registered Resources and PA owner remain
                // retained through every error/drop/removal. ACCESS0 cleanup
                // independently invokes current original PCI authority.
                let pa = unsafe { scratch.pa.acquire(&physical) }.map_err(|_| Error::State)?;
                if pa != r.inputs.pa() {
                    return Err(Error::Readback);
                }
                // Exact rtl8723ae/hw.c:1004..1016 source order and widths.
                if pa & 1 == 0 {
                    phy::set_rf(io, phy::Path::A, 0x15, 0xf, 5).await?;
                }
                if pa & 0x10 == 0 {
                    let value = io.read8(0x16)?;
                    if value == u8::MAX {
                        return Err(Error::Access(
                            crate::rtlwifi::firmware_transport::Error::Gone,
                        ));
                    }
                    let low = value & 0xf;
                    io.write8(0x16, low | 0x80)?;
                    io.delay_us(10).await;
                    io.write8(0x16, low | 0x90)?;
                }
                // DM software defaults do not enable dynamic power, thermal
                // tracking, RF-saving or coexistence hardware programs.
            }
            Stage::PowerChannel => {
                let mut scratch = r.scratch.lock().await;
                let plan = r.io.grant().plan();
                scratch.power.program(io, plan)?;
                plan.verify(io)?;
                let (forty, side, channel) = match r.op.width {
                    envelope::Width::W20 => (false, 0, r.op.channel),
                    envelope::Width::W40Above => (true, 1, r.op.channel + 2),
                    envelope::Width::W40Below => (true, 2, r.op.channel - 2),
                };
                phy::sw_chnl_rf(io, r.cold.version(), &mut scratch.chnlval, channel, forty).await?;
                phy::set_bw_mode(io, &mut scratch.chnlval, forty, side).await?;
            }
            Stage::Verify => {
                parked(io)?;
                r.io.grant().plan().verify(io)?;
                let scratch = r.scratch.lock().await;
                let actual = phy::get_rf(io, phy::Path::A, 0x18, phy::RFREG_OFFSET_MASK).await?;
                if actual & 0xfff != scratch.chnlval & 0xfff
                    || (io.read8(0x603)? & 4 != 0) != (r.op.width == envelope::Width::W20)
                    || phy::get_bb(io, 0x800, 1)? != u32::from(r.op.width != envelope::Width::W20)
                    || phy::get_bb(io, 0x900, 1)? != u32::from(r.op.width != envelope::Width::W20)
                    || phy::get_bb(io, 0x884, 1 << 10)?
                        != u32::from(r.op.width == envelope::Width::W20)
                {
                    return Err(Error::Readback);
                }
            }
        }
        Ok(())
    })
}
fn parked(io: &impl Io) -> Result<(), Error> {
    let cr = io.read8(0x100)?;
    if cr == u8::MAX
        || cr & 0xcf != 0
        || io.read32(super::irq::MASK0)? != 0
        || io.read32(super::irq::MASK1)? != 0
        || io.read8(0x680)? != 0
    {
        return Err(Error::Readback);
    }
    Ok(())
}

impl<I: Backend> Retained<I> {
    async fn ensure_inputs(self: &Arc<Self>) -> Result<(), Error> {
        if !self.registered_for(self.firmware()) {
            return Err(Error::State);
        }
        match self.firmware().status().stage {
            FirmwareStage::Detected => {
                self.firmware().initialize_registered().await?;
            }
            FirmwareStage::Ready => (),
            _ => return Err(Error::State),
        }
        let phase = self.state.lock().await.phase;
        match phase {
            Phase::Allocated => {
                self.acquire_factory().await?;
            }
            Phase::InputsReady => (),
            _ => return Err(Error::State),
        }
        Ok(())
    }
    async fn program(self: &Arc<Self>, op: envelope::Operating) -> Result<Program, Error> {
        self.ensure_inputs().await?;
        let (inputs, identity, cold) = {
            let state = self.state.lock().await;
            if state.phase != Phase::InputsReady {
                return Err(Error::State);
            }
            (
                state.factory.inputs().ok_or(Error::State)?,
                state.identity.ok_or(Error::State)?,
                self.cold.bound()?,
            )
        };
        let base = Arc::new(
            envelope::Calibration::load_registered(self.expected()).map_err(Error::Power)?,
        );
        Program::bind(
            inputs,
            base,
            identity,
            Arc::new(ColdBinding::from_native(cold)),
            op,
        )
    }
    /// Loads real cold/factory inputs and the base NAPC; returns only the
    /// exact companion name/binding needed for independent measurement/signing.
    pub(in crate::rtlwifi) async fn native_request(
        self: &Arc<Self>,
        op: envelope::Operating,
    ) -> Result<Request, Error> {
        let _admission = self.admission.lock().await;
        let program = self.program(op).await?;
        let identity = self.firmware().identity().ok_or(Error::State)?;
        self.current(identity, |_| Ok(()))?;
        Ok(program.request())
    }
    pub(in crate::rtlwifi) async fn prepare_registered(
        self: &Arc<Self>,
        op: envelope::Operating,
    ) -> Result<(), Error> {
        let _admission = self.admission.lock().await;
        let program = self.program(op).await?;
        let program = Arc::new(QualifiedProgram::registered(program)?);
        let domain = crate::platform::regdb::snapshot().ok_or(Error::State)?;
        let (inputs, identity, cold) = {
            let state = self.state.lock().await;
            if state.phase != Phase::InputsReady || state.work.is_some() {
                return Err(Error::State);
            }
            (
                state.factory.inputs().ok_or(Error::State)?,
                state.identity.ok_or(Error::State)?,
                self.cold.bound()?,
            )
        };
        let io = QualifiedIo::bind(self.clone(), identity, program, domain)?;
        let chnlval = cold.chnlval()[0];
        let resources = Arc::new(Resources {
            root: self.clone(),
            io,
            op,
            cold,
            scratch: Mutex::new(Scratch {
                iqk: iqk::Owner::new(),
                pa: factory::PaOwner::default(),
                power: txpower::Owner::new(),
                chnlval,
                _coex: Some(Box::new(coex::Owner::bind(&inputs.adapter().bt))),
            }),
            inputs,
        });
        let work = Work::new(resources);
        let ticket = Ticket {
            _root: self.clone(),
            cancel: work.cancel.clone(),
            result: work.result.clone(),
        };
        {
            let mut state = self.state.lock().await;
            if state.phase != Phase::InputsReady
                || state.work.is_some()
                || !self.registered_for(self.firmware())
            {
                return Err(Error::State);
            }
            state.phase = Phase::Calibrating;
            // All original resources and the source future are owned by the
            // registered preallocated capsule BEFORE spawn/first hardware poll.
            state.work = Some(work);
        }
        let root = self.clone();
        crate::platform::scheduler::spawn(async move {
            let _ = core::future::poll_fn(|cx| root.poll_preparation(cx)).await;
        });
        ticket.await
    }
    pub(super) fn poll_preparation(&self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let Some(mut state) = self.state.try_lock() else {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };
        let Some(work) = state.work.as_mut() else {
            return Poll::Ready(Err(Error::State));
        };
        let result = work.poll(cx);
        if let Poll::Ready(result) = result {
            state.phase = if result.is_ok() {
                Phase::Prepared
            } else {
                Phase::ResetOnly
            };
        }
        result
    }
    pub(in crate::rtlwifi) fn preparation_status(&self) -> Status {
        self.state
            .try_lock()
            .and_then(|state| state.work.as_ref().map(|work| work.status))
            .unwrap_or(Status::Waiting)
    }
    pub(in crate::rtlwifi) fn can_retry(&self) -> bool {
        self.registered_for(self.firmware())
            && matches!(
                self.firmware().status().stage,
                FirmwareStage::Detected | FirmwareStage::Ready
            )
            && self.state.try_lock().is_some_and(|state| {
                matches!(
                    state.phase,
                    Phase::Allocated | Phase::InputsReady | Phase::Prepared | Phase::RingsReady
                )
            })
    }
}

/// Private actual-operation gate retained with the original source context.
/// Erasure does not create a second backend or an arbitrary RF callback API.
trait LivePreparation: Send + Sync {
    fn invoke(&self, operation: &mut dyn FnMut() -> Result<(), Error>) -> Result<(), Error>;
    fn domain(&self) -> Result<Arc<narf_wireless::reg::RegulatoryDomain>, Error>;
    fn transfer_coex<'a>(
        &'a self,
        target: &'a mut Option<Box<coex::Owner>>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;
}
impl<I: Backend> LivePreparation for Resources<I> {
    fn transfer_coex<'a>(
        &'a self,
        target: &'a mut Option<Box<coex::Owner>>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>> {
        Box::pin(async move {
            if target.is_some() {
                return Err(Error::State);
            }
            let mut scratch = self.scratch.lock().await;
            // Revalidate AFTER the async lock. Moving the exact Box into the
            // already-retained Prepared has no following suspension point.
            self.io.invoke(|_| {
                if target.is_some() {
                    return Err(crate::rtlwifi::firmware_transport::Error::Gate);
                }
                *target = Some(
                    scratch
                        ._coex
                        .take()
                        .ok_or(crate::rtlwifi::firmware_transport::Error::Gate)?,
                );
                Ok(())
            })
        })
    }
    fn domain(&self) -> Result<Arc<narf_wireless::reg::RegulatoryDomain>, Error> {
        self.io.current_domain()
    }
    fn invoke(&self, operation: &mut dyn FnMut() -> Result<(), Error>) -> Result<(), Error> {
        let mut result = None;
        self.io.invoke(|_| {
            result = Some(operation());
            Ok(())
        })?;
        result.ok_or(Error::State)?
    }
}
/// Sealed successful native calibration history and its actual retained
/// current-operation gate. No public constructor, guessed history or clone
/// of the original cold owner/PG. This is not station admission on its own.
pub(in crate::rtlwifi) struct Binding {
    keep: Arc<dyn LivePreparation>,
    program: Arc<QualifiedProgram>,
    cold: cold_storage::Bound,
    iqk: iqk::Report,
    pa: u8,
    grant: super::radio_policy::PowerGrant,
}
impl Binding {
    pub(in crate::rtlwifi) async fn transfer_coex(
        &self,
        target: &mut Option<Box<coex::Owner>>,
    ) -> Result<(), Error> {
        self.keep.transfer_coex(target).await
    }
    pub(in crate::rtlwifi) fn current_domain(
        &self,
    ) -> Result<Arc<narf_wireless::reg::RegulatoryDomain>, Error> {
        self.keep.domain()
    }
    pub(in crate::rtlwifi) fn receive_config(&self) -> u32 {
        self.cold.receive_config()
    }
    pub(in crate::rtlwifi) fn cck_high_power(&self) -> bool {
        self.cold.cck_high_power()
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut operation = Some(operation);
        let mut output = None;
        self.keep.invoke(&mut || {
            output = Some(operation.take().ok_or(Error::State)?()?);
            Ok(())
        })?;
        output.ok_or(Error::State)
    }
    pub(super) fn operating(&self) -> envelope::Operating {
        self.program.operating()
    }
    pub(in crate::rtlwifi) fn factory(&self) -> &crate::rtlwifi::efuse::Factory {
        self.program.inputs().factory()
    }
    pub(in crate::rtlwifi) fn adapter(&self) -> &super::adapter::Adapter {
        self.program.inputs().adapter()
    }
    pub(super) fn base(&self) -> &envelope::Calibration {
        self.program.base()
    }
    pub(super) fn napc_digest(&self) -> [u8; 32] {
        self.program.base().digest
    }
    pub(super) fn naqr_digest(&self) -> [u8; 32] {
        self.program.measurement()
    }
    pub(super) fn firmware(&self) -> crate::rtlwifi::firmware_transport::Identity {
        self.program.firmware()
    }
    pub(super) fn antenna(&self) -> i16 {
        self.program.antenna()
    }
    pub(super) fn source_plan(&self) -> Result<txpower::Plan, Error> {
        self.program.source_plan()
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(b"AE actual retained preparation completion v1");
        h.update(&self.cold.digest());
        h.update(&self.naqr_digest());
        h.update(&self.napc_digest());
        h.update(&self.firmware().digest);
        h.update(&[self.pa, self.iqk.candidate]);
        h.update(&self.receive_config().to_le_bytes());
        h.update(&[u8::from(self.cck_high_power())]);
        for value in self.iqk.result.iter().flatten() {
            h.update(&value.to_le_bytes());
        }
        for value in [self.iqk.e94, self.iqk.e9c, self.iqk.eb4, self.iqk.ebc] {
            h.update(&value.to_le_bytes());
        }
        for value in self.iqk.bb_backup {
            h.update(&value.to_le_bytes());
        }
        for row in self.grant.plan().ofdm_words() {
            for value in row {
                h.update(&value.to_le_bytes());
            }
        }
        for value in self.grant.plan().cck_words() {
            h.update(&value.to_le_bytes());
        }
        h.finalize()
    }
}
impl<I: Backend> Retained<I> {
    pub(super) async fn completed_binding(self: &Arc<Self>) -> Result<Arc<Binding>, Error> {
        let state = self.state.lock().await;
        let work = state.work.as_ref().ok_or(Error::State)?;
        if state.phase != Phase::Prepared
            || work.status != Status::Complete
            || !Arc::ptr_eq(&work.resources.root, self)
        {
            return Err(Error::State);
        }
        let r = &work.resources;
        let scratch = r.scratch.lock().await;
        let iqk = *scratch.iqk.report().ok_or(Error::State)?;
        let pa = scratch.pa.observed().ok_or(Error::State)?;
        if iqk.candidate == 0xff
            || iqk.e94 == 0
            || pa != r.inputs.pa()
            || scratch.pa.cleanup_receipt().is_none()
        {
            return Err(Error::State);
        }
        r.io.invoke(|_| Ok(()))?;
        Ok(Arc::new(Binding {
            keep: r.clone(),
            program: r.io.program().clone(),
            cold: r.cold.clone(),
            iqk,
            pa,
            grant: r.io.grant().clone(),
        }))
    }
}
