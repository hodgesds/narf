//! Driver-local physical global-reset availability and retained recovery policy.
//!
//! A positive publication requires this coordinator's real private-PPGTT store
//! and terminal retirement on every published engine. Neither UserStatus, a
//! successful stop, nor a caller-supplied fence can manufacture that proof.
//! Hardware access, diagnostics, IRQ closure, display quarantine and PCI/PM
//! remain with the enclosing physical owner. In particular poll never starts
//! reset: the owner must finish its fault snapshot before begin_cleanup.

use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_engine::{Engine, EngineSet},
    intel_gpu_exec::PpgttProbeSubmission,
    intel_gpu_gt::GtPlatform,
    intel_gpu_guc_boot::BootAllocator,
    intel_gpu_guc_gt::{GtError, GtState, GuCGt},
};
use alloc::sync::Arc;
use core::{
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
};
use narf_lib::sync::IrqSafeSpinLock;

type Identity = (GtPlatform, EngineSet, u64);

#[derive(Debug)]
struct Cached {
    serial: u64,
    worker: u64,
    active: bool,
    exhausted: bool,
    ready_epoch: u64,
    /// Set only by Ready::publish; survives fault withdrawal until Cold.
    published: bool,
}
impl Cached {
    fn advance(&mut self) {
        self.ready_epoch = 0;
        match self.serial.checked_add(1) {
            Some(serial) => self.serial = serial,
            None => self.exhausted = true,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Publication {
    platform: GtPlatform,
    cached: IrqSafeSpinLock<Cached>,
}
impl Publication {
    pub(crate) fn new(platform: GtPlatform) -> Self {
        Self {
            platform,
            cached: IrqSafeSpinLock::new(Cached {
                serial: 0,
                worker: 0,
                active: false,
                exhausted: false,
                ready_epoch: 0,
                published: false,
            }),
        }
    }

    /// Passive last-observed availability. Current authority remains mandatory
    /// on every actual register action, and cannot be sampled by this getter.
    pub(crate) fn epoch(&self, platform: GtPlatform, user_epoch: u64) -> Option<u64> {
        let cached = self.cached.lock();
        (platform == self.platform
            && platform.guc().is_some()
            && cached.active
            && !cached.exhausted
            && user_epoch != 0
            && cached.ready_epoch == user_epoch)
            .then_some(user_epoch)
    }

    pub(crate) fn withdraw(&self) {
        self.cached.lock().advance();
    }

    pub(crate) fn worker(self: &Arc<Self>, user_epoch: Arc<AtomicU64>) -> Result<Worker, GtError> {
        let mut cached = self.cached.lock();
        if cached.active || cached.exhausted {
            return Err(GtError::State);
        }
        let worker = cached.worker.checked_add(1).ok_or(GtError::State)?;
        cached.advance();
        if cached.exhausted {
            return Err(GtError::State);
        }
        cached.worker = worker;
        cached.active = true;
        cached.published = false;
        Ok(Worker {
            publication: self.clone(),
            user_epoch,
            worker,
        })
    }

    fn ticket(&self) -> Result<(u64, u64), GtError> {
        let cached = self.cached.lock();
        if !cached.active || cached.exhausted {
            return Err(GtError::State);
        }
        Ok((cached.serial, cached.worker))
    }
}

/// Cancellation only closes cached admission. The retained Owner/GuCGt graph
/// still owns DMA; Drop performs no MMIO, waits or reclaim of an exposed graph.
#[must_use]
pub(crate) struct Worker {
    publication: Arc<Publication>,
    user_epoch: Arc<AtomicU64>,
    worker: u64,
}
impl Drop for Worker {
    fn drop(&mut self) {
        let mut cached = self.publication.cached.lock();
        if cached.active && cached.worker == self.worker {
            cached.advance();
            cached.active = false;
            self.user_epoch.store(0, Ordering::Release);
        }
    }
}

struct Probes {
    identity: Identity,
    ticket: (u64, u64),
    engine: Engine,
    owned: PpgttProbeSubmission,
}
struct Qualified {
    identity: Identity,
    ticket: (u64, u64),
}

/// Non-Copy, privately constructed proof consumed at the owner's final commit.
/// Invalidation and publication serialize under a metadata-only lock; no
/// callback or owned hardware graph is dropped while that lock is held.
pub(crate) struct Ready {
    publication: Arc<Publication>,
    ticket: (u64, u64),
    epoch: u64,
}
impl Ready {
    pub(crate) fn publish(self) -> Result<(), GtError> {
        let mut cached = self.publication.cached.lock();
        if !cached.active
            || cached.exhausted
            || self.epoch == 0
            || self.ticket != (cached.serial, cached.worker)
        {
            return Err(GtError::State);
        }
        cached.ready_epoch = self.epoch;
        cached.published = true;
        Ok(())
    }
}

pub(crate) struct Coordinator {
    publication: Arc<Publication>,
    probes: Option<Probes>,
    qualified: Option<Qualified>,
    cleaning: bool,
    restart: bool,
}
impl Coordinator {
    pub(crate) fn new(publication: Arc<Publication>) -> Self {
        Self {
            publication,
            probes: None,
            qualified: None,
            cleaning: false,
            restart: false,
        }
    }

    /// A fresh upload must execute every probe again. Cold never qualifies
    /// itself, and an initial/requalification failure cannot inherit retry.
    pub(crate) fn cold(&mut self) {
        self.fault();
        self.publication.cached.lock().published = false;
        self.cleaning = false;
        self.restart = false;
    }

    /// Withdraw at the observed fault before diagnostics or hardware cleanup.
    pub(crate) fn fault(&mut self) {
        self.publication.withdraw();
        if self.cleaning {
            // A fault during cleanup cannot authorize another automatic
            // restart, even if an independent later stop proves retirement.
            self.restart = false;
        }
        self.probes = None;
        self.qualified = None;
    }

    pub(crate) fn poll<M: MmioWindow, A: BootAllocator>(
        &mut self,
        gt: &mut GuCGt<M, A>,
        now: u64,
        current: impl FnMut() -> bool,
    ) -> Poll<Result<GtState, GtError>> {
        let result = gt.poll_with_access(now, current);
        if matches!(result, Poll::Ready(Err(_))) {
            self.fault();
        }
        result
    }

    pub(crate) fn begin_qualification<M: MmioWindow, A: BootAllocator>(
        &mut self,
        gt: &mut GuCGt<M, A>,
        now: u64,
    ) -> Result<(), GtError> {
        self.fault();
        let ticket = self.publication.ticket()?;
        let identity = gt.recovery_identity().ok_or(GtError::State)?;
        if identity.0 != self.publication.platform {
            return Err(GtError::State);
        }
        let engine = identity.1.iter().next().ok_or(GtError::State)?;
        let owned = gt.submit_ppgtt_probe_on(now, engine)?;
        self.probes = Some(Probes {
            identity,
            ticket,
            engine,
            owned,
        });
        Ok(())
    }

    pub(crate) fn advance_qualification<M: MmioWindow, A: BootAllocator>(
        &mut self,
        gt: &mut GuCGt<M, A>,
        now: u64,
    ) -> Result<bool, GtError> {
        let probes = self.probes.as_ref().ok_or(GtError::State)?;
        if gt.recovery_identity() != Some(probes.identity)
            || self.publication.ticket()? != probes.ticket
        {
            return Err(GtError::State);
        }
        let Some(result) = probes.owned.completion.result() else {
            return Ok(false);
        };
        result.map_err(|_| GtError::State)?;
        probes.owned.result.verify().map_err(|_| GtError::State)?;
        let next = super::next_probe_engine(probes.identity.1, probes.engine)
            .map_err(|_| GtError::State)?;
        if let Some(engine) = next {
            let owned = gt.submit_ppgtt_probe_on(now, engine)?;
            let probes = self.probes.as_mut().expect("owned qualification");
            probes.engine = engine;
            probes.owned = owned;
            return Ok(false);
        }
        let probes = self.probes.take().expect("owned qualification");
        self.qualified = Some(Qualified {
            identity: probes.identity,
            ticket: probes.ticket,
        });
        Ok(true)
    }

    /// Read-only observation of the actual retained qualification submission.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn pending_probe(&self) -> Option<(Engine, &PpgttProbeSubmission)> {
        self.probes
            .as_ref()
            .map(|probes| (probes.engine, &probes.owned))
    }

    /// Final metadata check after HuC/MERT/display and parked-epoch adoption.
    /// Upload identity is independent of the deliberately adopted user epoch.
    pub(crate) fn ready<M: MmioWindow, A: BootAllocator>(
        &mut self,
        gt: &GuCGt<M, A>,
    ) -> Result<Ready, GtError> {
        let qualified = self.qualified.take().ok_or(GtError::State)?;
        if gt.recovery_identity() != Some(qualified.identity)
            || self.publication.ticket()? != qualified.ticket
        {
            return Err(GtError::State);
        }
        Ok(Ready {
            publication: self.publication.clone(),
            ticket: qualified.ticket,
            epoch: gt
                .user_epoch()
                .filter(|epoch| *epoch != 0)
                .ok_or(GtError::State)?,
        })
    }

    /// Shared cached park admission. The physical owner first checks phase,
    /// system sleep, PM policy and its VRAM alias restriction. Busy/refused
    /// requests leave the live qualified publication untouched.
    pub(crate) fn accept_park<M: MmioWindow, A: BootAllocator>(
        &mut self,
        gt: &GuCGt<M, A>,
        epoch: u64,
    ) -> Result<(u64, EngineSet, (u8, u8)), GtError> {
        if epoch == 0 || !gt.idle() {
            return Err(GtError::Busy);
        }
        let identity = gt.recovery_identity().ok_or(GtError::State)?;
        if gt.user_epoch() != Some(epoch)
            || self.publication.epoch(identity.0, epoch) != Some(epoch)
        {
            return Err(GtError::State);
        }
        let compute = gt.compute_configuration().ok_or(GtError::State)?;
        self.fault();
        Ok((epoch, identity.1, compute))
    }

    /// Owner calls only after IRQ shutdown, diagnostic snapshot, admission
    /// closure and display quarantine. A failed cleanup cannot retry or free
    /// uncertain DMA. Restart authority comes solely from a prior Ready commit.
    pub(crate) fn begin_cleanup<M: MmioWindow, A: BootAllocator>(
        &mut self,
        gt: &mut GuCGt<M, A>,
        now: u64,
    ) -> Result<bool, GtError> {
        self.fault();
        if self.cleaning || matches!(gt.state(), GtState::Staged | GtState::Stopped) {
            return Ok(false);
        }
        self.restart = self.publication.cached.lock().published;
        gt.begin_stop(now)?;
        self.cleaning = true;
        Ok(true)
    }

    /// An accepted CCS transaction already called real begin_stop after its
    /// owner callback. Refused/busy requests never reach this method.
    pub(crate) fn adopted_stop<M: MmioWindow, A: BootAllocator>(
        &mut self,
        gt: &GuCGt<M, A>,
    ) -> Result<(), GtError> {
        if matches!(
            gt.state(),
            GtState::Staged | GtState::Stopped | GtState::SchedulingReady
        ) {
            return Err(GtError::State);
        }
        self.restart = self.publication.cached.lock().published;
        self.cleaning = true;
        Ok(())
    }

    /// The only automatic Cold decision; actual GuCGt owns full reset, DMA
    /// idle and all cache/media handoffs before exposing Stopped.
    pub(crate) fn after_stop<M: MmioWindow, A: BootAllocator>(
        &mut self,
        gt: &GuCGt<M, A>,
    ) -> Result<bool, GtError> {
        if !self.cleaning || gt.state() != GtState::Stopped {
            return Err(GtError::State);
        }
        self.cleaning = false;
        let restart = self.restart;
        self.restart = false;
        Ok(restart)
    }
}
