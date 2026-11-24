//! Execlists GT owner for Gen9 (Skylake .. Comet Lake) and Gen11 (Ice,
//! Elkhart and Jasper Lake): the render backend Linux's default i915
//! configuration runs on these parts, with no GuC submission.
//!
//! Bring-up follows MIT Linux v6.12 `gt/intel_reset.c` (`gen8_reset_engines`
//! with a full-domain `GEN6_GDRST`), `intel_gt_init_hw` (GT workarounds,
//! `gtt_write_workarounds`, private PPAT, L3 MOCS) and the engine resume
//! path (`intel_engine_apply_workarounds`, `intel_engine_apply_whitelist`,
//! `intel_mocs_init_engine`, `enable_execlists`), using the tables in
//! [`crate::intel_gpu_legacy_gt`]. Submission runs on
//! [`crate::intel_gpu_rcs::RcsEngine`]: one hardware context per user
//! context, the context workarounds loaded ahead of its first request.
//!
//! What this owner does not do yet, and Linux does: RC6 and frequency
//! management (it keeps render and GT forcewake held), preemption and
//! timeslicing (one engine load at a time), per-engine reset (a hang or
//! lost completion resets the whole GT and bans the contexts involved), the
//! Gen9 golden render state (`intel_renderstate`), and engines other than
//! RCS0.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Poll;

use narf_filesystem::{FsError, FsFuture};
use narf_lib::mutex::Mutex;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_fence::CompletionFence;
use crate::intel_gpu_forcewake::{Forcewake, FwDomain};
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_legacy_gt::{
    ctx_workarounds, engine_mocs_writes, gt_workarounds, gtt_workarounds, l3cc_writes, ppat_writes,
    rcs_whitelist, rcs_workarounds, whitelist_writes, LegacyGt, Steering, WaList, WaPlatform,
    MCR_SELECTOR,
};
use crate::intel_gpu_legacy_power::{
    rc6_disable, rc6_enable, rc6_park, rc6_unpark, rps_enable, rps_request, Caps, Governor, Step,
};
use crate::intel_gpu_rcs::{BarWindow, ContextId, RcsEngine, SharedArena, SubmitError};
use crate::intel_gpu_user::{UserBackend, UserBatch, UserContext, UserJob, UserStatus};

// ── Reset (`gen8_reset_engines`, ALL_ENGINES) ───────────────────────

/// RCS0 `RING_MI_MODE`.
const MI_MODE: u64 = 0x209c;
const MODE_IDLE: u32 = 1 << 9;
const STOP_RING: u32 = 1 << 8;
/// RCS0 `RING_RESET_CTL`.
const RESET_CTL: u64 = 0x20d0;
const REQUEST_RESET: u32 = 1 << 0;
const READY_TO_RESET: u32 = 1 << 1;
/// `GEN6_GDRST`; `GEN6_GRDOM_FULL` / `GEN11_GRDOM_FULL` is bit 0 on both.
const GDRST: u64 = 0x941c;
const GRDOM_FULL: u32 = 1;

const fn masked_enable(bits: u32) -> u32 {
    bits << 16 | bits
}
const fn masked_disable(bits: u32) -> u32 {
    bits << 16
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum InitError {
    /// A register read all-ones: the function is gone or powered down.
    Unavailable,
    /// The full-domain reset did not self-clear.
    ResetTimeout,
    /// The slice/subslice fuses report nothing enabled.
    Fuses,
    Forcewake,
    Engine(SubmitError),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ResetPhase {
    Start,
    Stopping,
    Preparing,
    Resetting,
}

/// A full GT reset as `__intel_gt_reset(gt, ALL_ENGINES)` performs it on
/// execlists: stop the command streamer (`intel_engine_stop_cs`, 1 ms),
/// request the engine reset handshake (`gen8_engine_reset_prepare`, 700 us;
/// Linux retries without it), pulse the full domain (`gen6_hw_domain_reset`,
/// 500 ms) and cancel the handshake. Forcewake must be held throughout.
#[derive(Debug)]
pub(crate) struct Reset {
    phase: ResetPhase,
    deadline: u64,
}

impl Reset {
    pub(crate) const fn new() -> Self {
        Self {
            phase: ResetPhase::Start,
            deadline: 0,
        }
    }

    pub(crate) fn poll(&mut self, mmio: &impl MmioWindow, now: u64) -> Poll<Result<(), InitError>> {
        match self.phase {
            ResetPhase::Start => {
                if mmio.read32(MI_MODE) == u32::MAX {
                    return Poll::Ready(Err(InitError::Unavailable));
                }
                mmio.write32(MI_MODE, masked_enable(STOP_RING));
                self.phase = ResetPhase::Stopping;
                self.deadline = now + 1_000_000;
                Poll::Pending
            }
            ResetPhase::Stopping => {
                // A CS that will not idle is reset anyway, as Linux does.
                if mmio.read32(MI_MODE) & MODE_IDLE == 0 && now < self.deadline {
                    return Poll::Pending;
                }
                mmio.write32(RESET_CTL, masked_enable(REQUEST_RESET));
                self.phase = ResetPhase::Preparing;
                self.deadline = now + 700_000;
                Poll::Pending
            }
            ResetPhase::Preparing => {
                if mmio.read32(RESET_CTL) & READY_TO_RESET == 0 && now < self.deadline {
                    return Poll::Pending;
                }
                mmio.write32(GDRST, GRDOM_FULL);
                self.phase = ResetPhase::Resetting;
                self.deadline = now + 500_000_000;
                Poll::Pending
            }
            ResetPhase::Resetting => {
                let status = mmio.read32(GDRST);
                if status == u32::MAX {
                    return Poll::Ready(Err(InitError::Unavailable));
                }
                if status & GRDOM_FULL != 0 {
                    if now < self.deadline {
                        return Poll::Pending;
                    }
                    mmio.write32(RESET_CTL, masked_disable(REQUEST_RESET));
                    return Poll::Ready(Err(InitError::ResetTimeout));
                }
                mmio.write32(RESET_CTL, masked_disable(REQUEST_RESET));
                Poll::Ready(Ok(()))
            }
        }
    }
}

// ── Programming (`intel_gt_init_hw` + RCS resume) ───────────────────

/// What GT programming observed. Linux only warns about both.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Programmed {
    /// Workaround registers whose verified bits did not stick.
    pub(crate) lost: Vec<u64>,
    /// `RING_ESR` still set after the error registers were cleared
    /// ("engine resumed still in error").
    pub(crate) error_status: u32,
}

/// RCS0 base.
const RCS: u64 = 0x2000;

fn apply(list: &WaList, mmio: &impl MmioWindow, steering: Steering, lost: &mut Vec<u64>) {
    // rw_with_mcr_steering_fw: an L3BANK read on Ice Lake is steered to a
    // live bank and the default steering restored.
    let read = |reg: u64| match steering.l3bank_read_selector(reg) {
        Some(selector) => {
            let old = mmio.read32(MCR_SELECTOR);
            let mask = 0xf << 27 | 0x7 << 24;
            mmio.write32(MCR_SELECTOR, (old & !mask) | selector);
            let value = mmio.read32(reg);
            mmio.write32(MCR_SELECTOR, old);
            value
        }
        None => mmio.read32(reg),
    };
    list.apply(read, |reg, value| mmio.write32(reg, value));
    if let Err(reg) = list.verify(read) {
        lost.push(reg);
    }
}

/// Program the GT and RCS0 after a full reset, in Linux's order:
/// `intel_gt_apply_workarounds`, `i915_ppgtt_init_hw` (GTT workarounds and
/// the private PPAT), `intel_mocs_init` (the L3 table), then RCS0's engine
/// workarounds, whitelist, MOCS bank and `enable_execlists` (HWSTAM,
/// `RING_MODE`, `STOP_RING` off, error interrupts). The caller then points
/// `RING_HWS_PGA` at the status page ([`RcsEngine`] bring-up).
pub(crate) fn program(
    mmio: &impl MmioWindow,
    platform: WaPlatform,
    steering: Steering,
) -> Programmed {
    let gt = platform.gt();
    let mut report = Programmed::default();
    apply(
        &gt_workarounds(platform, steering),
        mmio,
        steering,
        &mut report.lost,
    );
    apply(&gtt_workarounds(gt), mmio, steering, &mut report.lost);
    for (reg, value) in ppat_writes(gt) {
        mmio.write32(reg, value);
    }
    for (reg, value) in l3cc_writes(gt) {
        mmio.write32(reg, value);
    }
    apply(&rcs_workarounds(platform), mmio, steering, &mut report.lost);
    for (reg, value) in whitelist_writes(RCS, &rcs_whitelist(platform)) {
        mmio.write32(reg, value);
    }
    for (reg, value) in engine_mocs_writes(gt, crate::intel_gpu_engine::Engine::Rcs0)
        .into_iter()
        .flatten()
    {
        mmio.write32(reg, value);
    }
    // enable_execlists: every HWSP write unmasked, the execlists mode
    // (Gen11 GFX_DISABLE_LEGACY_MODE, Gen9 GFX_RUN_LIST_ENABLE), the ring
    // running.
    mmio.write32(RCS + 0x98, u32::MAX);
    mmio.write32(
        RCS + 0x29c,
        match gt {
            LegacyGt::Gen11 => masked_enable(1 << 3),
            LegacyGt::Gen9 => masked_enable(1 << 15),
        },
    );
    mmio.write32(MI_MODE, masked_disable(STOP_RING));
    // enable_error_interrupt: EMR, EIR cleared, ESR checked, then only
    // instruction errors unmasked.
    mmio.write32(RCS + 0xb4, u32::MAX);
    mmio.write32(RCS + 0xb0, u32::MAX);
    report.error_status = mmio.read32(RCS + 0xb8);
    mmio.write32(RCS + 0xb4, !1);
    report
}

/// `read_clock_frequency` for graphics 9 (big core) and 11: the command
/// streamer timestamp rate, from `TIMESTAMP_OVERRIDE` when `CTC_MODE`
/// selects the divide logic, else the crystal shifted by the CTC shift.
pub(crate) fn timestamp_frequency(gt: LegacyGt, mut read: impl FnMut(u64) -> u32) -> u32 {
    let ctc = read(0xa26c);
    if ctc & 1 == 1 {
        let ts = read(0x44074);
        let base = ((ts & 0x3ff) + 1) * 1_000_000;
        return base + 1_000_000 / (((ts >> 12) & 0xf) + 1);
    }
    match gt {
        LegacyGt::Gen9 => 24_000_000 >> (3 - ((ctc >> 1) & 3)),
        LegacyGt::Gen11 => {
            let config = read(0xd00);
            let crystal = match (config >> 3) & 7 {
                0 => 24_000_000,
                1 => 19_200_000,
                2 => 38_400_000,
                3 => 25_000_000,
                _ => return 0,
            };
            crystal >> (3 - ((config >> 1) & 3))
        }
    }
}

// ── Runtime ─────────────────────────────────────────────────────────

type Engine = RcsEngine<BarWindow, SharedArena>;

/// A job is declared hung after this long without retiring (Linux's
/// heartbeat declares a hang after a few 2.5 s pulses).
const JOB_TIMEOUT_NS: u64 = 10_000_000_000;

struct Job {
    request: u64,
    job: UserJob,
    deadline: u64,
}

struct Context {
    user: Weak<UserContext>,
    id: ContextId,
}

struct Runtime {
    engine: Engine,
    fw: Forcewake,
    window: BarWindow,
    epoch: u64,
    /// The context workaround LRI each new hardware context starts with.
    ctx_wa: Vec<u32>,
    contexts: Vec<Context>,
    jobs: Vec<Job>,
    /// Frequency and park policy ([`crate::intel_gpu_legacy_power`]).
    governor: Governor,
    /// `RC_CONTROL` while unparked (`rc6->ctl_enable`).
    rc6_ctl: u32,
}

impl Runtime {
    /// `intel_rc6_unpark` + `intel_rps_unpark`: take forcewake back, leave
    /// RC6 and request the efficient frequency before touching the engine.
    /// Forcewake is acquired first, so a refused wake leaves the GT parked.
    fn unpark(&mut self) -> Result<(), FsError> {
        if !self.governor.parked() {
            return Ok(());
        }
        self.fw
            .acquire(&self.window, FwDomain::Render)
            .map_err(|_| crate::intel_gpu_user::io_error())?;
        if self.fw.acquire(&self.window, FwDomain::Blitter).is_err() {
            let _ = self.fw.release(&self.window, FwDomain::Render);
            return Err(crate::intel_gpu_user::io_error());
        }
        let window = &self.window;
        rc6_unpark(self.rc6_ctl, |r, v| window.write32(r, v));
        if let Some(Some(freq)) = self.governor.unpark() {
            rps_request(freq, |r, v| window.write32(r, v));
        }
        Ok(())
    }

    /// `intel_rps_park` + `intel_rc6_park`: the idle frequency (with the
    /// render well still awake, so the PCU commits it), the software RC6
    /// request, then forcewake released so the GT may enter RC6.
    fn park(&mut self, idle: u32) {
        let window = &self.window;
        if idle != 0 {
            rps_request(idle, |r, v| window.write32(r, v));
        }
        rc6_park(|r, v| window.write32(r, v));
        let _ = self.fw.release(window, FwDomain::Blitter);
        let _ = self.fw.release(window, FwDomain::Render);
    }

    fn context_for(&mut self, user: &Arc<UserContext>) -> Result<ContextId, SubmitError> {
        if let Some(context) = self
            .contexts
            .iter()
            .find(|c| core::ptr::eq(c.user.as_ptr(), Arc::as_ptr(user)))
        {
            return Ok(context.id);
        }
        let id = self.engine.create_context()?;
        if let Err(error) = self.engine.emit_context_setup(id, &self.ctx_wa) {
            let _ = self.engine.destroy_context(id);
            return Err(error);
        }
        self.contexts.push(Context {
            user: Arc::downgrade(user),
            id,
        });
        Ok(id)
    }

    /// Retire landed jobs and drop hardware contexts whose user context is
    /// gone. `true` when the GT must be reset: a completion could not be
    /// proven, or a job outlived its deadline.
    fn service(&mut self, now: u64) -> bool {
        for done in self.engine.poll_completions() {
            if let Some(i) = self.jobs.iter().position(|j| j.request == done.request) {
                self.jobs.swap_remove(i).job.finish(false);
            }
        }
        let engine = &mut self.engine;
        self.contexts.retain(|context| {
            context.user.strong_count() != 0 || engine.destroy_context(context.id).is_err()
        });
        let lost = self.engine.completion_lost() || self.jobs.iter().any(|job| now >= job.deadline);
        if !lost {
            let busy = !self.jobs.is_empty() || !self.engine.is_idle();
            match self.governor.tick(now, busy) {
                Some(Step::Request(freq)) => {
                    let window = &self.window;
                    rps_request(freq, |r, v| window.write32(r, v));
                }
                Some(Step::Park(idle)) => self.park(idle),
                None => {}
            }
        }
        lost
    }
}

pub(crate) struct Owner {
    index: u32,
    platform: GtPlatform,
    wa: WaPlatform,
    revision: u8,
    /// PCI device ID (`WaRsDisableCoarsePowerGating`'s Skylake GT3/GT4).
    device: u16,
    bar: narf_bus::bar::MmioRegion,
    card: Arc<crate::drm_devfs_bridge::IntelGpuCard>,
    state: Mutex<Option<Runtime>>,
    epoch: AtomicU64,
    clock: AtomicU64,
    topology: narf_lib::sync::IrqSafeSpinLock<Option<crate::intel_gpu_legacy_gt::LegacyTopology>>,
}

impl core::fmt::Debug for Owner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("legacy::Owner")
            .field("index", &self.index)
            .field("platform", &self.platform)
            .field("epoch", &self.epoch.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

fn log(index: u32, text: &str) {
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "intel-gt card{index}: execlists: {text}"
    );
}

async fn sleep_us(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}

/// `__engines_record_defaults`: run the context workarounds and the golden
/// batch ([`RcsEngine::begin_default_image`]) and record the saved image,
/// waiting as long as Linux does (`I915_GEM_IDLE_TIMEOUT`, 200 ms).
async fn record_defaults(engine: &mut Engine, ctx_wa: &[u32]) -> Result<(), SubmitError> {
    let (id, request) = engine.begin_default_image(ctx_wa)?;
    let deadline = narf_time::monotonic_ns().saturating_add(200_000_000);
    loop {
        if engine
            .poll_completions()
            .iter()
            .any(|done| done.request == request)
        {
            return engine.finish_default_image(id);
        }
        if engine.completion_lost() {
            return Err(SubmitError::CompletionLost);
        }
        if narf_time::monotonic_ns() >= deadline {
            return Err(SubmitError::Timeout);
        }
        sleep_us(50).await;
    }
}

impl Owner {
    /// Reset and program the GT, bring RCS0 up, record the default context
    /// image and publish a new epoch.
    async fn bring_up(&self) -> Result<(), InitError> {
        let window = BarWindow::new(self.bar);
        let mut fw = Forcewake::new();
        fw.sanitize(&window);
        fw.acquire(&window, FwDomain::Render)
            .map_err(|_| InitError::Forcewake)?;
        if fw.acquire(&window, FwDomain::Blitter).is_err() {
            let _ = fw.release(&window, FwDomain::Render);
            return Err(InitError::Forcewake);
        }
        let mut reset = Reset::new();
        loop {
            match reset.poll(&window, narf_time::monotonic_ns()) {
                Poll::Pending => sleep_us(20).await,
                Poll::Ready(result) => break result?,
            }
        }
        let steering = Steering::read(self.wa, |reg| window.read32(reg)).ok_or(InitError::Fuses)?;
        *self.topology.lock() =
            crate::intel_gpu_legacy_gt::LegacyTopology::read(self.wa, |reg| window.read32(reg));
        let report = program(&window, self.wa, steering);
        if !report.lost.is_empty() {
            log(self.index, "some workarounds did not stick");
        }
        if report.error_status != 0 {
            log(self.index, "RCS0 resumed with ESR set");
        }
        self.clock.store(
            u64::from(timestamp_frequency(self.wa.gt(), |reg| window.read32(reg))),
            Ordering::Release,
        );
        let generation = match self.wa.gt() {
            LegacyGt::Gen9 => crate::intel_gpu::Generation::Skylake,
            LegacyGt::Gen11 => crate::intel_gpu::Generation::IceLake,
        };
        let mut engine = RcsEngine::new_for_generation(
            generation,
            BarWindow::new(self.bar),
            crate::intel_gpu_rcs::production_arena(self.bar),
        )
        .map_err(InitError::Engine)?;
        let ready = engine
            .install_gen9_wa_bb()
            .and_then(|()| engine.reset_csb_pointers());
        if let Err(error) = ready {
            // SAFETY: nothing was submitted on this engine.
            unsafe { engine.release_after_reset() };
            return Err(InitError::Engine(error));
        }
        let ctx_wa = ctx_workarounds(self.wa, steering).load_register_imm();
        if let Err(error) = record_defaults(&mut engine, &ctx_wa).await {
            log(self.index, "no default context image");
            // The golden request may still be running: only a completed
            // reset frees what it references.
            let mut reset = Reset::new();
            let result = loop {
                match reset.poll(&window, narf_time::monotonic_ns()) {
                    Poll::Pending => sleep_us(20).await,
                    Poll::Ready(result) => break result,
                }
            };
            if result.is_ok() {
                // SAFETY: the full-domain reset above completed, so the
                // engine no longer reads or writes any of its memory.
                unsafe { engine.release_after_reset() };
            } else {
                core::mem::forget(engine);
            }
            return Err(InitError::Engine(error));
        }
        // intel_rps_enable / intel_rc6_enable, then unparked: hardware RC6
        // timers (Gen11) and RPS stay programmed across park/unpark.
        let gt = self.wa.gt();
        let caps = Caps::read(gt, |r| window.read32(r));
        if let Some(caps) = caps {
            rps_enable(gt, caps, self.clock.load(Ordering::Acquire), |r, v| {
                window.write32(r, v)
            });
        } else {
            log(self.index, "no RP_STATE_CAP; GPU frequency left to the PCU");
        }
        let rc6_ctl = rc6_enable(gt, self.device, |r, v| window.write32(r, v));
        rc6_unpark(rc6_ctl, |r, v| window.write32(r, v));
        let epoch = crate::intel_gpu_user::next_epoch();
        *self.state.lock().await = Some(Runtime {
            engine,
            fw,
            window,
            epoch,
            ctx_wa,
            contexts: Vec::new(),
            jobs: Vec::new(),
            governor: Governor::new(caps),
            rc6_ctl,
        });
        self.epoch.store(epoch, Ordering::Release);
        Ok(())
    }

    /// Unpublish, reset the GT so nothing references the engine's memory,
    /// then release it: every pending fence fails with a reset and every
    /// context involved is banned.
    async fn tear_down(&self) {
        self.epoch.store(0, Ordering::Release);
        let Some(mut runtime) = self.state.lock().await.take() else {
            return;
        };
        // The reset sequence needs the render well awake; a refused wake
        // still attempts it.
        let _ = runtime.unpark();
        let mut reset = Reset::new();
        let result = loop {
            match reset.poll(&runtime.window, narf_time::monotonic_ns()) {
                Poll::Pending => sleep_us(20).await,
                Poll::Ready(result) => break result,
            }
        };
        rc6_disable(|r, v| runtime.window.write32(r, v));
        let _ = runtime.fw.release(&runtime.window, FwDomain::Blitter);
        let _ = runtime.fw.release(&runtime.window, FwDomain::Render);
        if result.is_err() {
            // The GT never confirmed the reset; its memory stays retained.
            log(self.index, "reset did not complete; GT closed");
            core::mem::forget(runtime);
            return;
        }
        for job in runtime.jobs.drain(..) {
            job.job.finish(true);
        }
        // SAFETY: the full-domain reset above completed, so the engine no
        // longer reads or writes any context, ring or batch memory.
        unsafe { runtime.engine.release_after_reset() };
    }

    async fn run(self: Arc<Self>) {
        let mut attempts = 0;
        loop {
            if let Err(error) = self.bring_up().await {
                let _ = error;
                log(self.index, "bring-up failed");
                attempts += 1;
                if attempts >= 3 {
                    log(self.index, "GT closed");
                    return;
                }
                self.tear_down().await;
                continue;
            }
            if attempts == 0 {
                let backend = Arc::new(Backend(self.clone()));
                if self.card.install_user_backend(backend).is_err() {
                    log(self.index, "render backend already installed");
                    return;
                }
                log(self.index, "RCS0 published");
            }
            attempts = 0;
            loop {
                let (reset, busy) = {
                    let mut state = self.state.lock().await;
                    let Some(runtime) = state.as_mut() else {
                        break;
                    };
                    let reset = runtime.service(narf_time::monotonic_ns());
                    (reset, !runtime.jobs.is_empty())
                };
                if reset {
                    log(self.index, "job hung or completion lost; resetting the GT");
                    self.tear_down().await;
                    break;
                }
                sleep_us(if busy { 50 } else { 1000 }).await;
            }
        }
    }

    async fn submit(
        &self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> Result<Arc<CompletionFence>, FsError> {
        let epoch = self.epoch.load(Ordering::Acquire);
        if epoch == 0 {
            return Err(FsError::NoDevice);
        }
        if batch.0.platform() != Some(self.platform)
            || context.engine() != crate::intel_gpu_engine::Engine::Rcs0
            || context.parallel().is_some()
            || context.placements() != crate::intel_gpu_engine::EngineSet::of(&[context.engine()])
        {
            return Err(FsError::InvalidData);
        }
        let mut state = self.state.lock().await;
        let runtime = state
            .as_mut()
            .filter(|r| r.epoch == epoch)
            .ok_or(FsError::NoDevice)?;
        runtime.unpark()?;
        let claim = context.claim_resident(epoch)?;
        let id = runtime.context_for(&context).map_err(submit_error)?;
        let submission = runtime
            .engine
            .submit_resident(id, batch.0)
            .map_err(submit_error)?;
        let fence = submission.fence.clone();
        runtime.jobs.push(Job {
            request: submission.request,
            job: claim.publish(fence.clone()),
            deadline: narf_time::monotonic_ns().saturating_add(JOB_TIMEOUT_NS),
        });
        Ok(fence)
    }
}

fn submit_error(error: SubmitError) -> FsError {
    match error {
        SubmitError::ContextBusy | SubmitError::QueueFull | SubmitError::RingFull => {
            FsError::WouldBlock
        }
        SubmitError::CompletionLost => FsError::NoDevice,
        _ => crate::intel_gpu_user::io_error(),
    }
}

#[derive(Debug)]
struct Backend(Arc<Owner>);

impl UserBackend for Backend {
    fn status(&self) -> Option<UserStatus> {
        let epoch = self.0.epoch.load(Ordering::Acquire);
        (epoch != 0).then(|| UserStatus {
            epoch,
            platform: self.0.platform,
            submission_version: (0, 0, 0),
            engines: crate::intel_gpu_engine::EngineSet::of(&[
                crate::intel_gpu_engine::Engine::Rcs0,
            ]),
        })
    }

    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        let clock = self.0.clock.load(Ordering::Acquire) as u32;
        (clock != 0).then(|| crate::intel_gpu_user::DeviceFacts {
            revision: self.0.revision,
            graphics_version: match self.0.wa.gt() {
                LegacyGt::Gen9 => 900,
                LegacyGt::Gen11 => 1100,
            },
            graphics_step: 0,
            reference_clock: clock,
            oa_timestamp_frequency: clock,
        })
    }

    fn legacy_topology(&self) -> Option<crate::intel_gpu_legacy_gt::LegacyTopology> {
        *self.0.topology.lock()
    }

    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        alloc::boxed::Box::pin(self.0.submit(context, batch))
    }
}

// ── Installation ────────────────────────────────────────────────────

static PENDING: narf_lib::sync::IrqSafeSpinLock<Vec<Arc<Owner>>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());

/// Stage the execlists owner for a Gen9/Gen11 function. `false` when the
/// platform is not one of them, or another owner holds the function.
pub(crate) fn install(
    index: u32,
    card: Arc<crate::drm_devfs_bridge::IntelGpuCard>,
    device: &narf_bus::BusDevice,
    revision: u8,
    bar: narf_bus::bar::MmioRegion,
) -> bool {
    let Some(platform) = GtPlatform::from_pci(device.id.vendor, device.id.device) else {
        return false;
    };
    let Some(wa) = WaPlatform::for_device(device.id.device, revision) else {
        return false;
    };
    if LegacyGt::for_platform(platform).is_none()
        || crate::intel_gpu_gt::ownership::claim_execlists(device.addr, bar).is_err()
    {
        return false;
    }
    PENDING.lock().push(Arc::new(Owner {
        index,
        platform,
        wa,
        revision,
        device: device.id.device,
        bar,
        card,
        state: Mutex::new(None),
        epoch: AtomicU64::new(0),
        clock: AtomicU64::new(0),
        topology: narf_lib::sync::IrqSafeSpinLock::new(None),
    }));
    true
}

pub(crate) fn start_pending() {
    let pending = core::mem::take(&mut *PENDING.lock());
    for owner in pending {
        narf_scheduler::spawn(async move { owner.run().await });
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[derive(Default)]
    struct Regs {
        values: RefCell<BTreeMap<u64, u32>>,
        writes: RefCell<Vec<(u64, u32)>>,
    }
    impl MmioWindow for Regs {
        fn read32(&self, reg: u64) -> u32 {
            *self.values.borrow().get(&reg).unwrap_or(&0)
        }
        fn write32(&self, reg: u64, value: u32) {
            self.writes.borrow_mut().push((reg, value));
            let mut values = self.values.borrow_mut();
            let masked = matches!(reg, MI_MODE | RESET_CTL);
            let old = *values.get(&reg).unwrap_or(&0);
            values.insert(
                reg,
                if masked {
                    (old & !(value >> 16)) | (value & value >> 16 & 0xffff)
                } else {
                    value
                },
            );
        }
    }

    /// The reset walks stop → prepare → full domain → cancel, proceeding
    /// past a CS that will not idle, and fails only on a stuck domain.
    fn smoke_legacy_owner_reset_sequence() -> TestResult {
        let regs = Regs::default();
        let mut reset = Reset::new();
        if reset.poll(&regs, 0).is_ready() || regs.writes.borrow()[0] != (MI_MODE, 0x0100_0100) {
            return TestResult::Fail("STOP_RING first");
        }
        // The CS never idles: after 1 ms the handshake is requested anyway.
        if reset.poll(&regs, 999_999).is_ready() || regs.writes.borrow().len() != 1 {
            return TestResult::Fail("waits up to 1 ms for MODE_IDLE");
        }
        let _ = reset.poll(&regs, 1_000_000);
        if regs.writes.borrow()[1] != (RESET_CTL, 0x0001_0001) {
            return TestResult::Fail("RESET_CTL request after the stop");
        }
        regs.values.borrow_mut().insert(RESET_CTL, 0x3);
        let _ = reset.poll(&regs, 1_000_001);
        if regs.writes.borrow()[2] != (GDRST, 1) {
            return TestResult::Fail("GRDOM_FULL once ready");
        }
        // GDRST still set: pending, then cleared → cancel and done.
        if reset.poll(&regs, 1_000_002).is_ready() {
            return TestResult::Fail("waits for the domain to self-clear");
        }
        regs.values.borrow_mut().insert(GDRST, 0);
        if reset.poll(&regs, 1_000_003) != Poll::Ready(Ok(()))
            || *regs.writes.borrow().last().unwrap() != (RESET_CTL, 0x0001_0000)
        {
            return TestResult::Fail("reset completes and cancels the handshake");
        }
        let stuck = Regs::default();
        let mut reset = Reset::new();
        for now in [0, 2_000_000, 3_000_000] {
            let _ = reset.poll(&stuck, now);
        }
        stuck.values.borrow_mut().insert(GDRST, 1);
        if reset.poll(&stuck, 3_000_000 + 499_999_999).is_ready()
            || reset.poll(&stuck, 3_000_000 + 500_000_000)
                != Poll::Ready(Err(InitError::ResetTimeout))
        {
            return TestResult::Fail("a stuck full-domain reset times out at 500 ms");
        }
        let gone = Regs::default();
        gone.values.borrow_mut().insert(MI_MODE, u32::MAX);
        if Reset::new().poll(&gone, 0) != Poll::Ready(Err(InitError::Unavailable)) {
            return TestResult::Fail("an all-ones read is an absent function");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_owner",
        smoke_legacy_owner_reset_sequence
    );

    /// GT programming order and the execlists enable on each generation,
    /// with Ice Lake's L3BANK reads steered and the selector restored.
    fn smoke_legacy_owner_program_order() -> TestResult {
        let gen9 = WaPlatform::Gen9 {
            kind: crate::intel_gpu_legacy_gt::Gen9Kind::CoffeeLake,
            revision: 0,
        };
        let steer = Steering {
            slice: 0,
            subslice: 0,
            l3_banks: 0,
            iz_hashing: [0; 3],
        };
        let regs = Regs::default();
        // Subslice 1, so the steering WA has a value to write.
        let report = program(
            &regs,
            gen9,
            Steering {
                subslice: 1,
                ..steer
            },
        );
        let writes = regs.writes.borrow();
        let at = |reg: u64| writes.iter().position(|(r, _)| *r == reg);
        let order = [
            at(MCR_SELECTOR),
            at(0x40e0),
            at(0xb020),
            at(0x20e0),
            at(0x24d0),
            at(0xc800),
            at(0x229c),
        ];
        if order.iter().any(Option::is_none) || !order.windows(2).all(|w| w[0] < w[1]) {
            return TestResult::Fail("GT WA, PPAT, L3CC, RCS WA, whitelist, MOCS, execlists");
        }
        if writes.iter().find(|(r, _)| *r == 0x229c).map(|w| w.1) != Some(0x8000_8000)
            || writes
                .iter()
                .filter(|(r, _)| *r == MI_MODE)
                .next_back()
                .map(|w| w.1)
                != Some(0x0100_0000)
            || *writes.last().unwrap() != (0x20b4, !1)
            || !report.lost.is_empty()
        {
            return TestResult::Fail("Gen9 run-list enable, ring running, EMR");
        }
        drop(writes);
        let icl = WaPlatform::Gen11 {
            jsl_ehl: false,
            revision: 0,
        };
        let regs = Regs::default();
        let steered = Steering {
            subslice: 0,
            l3_banks: 0x6,
            ..steer
        };
        let _ = program(&regs, icl, steered);
        let writes = regs.writes.borrow();
        if writes.iter().find(|(r, _)| *r == 0x229c).map(|w| w.1) != Some(0x0008_0008) {
            return TestResult::Fail("Gen11 disables legacy mode");
        }
        // The L3SQCREG4 RMW read is bracketed by a steer to bank 1 and a
        // restore of the default selector.
        let rmw = writes.iter().position(|(r, _)| *r == 0xb118).unwrap();
        if writes[rmw - 2] != (MCR_SELECTOR, 1 << 24) || writes[rmw - 1].0 != MCR_SELECTOR {
            return TestResult::Fail("Ice Lake L3BANK read steering");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_owner",
        smoke_legacy_owner_program_order
    );

    /// read_clock_frequency: the CTC shift on the 24 MHz Gen9 crystal, the
    /// Gen11 RPM_CONFIG0 crystal, and the divide-logic override.
    fn smoke_legacy_owner_timestamp_frequency() -> TestResult {
        let regs = |ctc: u32, config: u32, ts: u32| {
            move |reg: u64| match reg {
                0xa26c => ctc,
                0xd00 => config,
                0x44074 => ts,
                _ => 0,
            }
        };
        // CTC shift 2: 24 MHz >> 1 = Skylake's 12 MHz.
        if timestamp_frequency(LegacyGt::Gen9, regs(2 << 1, 0, 0)) != 12_000_000
            || timestamp_frequency(LegacyGt::Gen9, regs(3 << 1, 0, 0)) != 24_000_000
            // Ice Lake: 19.2 MHz crystal, shift 3 → full rate.
            || timestamp_frequency(LegacyGt::Gen11, regs(0, 1 << 3 | 3 << 1, 0)) != 19_200_000
            || timestamp_frequency(LegacyGt::Gen11, regs(0, 2 << 3 | 2 << 1, 0)) != 19_200_000
            || timestamp_frequency(LegacyGt::Gen11, regs(0, 7 << 3, 0)) != 0
            // Divide logic: (divider + 1) MHz + 1 MHz / (denominator + 1).
            || timestamp_frequency(LegacyGt::Gen9, regs(1, 0, 0x1000 | 18)) != 19_500_000
        {
            return TestResult::Fail("CS timestamp frequency");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_owner",
        smoke_legacy_owner_timestamp_frequency
    );

    /// claim_resident keeps claim's discipline: one job per context, the
    /// previous fence terminal first, and a context from an older epoch
    /// banned.
    fn smoke_legacy_owner_claim_resident() -> TestResult {
        let ctx = UserContext::new();
        let claim = ctx.claim_resident(5).unwrap();
        if ctx.claim_resident(5).err() != Some(FsError::WouldBlock) {
            return TestResult::Fail("a claimed context is busy");
        }
        let fence = Arc::new(CompletionFence::new());
        let job = claim.publish(fence.clone());
        job.finish(false);
        if ctx.claim_resident(5).err() != Some(FsError::WouldBlock) {
            return TestResult::Fail("the last fence must be terminal");
        }
        fence.signal(Ok(()));
        match ctx.claim_resident(5) {
            Ok(claim) => drop(claim),
            Err(_) => return TestResult::Fail("an idle context claims again"),
        }
        if ctx.claim_resident(5).is_err() {
            return TestResult::Fail("dropping an unpublished claim frees the context");
        }
        if ctx.claim_resident(6).err() != Some(crate::intel_gpu_user::io_error())
            || ctx.claim_resident(6).is_ok()
        {
            return TestResult::Fail("a context from an older epoch is banned");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_owner",
        smoke_legacy_owner_claim_resident
    );
}
