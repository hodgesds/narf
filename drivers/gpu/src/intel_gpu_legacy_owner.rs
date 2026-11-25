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
//! It schedules RCS0, BCS0, VCS0 and VECS0 with timeslicing and priority
//! preemption, records each engine's default image with the golden render
//! state (`__engines_record_defaults`), runs RC6 and RPS through
//! [`crate::intel_gpu_legacy_power`], and resets a hung engine alone where
//! it has its own reset domain (`intel_engine_reset`), falling back to a
//! full GT reset otherwise.

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
    rc6_disable, rc6_enable, rc6_park, rc6_supported, rc6_unpark, rps_disable, rps_enable,
    rps_request, Caps, Governor, Step,
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
/// `GEN6_GRDOM_RENDER` / `GEN11_GRDOM_RENDER`.
const GRDOM_RENDER: u32 = 1 << 1;

/// The `GDRST` domain resetting `which` alone (`gen6_hw_engine_mask`,
/// `get_reset_domain`'s Gen11 table). A Gen11 video or enhancement engine's
/// reset also locks the SFC it may be using ([`sfc_lock`]).
pub(crate) const fn engine_reset_domain(gt: LegacyGt, which: HwEngine) -> Option<u32> {
    match (gt, which) {
        (_, HwEngine::Rcs0) => Some(GRDOM_RENDER),
        (LegacyGt::Gen9 | LegacyGt::Gen9Lp, HwEngine::Bcs0) => Some(1 << 3),
        (LegacyGt::Gen9 | LegacyGt::Gen9Lp, HwEngine::Vcs0) => Some(1 << 2),
        (LegacyGt::Gen9 | LegacyGt::Gen9Lp, HwEngine::Vecs0) => Some(1 << 4),
        (LegacyGt::Gen11, HwEngine::Bcs0) => Some(1 << 2),
        // GEN11_GRDOM_MEDIA, GEN11_GRDOM_VECS.
        (LegacyGt::Gen11, HwEngine::Vcs0) => Some(1 << 5),
        (LegacyGt::Gen11, HwEngine::Vecs0) => Some(1 << 13),
        _ => None,
    }
}

/// `GEN11_GRDOM_SFC0`: VCS0's (`GEN11_VCS_SFC_RESET_BIT(0)`) and VECS0's
/// (`GEN11_VECS_SFC_RESET_BIT(0)`) scaler and format converter.
const GRDOM_SFC0: u32 = 1 << 17;

/// `get_sfc_forced_lock_data`: an engine's SFC forced-lock request, its
/// acknowledgement, the engine's SFC usage flag and the `GDRST` bit that
/// resets the SFC with the engine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct SfcLock {
    lock: u64,
    lock_bit: u32,
    ack: u64,
    ack_bit: u32,
    usage: u64,
    usage_bit: u32,
    reset_bit: u32,
}

/// The SFC lock of the engine at `base`: Gen11 VCS0 (logical VDBox 0, which
/// Gen11 always hooks to an SFC, `gen11_vdbox_has_sfc`) and VECS0, both on
/// SFC 0. `None` for any engine without an SFC to lock.
pub(crate) const fn sfc_lock(gt: LegacyGt, which: HwEngine, base: u64) -> Option<SfcLock> {
    match (gt, which) {
        // GEN11_VCS_SFC_FORCED_LOCK, GEN11_VCS_SFC_LOCK_STATUS (usage [0],
        // ack [1]).
        (LegacyGt::Gen11, HwEngine::Vcs0) => Some(SfcLock {
            lock: base + 0x88c,
            lock_bit: 1,
            ack: base + 0x890,
            ack_bit: 1 << 1,
            usage: base + 0x890,
            usage_bit: 1,
            reset_bit: GRDOM_SFC0,
        }),
        // GEN11_VECS_SFC_FORCED_LOCK, _LOCK_ACK, _USAGE.
        (LegacyGt::Gen11, HwEngine::Vecs0) => Some(SfcLock {
            lock: base + 0x201c,
            lock_bit: 1,
            ack: base + 0x2018,
            ack_bit: 1,
            usage: base + 0x2014,
            usage_bit: 1,
            reset_bit: GRDOM_SFC0,
        }),
        _ => None,
    }
}

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
    Locking,
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
    /// The engine whose CS is stopped and whose reset handshake is asked.
    base: u64,
    /// The `GDRST` domain pulsed: the full GT, or one engine (and its SFC
    /// once locked to it).
    domain: u32,
    /// The engine's SFC lock ([`sfc_lock`]), and whether it was requested.
    sfc: Option<SfcLock>,
    sfc_requested: bool,
}

impl Reset {
    pub(crate) const fn new() -> Self {
        Self::engine(RCS, GRDOM_FULL)
    }

    /// `intel_engine_reset` of the engine at `base`: stop its CS, ask its
    /// reset handshake, pulse its `GDRST` `domain` ([`engine_reset_domain`]).
    pub(crate) const fn engine(base: u64, domain: u32) -> Self {
        Self {
            phase: ResetPhase::Start,
            deadline: 0,
            base,
            domain,
            sfc: None,
            sfc_requested: false,
        }
    }

    /// `__gen11_reset_engines`' SFC handling: when the engine is using its
    /// SFC, force-lock it (1 ms for the ack) and reset it with the engine;
    /// an SFC released meanwhile is left alone; an unacknowledged lock fails
    /// the engine reset. The lock is released after the pulse either way.
    pub(crate) const fn with_sfc(mut self, sfc: Option<SfcLock>) -> Self {
        self.sfc = sfc;
        self
    }

    /// `gen6_hw_domain_reset`: pulse the domain and wait up to 500 ms.
    fn pulse(&mut self, mmio: &impl MmioWindow, now: u64) -> Poll<Result<(), InitError>> {
        mmio.write32(GDRST, self.domain);
        self.phase = ResetPhase::Resetting;
        self.deadline = now + 500_000_000;
        Poll::Pending
    }

    /// `gen11_unlock_sfc` for a requested lock, then
    /// `gen8_engine_reset_cancel`.
    fn finish(&mut self, mmio: &impl MmioWindow) {
        if let Some(sfc) = self.sfc.filter(|_| self.sfc_requested) {
            let lock = mmio.read32(sfc.lock);
            mmio.write32(sfc.lock, lock & !sfc.lock_bit);
        }
        mmio.write32(self.base + (RESET_CTL - RCS), masked_disable(REQUEST_RESET));
    }

    pub(crate) fn poll(&mut self, mmio: &impl MmioWindow, now: u64) -> Poll<Result<(), InitError>> {
        match self.phase {
            ResetPhase::Start => {
                if mmio.read32(self.base + (MI_MODE - RCS)) == u32::MAX {
                    return Poll::Ready(Err(InitError::Unavailable));
                }
                mmio.write32(self.base + (MI_MODE - RCS), masked_enable(STOP_RING));
                self.phase = ResetPhase::Stopping;
                self.deadline = now + 1_000_000;
                Poll::Pending
            }
            ResetPhase::Stopping => {
                // A CS that will not idle is reset anyway, as Linux does.
                if mmio.read32(self.base + (MI_MODE - RCS)) & MODE_IDLE == 0 && now < self.deadline
                {
                    return Poll::Pending;
                }
                mmio.write32(self.base + (RESET_CTL - RCS), masked_enable(REQUEST_RESET));
                self.phase = ResetPhase::Preparing;
                self.deadline = now + 700_000;
                Poll::Pending
            }
            ResetPhase::Preparing => {
                if mmio.read32(self.base + (RESET_CTL - RCS)) & READY_TO_RESET == 0
                    && now < self.deadline
                {
                    return Poll::Pending;
                }
                match self.sfc {
                    Some(sfc) if mmio.read32(sfc.usage) & sfc.usage_bit != 0 => {
                        let lock = mmio.read32(sfc.lock);
                        mmio.write32(sfc.lock, lock | sfc.lock_bit);
                        self.sfc_requested = true;
                        self.phase = ResetPhase::Locking;
                        self.deadline = now + 1_000_000;
                        Poll::Pending
                    }
                    _ => self.pulse(mmio, now),
                }
            }
            ResetPhase::Locking => {
                let Some(sfc) = self.sfc else {
                    return self.pulse(mmio, now);
                };
                let acked = mmio.read32(sfc.ack) & sfc.ack_bit != 0;
                if !acked && now < self.deadline {
                    return Poll::Pending;
                }
                // Released while locking: the engine resets alone.
                if mmio.read32(sfc.usage) & sfc.usage_bit == 0 {
                    return self.pulse(mmio, now);
                }
                if !acked {
                    self.finish(mmio);
                    return Poll::Ready(Err(InitError::ResetTimeout));
                }
                self.domain |= sfc.reset_bit;
                self.pulse(mmio, now)
            }
            ResetPhase::Resetting => {
                let status = mmio.read32(GDRST);
                if status == u32::MAX {
                    return Poll::Ready(Err(InitError::Unavailable));
                }
                if status & self.domain != 0 {
                    if now < self.deadline {
                        return Poll::Pending;
                    }
                    self.finish(mmio);
                    return Poll::Ready(Err(InitError::ResetTimeout));
                }
                self.finish(mmio);
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
    resume_rcs(mmio, platform, steering, &mut report);
    report
}

/// RCS0's engine state, which an engine reset clears as well as a full one
/// (`execlists_resume`): its workarounds, whitelist, MOCS bank and
/// `enable_execlists`. The caller then points `RING_HWS_PGA` at the status
/// page.
pub(crate) fn resume_rcs(
    mmio: &impl MmioWindow,
    platform: WaPlatform,
    steering: Steering,
    report: &mut Programmed,
) {
    let gt = platform.gt();
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
            LegacyGt::Gen9 | LegacyGt::Gen9Lp => masked_enable(1 << 15),
        },
    );
    mmio.write32(MI_MODE, masked_disable(STOP_RING));
    // enable_error_interrupt: EMR, EIR cleared, ESR checked, then only
    // instruction errors unmasked.
    mmio.write32(RCS + 0xb4, u32::MAX);
    mmio.write32(RCS + 0xb0, u32::MAX);
    report.error_status = mmio.read32(RCS + 0xb8);
    mmio.write32(RCS + 0xb4, !1);
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
        // Gen9 LP's crystal is 19.2 MHz (`gen9_read_clock_frequency`).
        LegacyGt::Gen9Lp => 19_200_000 >> (3 - ((ctc >> 1) & 3)),
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
use crate::intel_gpu_engine::Engine as HwEngine;
use crate::intel_gpu_media::{MediaForcewake, MediaFwDomain};
use crate::intel_gpu_rcs::{EngineClass, EngineSpec};

/// Gen9/Gen11 BCS0 (`BLT_RING_BASE`): a copy engine with the two-page
/// non-render context image.
const BCS0: EngineSpec = EngineSpec {
    name: "bcs0",
    class: EngineClass::Copy,
    instance: 0,
    base: 0x22000,
    image_pages: crate::intel_gpu_media::MEDIA_IMAGE_PAGES,
};

/// `GEN11_GT_VEBOX_VDBOX_DISABLE`: VDBox disables [7:0], VEBox [23:16].
const GEN11_VDBOX_VEBOX_DISABLE: u64 = 0x9140;

/// The copy and media engines run beside RCS0 (`intel_engines_init_mmio`):
/// BCS0, VCS0 and VECS0, present on every Gen9 and Gen11 part this owner
/// admits, except a Gen11 VDBox or VEBox its fuse register disables.
fn xcs_engines(gt: LegacyGt, mut read: impl FnMut(u64) -> u32) -> Vec<(HwEngine, EngineSpec)> {
    use crate::intel_gpu_media as media;
    match gt {
        // GEN9_LP_FEATURES' engine mask is the same RCS0, BCS0, VCS0, VECS0.
        LegacyGt::Gen9 | LegacyGt::Gen9Lp => alloc::vec![
            (HwEngine::Bcs0, BCS0),
            (HwEngine::Vcs0, media::GEN9_VCS0_SPEC),
            (HwEngine::Vecs0, media::GEN9_VECS0_SPEC),
        ],
        LegacyGt::Gen11 => {
            let fuse = read(GEN11_VDBOX_VEBOX_DISABLE);
            let fuse = if fuse == u32::MAX { 0xff_00ff } else { fuse };
            let mut engines = alloc::vec![(HwEngine::Bcs0, BCS0)];
            if fuse & 1 == 0 {
                engines.push((HwEngine::Vcs0, media::VCS0_SPEC));
            }
            if fuse & (1 << 16) == 0 {
                engines.push((HwEngine::Vecs0, media::VECS0_SPEC));
            }
            engines
        }
    }
}

/// `enable_execlists` and the engine MOCS bank for a copy or media engine
/// (`execlists_resume`): every HWSP write unmasked, execlists mode, the ring
/// running, error interrupts cleared with only instruction errors unmasked.
fn resume_xcs(mmio: &impl MmioWindow, gt: LegacyGt, which: HwEngine, base: u64) {
    for (reg, value) in engine_mocs_writes(gt, which).into_iter().flatten() {
        mmio.write32(reg, value);
    }
    mmio.write32(base + 0x98, u32::MAX);
    mmio.write32(
        base + 0x29c,
        match gt {
            LegacyGt::Gen11 => masked_enable(1 << 3),
            LegacyGt::Gen9 | LegacyGt::Gen9Lp => masked_enable(1 << 15),
        },
    );
    mmio.write32(base + 0x9c, masked_disable(STOP_RING));
    mmio.write32(base + 0xb4, u32::MAX);
    mmio.write32(base + 0xb0, u32::MAX);
    mmio.write32(base + 0xb4, !1);
}

/// The media forcewake domain gating `which`: Gen9's aggregate media well,
/// Gen11's per-VDBox / per-VEBox wells. `None` for the copy engine, which
/// the blitter domain covers.
fn media_domain(gt: LegacyGt, which: HwEngine) -> Option<MediaFwDomain> {
    match (gt, which) {
        (_, HwEngine::Bcs0 | HwEngine::Rcs0) => None,
        (LegacyGt::Gen9 | LegacyGt::Gen9Lp, _) => Some(MediaFwDomain::Aggregate),
        (LegacyGt::Gen11, HwEngine::Vcs0) => Some(MediaFwDomain::VdBox(0)),
        (LegacyGt::Gen11, HwEngine::Vecs0) => Some(MediaFwDomain::VeBox(0)),
        _ => None,
    }
}

/// One copy or media engine beside RCS0.
struct Lane {
    which: HwEngine,
    engine: Engine,
    contexts: Vec<Context>,
}

/// The hardware context of `user` on `engine`, created on first use with
/// `setup` (the render context workarounds; nothing on other engines).
fn context_on(
    engine: &mut Engine,
    contexts: &mut Vec<Context>,
    setup: &[u32],
    user: &Arc<UserContext>,
) -> Result<ContextId, SubmitError> {
    if let Some(context) = contexts
        .iter()
        .find(|c| core::ptr::eq(c.user.as_ptr(), Arc::as_ptr(user)))
    {
        return Ok(context.id);
    }
    let id = engine.create_context()?;
    if !setup.is_empty() {
        if let Err(error) = engine.emit_context_setup(id, setup) {
            let _ = engine.destroy_context(id);
            return Err(error);
        }
    }
    contexts.push(Context {
        user: Arc::downgrade(user),
        id,
    });
    Ok(id)
}

/// A job is declared hung after this long without retiring (Linux's
/// heartbeat declares a hang after a few 2.5 s pulses).
const JOB_TIMEOUT_NS: u64 = 10_000_000_000;

struct Job {
    /// The engine running the request; request ids are per engine.
    which: HwEngine,
    request: u64,
    job: UserJob,
    deadline: u64,
}

struct Context {
    user: Weak<UserContext>,
    id: ContextId,
}

/// What a service pass found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Service {
    Ok,
    /// A job (this request) overran its deadline on this engine, which
    /// resets alone where it can, else through the full GT reset.
    Hung(HwEngine, u64),
    /// Completion tracking is lost: only a full GT reset recovers.
    Lost,
}

struct Runtime {
    engine: Engine,
    /// The copy and media engines ([`xcs_engines`]) that came up.
    xcs: Vec<Lane>,
    gt: LegacyGt,
    fw: Forcewake,
    /// The media wells the media lanes need (Gen9 aggregate, Gen11
    /// VDBox/VEBox), held whenever render forcewake is.
    media_fw: MediaForcewake,
    window: BarWindow,
    epoch: u64,
    /// The context workaround LRI each new hardware context starts with.
    ctx_wa: Vec<u32>,
    contexts: Vec<Context>,
    jobs: Vec<Job>,
    /// Frequency and park policy ([`crate::intel_gpu_legacy_power`]).
    governor: Governor,
    /// MCR steering for re-applying RCS0's workarounds after an engine reset.
    steering: Steering,
    /// `RC_CONTROL` while unparked (`rc6->ctl_enable`); `None` when RC6 is
    /// not supported, which leaves every RC6 control untouched.
    rc6: Option<u32>,
    /// The function's BAR, for the display's Gen9 `DC_off` service.
    bar: narf_bus::bar::MmioRegion,
    /// `gt->awake`: the Gen9 `GT_IRQ` reference held while unparked
    /// (`__gt_unpark`), inert without the Gen9 DC service (Gen11, or the
    /// option clear) and `None` when its DC exit was refused.
    gt_irq: Option<crate::intel_gpu_gen9_dc_states::Gen9DcRef>,
}

impl Runtime {
    /// `intel_rc6_unpark` + `intel_rps_unpark`: take forcewake back, leave
    /// RC6 and request the efficient frequency before touching the engine.
    /// Forcewake is acquired first, so a refused wake leaves the GT parked.
    fn unpark(&mut self) -> Result<(), FsError> {
        if !self.governor.parked() {
            return Ok(());
        }
        // __gt_unpark takes POWER_DOMAIN_GT_IRQ first: DC states stay off
        // while the GT is awake (a latency workaround; best effort).
        if self.gt_irq.is_none() {
            self.gt_irq = crate::intel_gpu_gen9_dc_states::gt_unparked(&self.bar);
        }
        self.fw
            .acquire(&self.window, FwDomain::Render)
            .map_err(|_| crate::intel_gpu_user::io_error())?;
        if self.fw.acquire(&self.window, FwDomain::Blitter).is_err() {
            let _ = self.fw.release(&self.window, FwDomain::Render);
            return Err(crate::intel_gpu_user::io_error());
        }
        if !self.acquire_media() {
            let _ = self.fw.release(&self.window, FwDomain::Blitter);
            let _ = self.fw.release(&self.window, FwDomain::Render);
            return Err(crate::intel_gpu_user::io_error());
        }
        let window = &self.window;
        if let Some(ctl) = self.rc6 {
            rc6_unpark(ctl, |r, v| window.write32(r, v));
        }
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
        if self.rc6.is_some() {
            rc6_park(|r, v| window.write32(r, v));
        }
        self.release_media();
        let _ = self.fw.release(&self.window, FwDomain::Blitter);
        let _ = self.fw.release(&self.window, FwDomain::Render);
        // __gt_park: GT_IRQ released last, with its 100 ms async put.
        self.gt_irq = None;
    }

    /// Every media well a media lane needs; on failure nothing extra is held.
    fn acquire_media(&mut self) -> bool {
        let domains: Vec<_> = self
            .xcs
            .iter()
            .filter_map(|lane| media_domain(self.gt, lane.which))
            .collect();
        let mut held = Vec::new();
        for domain in domains {
            if held.contains(&domain) {
                continue;
            }
            if self.media_fw.acquire(&self.window, domain).is_err() {
                for domain in held {
                    let _ = self.media_fw.release(&self.window, domain);
                }
                return false;
            }
            held.push(domain);
        }
        true
    }

    fn release_media(&mut self) {
        let mut released = Vec::new();
        for lane in &self.xcs {
            if let Some(domain) = media_domain(self.gt, lane.which) {
                if !released.contains(&domain) {
                    let _ = self.media_fw.release(&self.window, domain);
                    released.push(domain);
                }
            }
        }
    }

    /// The hardware engine and context for `user`'s engine.
    fn context_for(
        &mut self,
        user: &Arc<UserContext>,
    ) -> Result<(&mut Engine, ContextId), SubmitError> {
        let which = user.engine();
        if which == HwEngine::Rcs0 {
            let id = context_on(&mut self.engine, &mut self.contexts, &self.ctx_wa, user)?;
            return Ok((&mut self.engine, id));
        }
        let lane = self
            .xcs
            .iter_mut()
            .find(|lane| lane.which == which)
            .ok_or(SubmitError::NoEngine)?;
        let id = context_on(&mut lane.engine, &mut lane.contexts, &[], user)?;
        Ok((&mut lane.engine, id))
    }

    /// Retire landed jobs and drop hardware contexts whose user context is
    /// gone. [`Service::Lost`] when a completion could not be proven (only a
    /// GT reset recovers), [`Service::Hung`] when a job outlived its deadline.
    fn service(&mut self, now: u64) -> Service {
        let mut done: Vec<_> = self
            .engine
            .poll_completions()
            .into_iter()
            .map(|done| (HwEngine::Rcs0, done.request))
            .collect();
        for lane in &mut self.xcs {
            let which = lane.which;
            done.extend(
                lane.engine
                    .poll_completions()
                    .into_iter()
                    .map(|d| (which, d.request)),
            );
        }
        for (which, request) in done {
            if let Some(i) = self
                .jobs
                .iter()
                .position(|j| j.which == which && j.request == request)
            {
                self.jobs.swap_remove(i).job.finish(false);
            }
        }
        // Rotate an engine whose ELSP[0] has used its slice while another
        // context waits (Linux's execlists timeslice timer).
        self.engine.timeslice(now);
        for lane in &mut self.xcs {
            lane.engine.timeslice(now);
        }
        let engine = &mut self.engine;
        self.contexts.retain(|context| {
            context.user.strong_count() != 0 || engine.destroy_context(context.id).is_err()
        });
        for lane in &mut self.xcs {
            let engine = &mut lane.engine;
            lane.contexts.retain(|context| {
                context.user.strong_count() != 0 || engine.destroy_context(context.id).is_err()
            });
        }
        if self.engine.completion_lost() || self.xcs.iter().any(|l| l.engine.completion_lost()) {
            return Service::Lost;
        }
        if let Some(job) = self.jobs.iter().find(|job| now >= job.deadline) {
            return Service::Hung(job.which, job.request);
        }
        {
            let busy = !self.jobs.is_empty()
                || !self.engine.is_idle()
                || self.xcs.iter().any(|l| !l.engine.is_idle());
            match self.governor.tick(now, busy) {
                Some(Step::Request(freq)) => {
                    let window = &self.window;
                    rps_request(freq, |r, v| window.write32(r, v));
                }
                Some(Step::Park(idle)) => self.park(idle),
                None => {}
            }
        }
        Service::Ok
    }
}

pub(crate) struct Owner {
    index: u32,
    platform: GtPlatform,
    wa: WaPlatform,
    revision: u8,
    /// PCI device ID (`WaRsDisableCoarsePowerGating`'s Skylake GT3/GT4).
    device: u16,
    /// The data stolen memory from PCI config, which Gen9 LP's BIOS RC6
    /// check places the RC6 context in.
    dsm: Option<(u64, u64)>,
    bar: narf_bus::bar::MmioRegion,
    card: Arc<crate::drm_devfs_bridge::IntelGpuCard>,
    state: Mutex<Option<Runtime>>,
    epoch: AtomicU64,
    clock: AtomicU64,
    /// The published engine set's bits (RCS0 plus the lanes that came up).
    engines: core::sync::atomic::AtomicU32,
    topology: narf_lib::sync::IrqSafeSpinLock<Option<crate::intel_gpu_legacy_gt::LegacyTopology>>,
    /// The system-sleep gate ([`SleepGate`], `narf.intel.execlists_suspend=1`).
    sleep: narf_lib::sync::IrqSafeSpinLock<SleepGate>,
    /// A runtime is installed (set after bring-up stores it, cleared when a
    /// stop takes it): the device-PM late check refuses while it is.
    live: core::sync::atomic::AtomicBool,
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
        // The engine's execlists layout: Gen9 LP shares big-core Gen9's
        // context image, CSB and indirect-context batch.
        let generation = match self.wa.gt() {
            LegacyGt::Gen9 | LegacyGt::Gen9Lp => crate::intel_gpu::Generation::Skylake,
            LegacyGt::Gen11 => crate::intel_gpu::Generation::IceLake,
        };
        let mut engine = RcsEngine::new_for_generation(
            generation,
            BarWindow::new(self.bar),
            crate::intel_gpu_rcs::production_arena(self.bar),
        )
        .map_err(InitError::Engine)?;
        engine.set_pooled_eu(self.topology.lock().is_some_and(|t| t.pooled_eu()));
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
        // BCS0, VCS0 and VECS0, with their media wells held from here:
        // intel_rc6_enable (and Gen9 LP's BIOS check) reach every engine's
        // idle count under FORCEWAKE_ALL. A lane whose well is refused is
        // left out.
        let mut media_fw = MediaForcewake::new();
        let lanes: Vec<_> = xcs_engines(gt, |r| window.read32(r))
            .into_iter()
            .filter(|&(which, _)| match media_domain(gt, which) {
                Some(domain) if media_fw.acquire(&window, domain).is_err() => {
                    log(self.index, "media forcewake refused; engine left out");
                    false
                }
                _ => true,
            })
            .collect();
        let bases: Vec<u64> = core::iter::once(RCS)
            .chain(lanes.iter().map(|(_, spec)| spec.base))
            .collect();
        let rc6 = rc6_supported(gt, self.dsm, |r| window.read32(r))
            .then(|| rc6_enable(gt, self.device, &bases, |r, v| window.write32(r, v)));
        match rc6 {
            Some(ctl) => rc6_unpark(ctl, |r, v| window.write32(r, v)),
            None => log(self.index, "RC6 and powersaving disabled by BIOS"),
        }
        // Each lane is its own execlists engine on the shared arena. An
        // engine that does not come up is left out of the published set;
        // RCS0 still runs.
        let mut xcs = Vec::new();
        for (which, spec) in lanes {
            resume_xcs(&window, gt, which, spec.base);
            let lane = RcsEngine::with_spec_for_generation(
                spec,
                generation,
                BarWindow::new(self.bar),
                crate::intel_gpu_rcs::production_arena(self.bar),
            )
            .and_then(|mut engine| match engine.reset_csb_pointers() {
                Ok(()) => Ok(engine),
                Err(error) => {
                    // SAFETY: nothing was submitted on this engine.
                    unsafe { engine.release_after_reset() };
                    Err(error)
                }
            });
            match lane {
                Ok(engine) => xcs.push(Lane {
                    which,
                    engine,
                    contexts: Vec::new(),
                }),
                Err(_) => {
                    if let Some(domain) = media_domain(gt, which) {
                        let _ = media_fw.release(&window, domain);
                    }
                    log(self.index, "copy/media engine did not come up; left out");
                }
            }
        }
        let engines = core::iter::once(HwEngine::Rcs0)
            .chain(xcs.iter().map(|lane| lane.which))
            .collect::<Vec<_>>();
        self.engines.store(
            crate::intel_gpu_engine::EngineSet::of(&engines).bits(),
            Ordering::Release,
        );
        let epoch = crate::intel_gpu_user::next_epoch();
        *self.state.lock().await = Some(Runtime {
            engine,
            xcs,
            gt,
            fw,
            media_fw,
            window,
            epoch,
            ctx_wa,
            contexts: Vec::new(),
            jobs: Vec::new(),
            governor: Governor::new(caps),
            steering,
            rc6,
            bar: self.bar,
            // Bring-up leaves the GT awake: __gt_unpark's GT_IRQ is held.
            gt_irq: crate::intel_gpu_gen9_dc_states::gt_unparked(&self.bar),
        });
        self.live.store(true, Ordering::Release);
        self.epoch.store(epoch, Ordering::Release);
        Ok(())
    }

    /// Unpublish, reset the GT so nothing references the engine's memory,
    /// then release it: every pending fence fails with a reset and every
    /// context involved is banned.
    async fn tear_down(&self) {
        self.stop_gt(false).await;
    }

    /// [`Self::tear_down`]; for system sleep (`sleep`) in
    /// `intel_gt_suspend_late`'s order: RPS and RC6 disabled
    /// (`intel_rps_disable`, `intel_rc6_disable`) before the full-domain
    /// reset (`gt_sanitize`). The `GT_IRQ` reference goes with the runtime,
    /// also when the reset did not complete and the memory stays retained.
    async fn stop_gt(&self, sleep: bool) {
        self.epoch.store(0, Ordering::Release);
        let Some(mut runtime) = self.state.lock().await.take() else {
            return;
        };
        self.live.store(false, Ordering::Release);
        // The reset sequence needs the render well awake; a refused wake
        // still attempts it.
        let _ = runtime.unpark();
        if sleep {
            rps_disable(|r, v| runtime.window.write32(r, v));
            if runtime.rc6.is_some() {
                rc6_disable(|r, v| runtime.window.write32(r, v));
            }
        }
        let mut reset = Reset::new();
        let result = loop {
            match reset.poll(&runtime.window, narf_time::monotonic_ns()) {
                Poll::Pending => sleep_us(20).await,
                Poll::Ready(result) => break result,
            }
        };
        if !sleep && runtime.rc6.is_some() {
            rc6_disable(|r, v| runtime.window.write32(r, v));
        }
        runtime.release_media();
        let _ = runtime.fw.release(&runtime.window, FwDomain::Blitter);
        let _ = runtime.fw.release(&runtime.window, FwDomain::Render);
        if result.is_err() {
            // The GT never confirmed the reset; its memory stays retained.
            log(self.index, "reset did not complete; GT closed");
            // __gt_park's GT_IRQ put still happens: DC states (Gen9 LP DC9)
            // must not stay refused behind a closed GT.
            drop(runtime.gt_irq.take());
            core::mem::forget(runtime);
            return;
        }
        for job in runtime.jobs.drain(..) {
            job.job.finish(true);
        }
        // SAFETY: the full-domain reset above completed, so no engine reads
        // or writes any context, ring or batch memory any more.
        unsafe { runtime.engine.release_after_reset() };
        for lane in runtime.xcs.drain(..) {
            // SAFETY: as above; the full-domain reset covers every engine.
            unsafe { lane.engine.release_after_reset() };
        }
    }

    async fn run(self: Arc<Self>) {
        let mut attempts = 0;
        // The card takes one render backend for the owner's life: publish it
        // after the first successful bring-up only. A bring-up after a full
        // GT reset or a system resume reuses it (a second install fails),
        // and a bring-up that succeeds after a failed attempt still
        // publishes it.
        let mut published = false;
        loop {
            // System sleep: once the runtime is gone (stopped for the sleep,
            // or reset while draining) the GT stays down until the resume
            // reopens admission (`intel_gt_resume` is the bring-up below).
            while !self.sleep.lock().admits() {
                sleep_us(1000).await;
            }
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
            if !published {
                let backend = Arc::new(Backend(self.clone()));
                if self.card.install_user_backend(backend).is_err() {
                    log(self.index, "render backend already installed");
                    return;
                }
                published = true;
                log(self.index, "engines published");
            }
            attempts = 0;
            loop {
                // A sleep that began while this runtime was coming up: stop
                // it here, as the preparation would have.
                if self.sleep.lock().asleep() {
                    self.stop_gt(true).await;
                    break;
                }
                let (service, busy) = {
                    let mut state = self.state.lock().await;
                    let Some(runtime) = state.as_mut() else {
                        break;
                    };
                    let service = runtime.service(narf_time::monotonic_ns());
                    (service, !runtime.jobs.is_empty())
                };
                let full_reset = match service {
                    Service::Ok => false,
                    Service::Lost => {
                        log(self.index, "completion lost; resetting the GT");
                        true
                    }
                    Service::Hung(engine, request) => {
                        match self.reset_engine(engine, request).await {
                            Ok(()) => false,
                            Err(_) => {
                                log(
                                    self.index,
                                    "engine reset unavailable or failed; resetting the GT",
                                );
                                true
                            }
                        }
                    }
                };
                if full_reset {
                    self.tear_down().await;
                    break;
                }
                self.pause(if busy { 50 } else { 1000 }).await;
            }
        }
    }

    /// The run loop's pause between service passes. With the Gen9 interrupt
    /// owner installed (`narf.intel.gen9_irq=1`) an interrupt on its vector
    /// ends it early; completions are still proven by the CSB, never by the
    /// interrupt.
    async fn pause(&self, us: u64) {
        match crate::intel_gpu_gen9_irq::vector_for_bar(&self.bar) {
            Some(vector) => {
                let _ =
                    narf_interrupts::wait_for_irq_until(vector, narf_time::Deadline::after_us(us))
                        .await;
            }
            None => sleep_us(us).await,
        }
    }

    /// `intel_engine_reset` for a hung job on `which`: stop and reset that
    /// engine alone, restore its engine state, fail and ban only the hung
    /// context and put every other request back on it
    /// (`__intel_engine_reset_bh`). Every surviving job gets a fresh
    /// deadline. An error, or an engine with no reset domain of its own,
    /// leaves the full GT reset to the caller.
    async fn reset_engine(&self, which: HwEngine, request: u64) -> Result<(), InitError> {
        let mut state = self.state.lock().await;
        let runtime = state.as_mut().ok_or(InitError::Unavailable)?;
        let domain = engine_reset_domain(runtime.gt, which).ok_or(InitError::Unavailable)?;
        let lane = if which == HwEngine::Rcs0 {
            None
        } else {
            Some(
                runtime
                    .xcs
                    .iter()
                    .position(|lane| lane.which == which)
                    .ok_or(InitError::Unavailable)?,
            )
        };
        let base = lane.map_or(RCS, |i| runtime.xcs[i].engine.spec().base);
        runtime.unpark().map_err(|_| InitError::Forcewake)?;
        let mut reset = Reset::engine(base, domain).with_sfc(sfc_lock(runtime.gt, which, base));
        loop {
            match reset.poll(&runtime.window, narf_time::monotonic_ns()) {
                Poll::Pending => sleep_us(20).await,
                Poll::Ready(result) => break result?,
            }
        }
        let (engine, contexts) = match lane {
            None => {
                let mut report = Programmed::default();
                resume_rcs(&runtime.window, self.wa, runtime.steering, &mut report);
                (&mut runtime.engine, &mut runtime.contexts)
            }
            Some(i) => {
                resume_xcs(&runtime.window, runtime.gt, which, base);
                let lane = &mut runtime.xcs[i];
                (&mut lane.engine, &mut lane.contexts)
            }
        };
        // SAFETY: the engine-domain reset above completed, so this engine no
        // longer reads or writes any of its batch, ring or context memory.
        let (guilty, failed) =
            unsafe { engine.reset_rewind_blaming(Some(request)) }.map_err(InitError::Engine)?;
        if let Some(guilty) = guilty {
            contexts
                .retain(|context| context.id != guilty || engine.destroy_context(guilty).is_err());
        }
        let now = narf_time::monotonic_ns();
        for request in failed {
            if let Some(i) = runtime
                .jobs
                .iter()
                .position(|j| j.which == which && j.request == request)
            {
                runtime.jobs.swap_remove(i).job.finish_hung();
            }
        }
        for job in &mut runtime.jobs {
            job.deadline = now.saturating_add(JOB_TIMEOUT_NS);
        }
        log(self.index, "engine reset; the hung context is banned");
        Ok(())
    }

    async fn submit(
        &self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> Result<Arc<CompletionFence>, FsError> {
        // intel_gt_suspend_prepare's unready: no new request once a system
        // sleep began.
        if !self.sleep.lock().admits() {
            return Err(FsError::WouldBlock);
        }
        let epoch = self.epoch.load(Ordering::Acquire);
        if epoch == 0 {
            return Err(FsError::NoDevice);
        }
        let published =
            crate::intel_gpu_engine::EngineSet::from_bits(self.engines.load(Ordering::Acquire));
        if batch.0.platform() != Some(self.platform)
            || !published.contains(context.engine())
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
        let (engine, id) = runtime.context_for(&context).map_err(submit_error)?;
        engine.set_band(id, claim.band()).map_err(submit_error)?;
        let submission = engine.submit_resident(id, batch.0).map_err(submit_error)?;
        let fence = submission.fence.clone();
        runtime.jobs.push(Job {
            which: context.engine(),
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
            engines: crate::intel_gpu_engine::EngineSet::from_bits(
                self.0.engines.load(Ordering::Acquire),
            ),
        })
    }

    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        let clock = self.0.clock.load(Ordering::Acquire) as u32;
        (clock != 0).then(|| crate::intel_gpu_user::DeviceFacts {
            revision: self.0.revision,
            graphics_version: match self.0.wa.gt() {
                LegacyGt::Gen9 | LegacyGt::Gen9Lp => 900,
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
    dsm: Option<(u64, u64)>,
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
        dsm,
        bar,
        card,
        state: Mutex::new(None),
        epoch: AtomicU64::new(0),
        clock: AtomicU64::new(0),
        engines: core::sync::atomic::AtomicU32::new(0),
        topology: narf_lib::sync::IrqSafeSpinLock::new(None),
        sleep: narf_lib::sync::IrqSafeSpinLock::new(SleepGate::new()),
        live: core::sync::atomic::AtomicBool::new(false),
    }));
    true
}

pub(crate) fn start_pending() {
    let pending = core::mem::take(&mut *PENDING.lock());
    let sleep_hooks = suspend_requested(narf_boot::args());
    for owner in pending {
        // System sleep (`narf.intel.execlists_suspend=1`, default off).
        if sleep_hooks {
            let name = alloc::format!("intel-execlists-card{}", owner.index);
            let pm = Arc::new(SleepPm(owner.clone()));
            narf_power::system_pm::register_async_system_pm(&name, pm.clone());
            narf_power::device_pm::register_device_pm_ops(&name, pm);
        }
        narf_scheduler::spawn(async move { owner.run().await });
    }
}

// ── System sleep (`i915_gem_suspend`, `intel_gt_suspend_late`,
//    `intel_gt_resume`) ───────────────────────────────────────────────

/// The boot option that gives the execlists owner its system-PM hooks
/// (default off: without it nothing is registered and a system sleep finds
/// the GT as it is).
pub const SUSPEND_OPT_IN: &str = "narf.intel.execlists_suspend";

/// `narf.intel.execlists_suspend=1`, with the strict grammar every Intel
/// opt-in uses ([`crate::intel_gpu_gt::boot_opt_in`]).
pub fn suspend_requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, SUSPEND_OPT_IN)
}

/// `I915_GT_SUSPEND_IDLE_TIMEOUT` (`HZ / 2`): how long
/// `intel_gt_suspend_prepare` waits for the GT to idle before wedging it.
pub(crate) const SUSPEND_IDLE_TIMEOUT_NS: u64 = 500_000_000;

/// Where a system-sleep transition is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SleepPhase {
    /// No sleep: requests are admitted.
    Awake,
    /// `intel_gt_suspend_prepare`: admission closed (the context bind
    /// unready), outstanding requests draining until `deadline`
    /// (`wait_for_suspend`).
    Draining { deadline: u64 },
    /// `intel_gt_suspend_late` done: RPS and RC6 disabled, the full-domain
    /// reset run (`gt_sanitize`), every engine's memory released and the
    /// `GT_IRQ` reference dropped (`__gt_park`). The owner waits for the
    /// resume.
    Asleep,
}

/// One step of the suspend drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DrainStep {
    /// Requests are outstanding and the timeout has not passed.
    Wait,
    /// The GT is idle.
    Idle,
    /// `wait_for_suspend`'s `-ETIME`: the GT is wedged and its outstanding
    /// requests fail with the stop's reset.
    Wedged,
}

/// The owner's system-sleep gate: admission, the drain decision, the late
/// check and the resume, free of hardware so fixtures drive it directly.
#[derive(Debug)]
pub(crate) struct SleepGate {
    phase: SleepPhase,
}

impl SleepGate {
    pub(crate) const fn new() -> Self {
        Self {
            phase: SleepPhase::Awake,
        }
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn phase(&self) -> SleepPhase {
        self.phase
    }

    /// Whether a new request is admitted.
    pub(crate) fn admits(&self) -> bool {
        self.phase == SleepPhase::Awake
    }

    /// Whether the GT is stopped for the sleep.
    pub(crate) fn asleep(&self) -> bool {
        self.phase == SleepPhase::Asleep
    }

    /// `intel_gt_suspend_prepare`: close admission and start the drain.
    /// `false` (nothing changed) when a sleep is already under way.
    pub(crate) fn begin(&mut self, now: u64) -> bool {
        if self.phase != SleepPhase::Awake {
            return false;
        }
        self.phase = SleepPhase::Draining {
            deadline: now.saturating_add(SUSPEND_IDLE_TIMEOUT_NS),
        };
        true
    }

    /// `wait_for_suspend`: `idle` ends the drain, the passed deadline wedges.
    pub(crate) fn drain_step(&self, idle: bool, now: u64) -> DrainStep {
        match self.phase {
            SleepPhase::Draining { .. } if idle => DrainStep::Idle,
            SleepPhase::Draining { deadline } if now >= deadline => DrainStep::Wedged,
            SleepPhase::Draining { .. } => DrainStep::Wait,
            _ => DrainStep::Idle,
        }
    }

    /// The stop for the sleep completed.
    pub(crate) fn sleep(&mut self) {
        self.phase = SleepPhase::Asleep;
    }

    /// The device-PM late step (interrupts gated): only a GT the
    /// asynchronous preparation stopped (`live` clear) may sleep.
    pub(crate) fn late_ok(&self, live: bool) -> bool {
        self.phase == SleepPhase::Asleep && !live
    }

    /// The resume: admission opens; `true` when the GT was stopped and the
    /// owner brings it up again (`intel_gt_resume`).
    pub(crate) fn resume(&mut self) -> bool {
        let was = self.phase == SleepPhase::Asleep;
        self.phase = SleepPhase::Awake;
        was
    }
}

impl Owner {
    /// The idle the drain waits for: no outstanding job and every engine
    /// idle (or no runtime at all).
    async fn gt_idle(&self) -> bool {
        let state = self.state.lock().await;
        state.as_ref().is_none_or(|runtime| {
            runtime.jobs.is_empty()
                && runtime.engine.is_idle()
                && runtime.xcs.iter().all(|lane| lane.engine.is_idle())
        })
    }

    /// `i915_gem_suspend` → `intel_gt_suspend_prepare` (admission closed,
    /// `wait_for_suspend` with its 500 ms idle timeout, wedging on expiry),
    /// then `intel_gt_suspend_late`'s RPS/RC6 disable and `gt_sanitize`
    /// ([`Self::stop_gt`]), run here while sleeping is still allowed. The
    /// GT's `GT_IRQ` reference is gone afterwards, so the Gen9 `DC_off`
    /// service may admit DC9 at the late step.
    async fn prepare_sleep(&self) {
        if !self.sleep.lock().begin(narf_time::monotonic_ns()) {
            return;
        }
        loop {
            let idle = self.gt_idle().await;
            match self.sleep.lock().drain_step(idle, narf_time::monotonic_ns()) {
                DrainStep::Wait => {}
                DrainStep::Idle => break,
                DrainStep::Wedged => {
                    log(self.index, "GT busy at suspend; outstanding jobs fail");
                    break;
                }
            }
            sleep_us(1000).await;
        }
        self.stop_gt(true).await;
        self.sleep.lock().sleep();
        log(self.index, "GT stopped for system sleep");
    }
}

/// The owner's system-sleep participant.
struct SleepPm(Arc<Owner>);

impl core::fmt::Debug for SleepPm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("legacy::SleepPm").field(&self.0).finish()
    }
}

impl narf_power::system_pm::AsyncSystemPm for SleepPm {
    fn prepare_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        alloc::boxed::Box::pin(async move {
            self.0.prepare_sleep().await;
            Ok(())
        })
    }
    fn resume_from_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        alloc::boxed::Box::pin(async move {
            // The run loop brings the GT up again (`intel_gt_resume`: the
            // reset, `intel_gt_init_hw`, RPS, the engines' resume, RC6).
            if self.0.sleep.lock().resume() {
                log(self.0.index, "GT resuming after system sleep");
            }
            Ok(())
        })
    }
}

impl narf_power::device_pm::DevicePmOps for SleepPm {
    /// The late step, interrupts gated: refuses a GT the asynchronous
    /// preparation did not stop.
    fn suspend(&self) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
        if self
            .0
            .sleep
            .lock()
            .late_ok(self.0.live.load(Ordering::Acquire))
        {
            Ok(())
        } else {
            Err(narf_power::device_pm::DeviceSuspendError::Busy)
        }
    }
    /// The bring-up waits for the asynchronous resume.
    fn resume(&self) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
        Ok(())
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
            // Gen9 LP: the 19.2 MHz crystal.
            || timestamp_frequency(LegacyGt::Gen9Lp, regs(3 << 1, 0, 0)) != 19_200_000
            || timestamp_frequency(LegacyGt::Gen9Lp, regs(2 << 1, 0, 0)) != 9_600_000
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

    /// BCS0, VCS0 and VECS0 beside RCS0 at their Gen9 and Gen11 bases; a
    /// Gen11 VDBox or VEBox fused off is left out (an unreadable fuse
    /// register keeps only the copy engine); each media engine names its
    /// forcewake well.
    fn smoke_legacy_owner_copy_and_media_engines() -> TestResult {
        let bases = |gt, fuse| {
            xcs_engines(gt, |_| fuse)
                .into_iter()
                .map(|(which, spec)| (which, spec.base))
                .collect::<Vec<_>>()
        };
        if bases(LegacyGt::Gen9, 0xffff_ffff)
            != alloc::vec![
                (HwEngine::Bcs0, 0x22000),
                (HwEngine::Vcs0, 0x12000),
                (HwEngine::Vecs0, 0x1a000),
            ]
        {
            return TestResult::Fail("Gen9 copy and media engines");
        }
        if bases(LegacyGt::Gen11, 0)
            != alloc::vec![
                (HwEngine::Bcs0, 0x22000),
                (HwEngine::Vcs0, 0x1c0000),
                (HwEngine::Vecs0, 0x1c8000),
            ]
            || bases(LegacyGt::Gen11, 1)
                != alloc::vec![(HwEngine::Bcs0, 0x22000), (HwEngine::Vecs0, 0x1c8000)]
            || bases(LegacyGt::Gen11, u32::MAX) != alloc::vec![(HwEngine::Bcs0, 0x22000)]
        {
            return TestResult::Fail("Gen11 engines follow GEN11_GT_VEBOX_VDBOX_DISABLE");
        }
        if media_domain(LegacyGt::Gen9, HwEngine::Vecs0) != Some(MediaFwDomain::Aggregate)
            || media_domain(LegacyGt::Gen11, HwEngine::Vcs0) != Some(MediaFwDomain::VdBox(0))
            || media_domain(LegacyGt::Gen11, HwEngine::Vecs0) != Some(MediaFwDomain::VeBox(0))
            || media_domain(LegacyGt::Gen11, HwEngine::Bcs0).is_some()
        {
            return TestResult::Fail("media engines name their forcewake wells");
        }
        let regs = Regs::default();
        resume_xcs(&regs, LegacyGt::Gen9, HwEngine::Vcs0, 0x12000);
        let writes = regs.writes.borrow();
        if !writes.contains(&(0x1229c, 1 << 31 | 1 << 15))
            || !writes.contains(&(0x1209c, 1 << 24))
            || writes.first().map(|w| w.0) != Some(0xc900)
        {
            return TestResult::Fail("VCS0 resume: MOCS bank, execlists mode, ring running");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_owner",
        smoke_legacy_owner_copy_and_media_engines
    );

    /// Per-engine reset domains (`gen6_hw_engine_mask`,
    /// `gen11_hw_engine_mask`), and an engine reset that stops and
    /// handshakes the hung engine's own CS before pulsing only its domain.
    fn smoke_legacy_owner_engine_reset_domains() -> TestResult {
        let expect = [
            (LegacyGt::Gen9, HwEngine::Rcs0, Some(1 << 1)),
            (LegacyGt::Gen9, HwEngine::Bcs0, Some(1 << 3)),
            (LegacyGt::Gen9, HwEngine::Vcs0, Some(1 << 2)),
            (LegacyGt::Gen9, HwEngine::Vecs0, Some(1 << 4)),
            (LegacyGt::Gen11, HwEngine::Rcs0, Some(1 << 1)),
            (LegacyGt::Gen11, HwEngine::Bcs0, Some(1 << 2)),
            (LegacyGt::Gen11, HwEngine::Vcs0, Some(1 << 5)),
            (LegacyGt::Gen11, HwEngine::Vecs0, Some(1 << 13)),
        ];
        if expect
            .iter()
            .any(|&(gt, which, domain)| engine_reset_domain(gt, which) != domain)
        {
            return TestResult::Fail("engine reset domains follow Linux's masks");
        }
        let regs = Regs::default();
        let mut reset = Reset::engine(0x22000, 1 << 3);
        let mut now = 0;
        let done = loop {
            if let Poll::Ready(result) = reset.poll(&regs, now) {
                break result;
            }
            // The domain bit self-clears once the engine reset completes.
            regs.values.borrow_mut().insert(GDRST, 0);
            now += 1000;
        };
        let writes = regs.writes.borrow();
        if done != Ok(())
            || writes.first() != Some(&(0x2209c, masked_enable(STOP_RING)))
            || !writes.contains(&(0x220d0, masked_enable(REQUEST_RESET)))
            || !writes.contains(&(GDRST, 1 << 3))
            || writes.iter().any(|&(r, _)| r == MI_MODE || r == RESET_CTL)
        {
            return TestResult::Fail("BCS0 reset uses BCS0's CS and only the blitter domain");
        }
        // Gen11 VCS0 at 0x1c0000 using its SFC: force-lock, reset the SFC
        // with the engine once acknowledged, then unlock.
        let run = |usage: u32, ack: bool| {
            let regs = Regs::default();
            regs.values.borrow_mut().insert(0x1c0890, usage);
            let sfc = sfc_lock(LegacyGt::Gen11, HwEngine::Vcs0, 0x1c0000);
            let mut reset = Reset::engine(0x1c0000, 1 << 5).with_sfc(sfc);
            let mut now = 0;
            let done = loop {
                if let Poll::Ready(result) = reset.poll(&regs, now) {
                    break result;
                }
                let locked = regs.writes.borrow().contains(&(0x1c088c, 1));
                if locked && ack {
                    regs.values.borrow_mut().insert(0x1c0890, usage | 1 << 1);
                }
                regs.values.borrow_mut().insert(GDRST, 0);
                now += 100_000;
            };
            let writes = regs.writes.borrow().clone();
            (done, writes)
        };
        let at = |writes: &[(u64, u32)], write| writes.iter().position(|w| *w == write);
        let (done, writes) = run(1, true);
        let (lock, pulse, unlock) = (
            at(&writes, (0x1c088c, 1)),
            at(&writes, (GDRST, 1 << 5 | 1 << 17)),
            at(&writes, (0x1c088c, 0)),
        );
        if done != Ok(())
            || !(lock < pulse && pulse < unlock && lock.is_some())
            || at(&writes, (0x1c00d0, masked_disable(REQUEST_RESET))) < unlock
        {
            return TestResult::Fail("a used SFC is locked, reset with VCS0 and unlocked");
        }
        let (done, writes) = run(0, true);
        if done != Ok(())
            || writes.iter().any(|&(r, _)| r == 0x1c088c)
            || at(&writes, (GDRST, 1 << 5)).is_none()
        {
            return TestResult::Fail("an idle SFC is left alone");
        }
        let (done, writes) = run(1, false);
        if done != Err(InitError::ResetTimeout)
            || writes.iter().any(|&(r, _)| r == GDRST)
            || at(&writes, (0x1c088c, 0)).is_none()
        {
            return TestResult::Fail("an unacknowledged SFC lock fails the engine reset");
        }
        let vecs = sfc_lock(LegacyGt::Gen11, HwEngine::Vecs0, 0x1c8000).unwrap();
        if (vecs.lock, vecs.ack, vecs.usage, vecs.reset_bit)
            != (0x1ca01c, 0x1ca018, 0x1ca014, 1 << 17)
            || sfc_lock(LegacyGt::Gen9, HwEngine::Vcs0, 0x12000).is_some()
            || sfc_lock(LegacyGt::Gen11, HwEngine::Bcs0, 0x22000).is_some()
        {
            return TestResult::Fail("SFC lock registers follow get_sfc_forced_lock_data");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_owner",
        smoke_legacy_owner_engine_reset_domains
    );

    /// The system-sleep gate (`intel_gt_suspend_prepare` /
    /// `wait_for_suspend` / `intel_gt_resume`): a sleep closes admission and
    /// drains, idle ends the drain and the 500 ms `I915_GT_SUSPEND_IDLE_TIMEOUT`
    /// wedges; the late step admits only a stopped GT with no live runtime;
    /// the resume reopens admission and asks for the bring-up once.
    fn smoke_legacy_owner_sleep_gate() -> TestResult {
        use narf_boot::args::KernelCmdline;
        if SUSPEND_IDLE_TIMEOUT_NS != 500_000_000
            || SUSPEND_OPT_IN != "narf.intel.execlists_suspend"
            || !suspend_requested(KernelCmdline::new("narf.intel.execlists_suspend=1"))
            || suspend_requested(KernelCmdline::new(""))
            || suspend_requested(KernelCmdline::new("narf.intel.execlists_suspend=2"))
        {
            return TestResult::Fail("I915_GT_SUSPEND_IDLE_TIMEOUT and the strict opt-in");
        }
        let mut gate = SleepGate::new();
        if !gate.admits() || gate.asleep() || gate.late_ok(false) {
            return TestResult::Fail("an awake GT admits and may not sleep");
        }
        if !gate.begin(1_000) || gate.begin(2_000) || gate.admits() {
            return TestResult::Fail("one sleep at a time, admission closed at once");
        }
        if gate.phase()
            != (SleepPhase::Draining {
                deadline: 1_000 + 500_000_000,
            })
        {
            return TestResult::Fail("the drain deadline is the idle timeout");
        }
        if gate.drain_step(false, 400_000_000) != DrainStep::Wait
            || gate.drain_step(true, 400_000_000) != DrainStep::Idle
            || gate.drain_step(false, 500_001_000) != DrainStep::Wedged
        {
            return TestResult::Fail("wait while busy, stop when idle, wedge at the timeout");
        }
        if gate.late_ok(false) {
            return TestResult::Fail("a draining GT may not sleep");
        }
        gate.sleep();
        if !gate.asleep() || gate.admits() || gate.late_ok(true) || !gate.late_ok(false) {
            return TestResult::Fail("only a stopped GT with no live runtime may sleep");
        }
        if !gate.resume() || !gate.admits() || gate.resume() {
            return TestResult::Fail("the resume brings the GT up once and reopens admission");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_owner",
        smoke_legacy_owner_sleep_gate
    );

    /// `intel_gt_suspend_late`'s register half: `gen6_rps_disable` clears
    /// `GEN6_RP_CONTROL` (0xA024), and `__intel_rc6_disable` clears
    /// `GEN9_PG_ENABLE`, `GEN6_RC_CONTROL` and `GEN6_RC_STATE`, in that order.
    fn smoke_legacy_owner_sleep_disables_rps_and_rc6() -> TestResult {
        let mut writes = Vec::new();
        rps_disable(|r, v| writes.push((r, v)));
        rc6_disable(|r, v| writes.push((r, v)));
        if writes != alloc::vec![(0xa024, 0), (0xa210, 0), (0xa090, 0), (0xa094, 0)] {
            return TestResult::Fail("RP_CONTROL, then PG_ENABLE, RC_CONTROL and RC_STATE");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_owner",
        smoke_legacy_owner_sleep_disables_rps_and_rc6
    );
}
