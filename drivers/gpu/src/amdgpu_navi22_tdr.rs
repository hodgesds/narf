//! Navi22 kernel-queue hang detection. Linux arms a drm_sched job timer
//! (`adev->{gfx,compute,sdma}_timeout`, 2 s by default since
//! `amdgpu_device_get_job_timeout_settings`) when a job reaches the ring and
//! re-arms it on each completion; `amdgpu_job_timedout` then reports
//! "ring %s timeout, signaled seq=%u, emitted seq=%u" and, with
//! `amdgpu_gpu_recovery`, starts recovery. NARF kernel queues have no job
//! scheduler, so this watchdog samples each queue's emitted sequence and its
//! fence writeback: a queue with unsignalled work whose fence has not moved
//! for the timeout is hung. Like drm_sched it runs only while a job is in
//! flight: an emitted job wakes it, it samples again at the earliest pending
//! job's timeout, and with nothing pending it arms no timer. Detection is always active and logs once per
//! stall. Like Linux's default `amdgpu_gpu_recovery=-1` on a dGPU, a hang
//! starts recovery (`set_automatic_recovery`, on by default for RX 6000;
//! `amdgpu.gpu_recovery=0` turns it off), at most
//! [`MAX_AUTOMATIC_RECOVERIES`] times per boot: each Navi22 recovery
//! quarantines (leaks) the old owners' VRAM, so a card that keeps hanging is
//! left stopped rather than recovered until VRAM runs out. Raphael re-arms
//! its owners in place, but keeps the same budget.
use crate::amdgpu_fence_navi22::{signaled, Engine};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

/// Linux default lockup timeout for every kernel queue.
// linux: n/a (literal msecs_to_jiffies(2000) in amdgpu_device.c:amdgpu_device_get_job_timeout_settings)
pub const TIMEOUT_MS: u64 = 2000;
/// Retry period while the owner is busy (a sample could not be taken).
pub const PERIOD_MS: u64 = 250; // linux: n/a (NARF retry period)
const ENGINES: usize = crate::amdgpu_fence_navi22::ENGINES;

/// One queue's software (emitted) and hardware (signalled) fence sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub engine: Engine,
    pub emitted: u32,
    pub signaled: u32,
}

/// One detected stall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hang {
    pub engine: Engine,
    pub emitted: u32,
    pub signaled: u32,
    pub stalled_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Every emitted fence has signalled.
    Idle,
    /// Work pending and the fence moved (or the timer is still running).
    Busy,
    /// First observation past the timeout for this stall.
    Hung(Hang),
    /// The same stall, already reported.
    StillHung,
}

#[derive(Clone, Copy, Debug, Default)]
struct Slot {
    busy: bool,
    signaled: u32,
    since_ms: u64,
    hung: bool,
}

/// Pure per-engine timer state, as drm_sched's per-ring job timeout.
#[derive(Debug)]
pub(crate) struct Watchdog {
    timeout_ms: u64,
    slots: [Slot; ENGINES],
}
impl Watchdog {
    pub(crate) fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            slots: [Slot::default(); ENGINES],
        }
    }
    pub(crate) fn observe(&mut self, p: Progress, now_ms: u64) -> Verdict {
        let slot = &mut self.slots[p.engine as usize];
        if signaled(p.signaled, p.emitted) {
            *slot = Slot {
                busy: false,
                signaled: p.signaled,
                since_ms: now_ms,
                hung: false,
            };
            return Verdict::Idle;
        }
        // The timer starts when work is first seen pending and restarts on
        // every fence advance (drm_sched_job_done re-arms the next job).
        if !slot.busy || slot.signaled != p.signaled {
            *slot = Slot {
                busy: true,
                signaled: p.signaled,
                since_ms: now_ms,
                hung: false,
            };
            return Verdict::Busy;
        }
        let stalled_ms = now_ms.saturating_sub(slot.since_ms);
        if stalled_ms < self.timeout_ms {
            return Verdict::Busy;
        }
        if slot.hung {
            return Verdict::StillHung;
        }
        slot.hung = true;
        Verdict::Hung(Hang {
            engine: p.engine,
            emitted: p.emitted,
            signaled: p.signaled,
            stalled_ms,
        })
    }
}

/// Published detector state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub samples: u64,
    pub hangs: u64,
    pub last: Option<Hang>,
    /// The sampler lost the device (all-ones/revoked) and stopped.
    pub device_lost: bool,
    pub automatic_recovery: bool,
}
static STATUS: IrqSafeSpinLock<Status> = IrqSafeSpinLock::new(Status {
    samples: 0,
    hangs: 0,
    last: None,
    device_lost: false,
    automatic_recovery: false,
});
static EPOCH: AtomicU64 = AtomicU64::new(0);
static AUTOMATIC: AtomicBool = AtomicBool::new(false);
/// Automatic recoveries allowed per boot (explicit `recover()` calls are not
/// counted).
pub const MAX_AUTOMATIC_RECOVERIES: u64 = 3;
static AUTOMATIC_RECOVERIES: AtomicU64 = AtomicU64::new(0);
/// Test-only: restore the full budget.
#[cfg(feature = "kernel-test")]
pub(crate) fn __reset_automatic_recoveries() {
    AUTOMATIC_RECOVERIES.store(0, Ordering::Release);
}
/// Claim one automatic recovery; `false` once the boot's budget is spent.
pub(crate) fn claim_automatic_recovery() -> bool {
    AUTOMATIC_RECOVERIES
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
            (used < MAX_AUTOMATIC_RECOVERIES).then_some(used + 1)
        })
        .is_ok()
}
pub fn status() -> Status {
    Status {
        automatic_recovery: AUTOMATIC.load(Ordering::Acquire),
        ..*STATUS.lock()
    }
}
/// Linux's `amdgpu_gpu_recovery`: a detected hang starts
/// `amdgpu_navi22_platform::recover`. The fb boot handoff enables it unless
/// `amdgpu.gpu_recovery=0`.
///
/// # Safety
/// The caller accepts recovery's contract (`recover`): every kernel queue's
/// in-flight work is abandoned, the card's display goes dark, and every
/// kernel CPU writer of the boot framebuffer is behind the console hook
/// (`amdgpu_navi22_platform::set_recovery_console_hook`). User CPU mappings
/// of VRAM are not revoked, as in Linux: their accesses during the reset go
/// to an unresponsive BAR and the contents are lost afterwards.
pub unsafe fn set_automatic_recovery(enabled: bool) {
    AUTOMATIC.store(enabled, Ordering::Release);
}

/// Fold one sample set into the detector and status. Returns new hangs.
pub(crate) fn record(
    watchdog: &mut Watchdog,
    samples: &[Progress],
    now_ms: u64,
) -> alloc::vec::Vec<Hang> {
    let mut hangs = alloc::vec::Vec::new();
    for &p in samples {
        if let Verdict::Hung(hang) = watchdog.observe(p, now_ms) {
            hangs.push(hang);
        }
    }
    let mut status = STATUS.lock();
    status.samples += 1;
    status.hangs += hangs.len() as u64;
    if let Some(&last) = hangs.last() {
        status.last = Some(last);
    }
    hangs
}

/// When the detector samples next, in ms from `now_ms`: at the earliest
/// pending job's timeout (drm_sched's `work_tdr`, re-armed by progress);
/// `None` with nothing pending, or only hangs already reported, until a job
/// is emitted.
pub(crate) fn next_sample(watchdog: &Watchdog, now_ms: u64) -> Option<u64> {
    watchdog
        .slots
        .iter()
        .filter(|s| s.busy && !s.hung)
        .map(|s| {
            s.since_ms
                .saturating_add(watchdog.timeout_ms)
                .saturating_sub(now_ms)
        })
        .min()
}

/// A job was emitted on a kernel queue since the detector's last sample.
static JOBS: AtomicBool = AtomicBool::new(false);
/// The detector while no job is in flight.
static JOB_WAKER: IrqSafeSpinLock<Option<core::task::Waker>> = IrqSafeSpinLock::new(None);

/// Work was emitted on a kernel queue (`Queue::next_seq`): the job start at
/// which drm_sched arms its timeout. Wakes a parked detector.
pub(crate) fn job_emitted() {
    JOBS.store(true, Ordering::Release);
    wake_detector();
}

fn wake_detector() {
    let waker = JOB_WAKER.lock().take();
    if let Some(w) = waker {
        w.wake();
    }
}

/// Resolves after the next [`job_emitted`] (at once if one came since the
/// last sample).
fn job_emitted_wait() -> impl core::future::Future<Output = ()> {
    core::future::poll_fn(|cx| {
        // Registered before the check: `job_emitted` publishes, then wakes.
        {
            let mut slot = JOB_WAKER.lock();
            if !slot.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                *slot = Some(cx.waker().clone());
            }
        }
        if JOBS.swap(false, Ordering::AcqRel) {
            core::task::Poll::Ready(())
        } else {
            core::task::Poll::Pending
        }
    })
}

/// Detector task for one owner generation; exits on `stop` or device loss.
pub(crate) async fn monitor(epoch: u64, generation: u64) {
    use core::fmt::Write;
    let mut watchdog = Watchdog::new(TIMEOUT_MS);
    // The first sample covers work emitted before the detector started.
    let mut next = Some(0);
    loop {
        match next {
            Some(ms) => {
                narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
            }
            // No job in flight: nothing runs until one is emitted.
            None => job_emitted_wait().await,
        }
        if EPOCH.load(Ordering::Acquire) != epoch {
            return;
        }
        // A job emitted from here on is in this sample or wakes the next park.
        JOBS.store(false, Ordering::Release);
        let who = crate::amdgpu_rdna2_client::name();
        let samples = match crate::amdgpu_rdna2_client::queue_progress().await {
            Ok(samples) => samples,
            Err(crate::amdgpu_navi22_boot::Error::Busy) => {
                // Owner busy: try again shortly.
                next = Some(PERIOD_MS);
                continue;
            }
            Err(_) => {
                crate::amdgpu_navi22_cs::abandon(narf_filesystem::FsError::NoDevice);
                STATUS.lock().device_lost = true;
                return;
            }
        };
        if EPOCH.load(Ordering::Acquire) != epoch {
            return;
        }
        let now_ms = narf_time::wall::cycles_to_ns(narf_time::now_cycles()) / 1_000_000;
        let raphael =
            crate::amdgpu_rdna2_client::backend() == crate::amdgpu_rdna2_client::Backend::Raphael;
        for hang in record(&mut watchdog, &samples, now_ms) {
            // amdgpu_job_timedout's first rung, Raphael only so far: a GFX or
            // compute job whose waves die lets its ring go on.
            if raphael && crate::amdgpu_navi22_cs::soft_recover(hang.engine, generation).await {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: raphael ring {:?} timeout, but soft recovered",
                    hang.engine
                );
                continue;
            }
            // The next rung: reset that queue alone.
            if raphael && matches!(hang.engine, Engine::Compute | Engine::Gfx) {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: raphael starting {:?} ring reset",
                    hang.engine
                );
                if crate::amdgpu_navi22_cs::reset_queue(hang.engine, generation).await {
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: raphael ring {:?} reset succeeded",
                        hang.engine
                    );
                    continue;
                }
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: raphael ring {:?} reset failed",
                    hang.engine
                );
            }
            crate::amdgpu_navi22_cs::hung(hang.engine, generation);
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: {who} ring {:?} timeout, signaled seq={}, emitted seq={} ({} ms)",
                hang.engine,
                hang.signaled,
                hang.emitted,
                hang.stalled_ms
            );
            if hang.engine == Engine::Gfx {
                match crate::amdgpu_rdna2_client::gfx_hang_snapshot().await {
                    Ok(snapshot) => snapshot.report(),
                    Err(error) => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "amdgpu: {who} Gfx hang snapshot {error:?}"
                        );
                    }
                }
            }
            if raphael {
                // The last rung: the whole-device mode 2 reset, under the
                // same per-boot budget as Navi22's recovery.
                if !crate::amdgpu_platform::gpu_recovery_enabled() {
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: raphael GPU recovery disabled (amdgpu.gpu_recovery=0)"
                    );
                    continue;
                }
                if !claim_automatic_recovery() {
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: raphael GPU recovery limit ({MAX_AUTOMATIC_RECOVERIES} per boot) reached; the GPU stays hung"
                    );
                    continue;
                }
                let result = crate::amdgpu_platform::recover().await;
                let _ = writeln!(narf_console::Writer, "amdgpu: raphael recovery {result:?}");
                return; // a recovered owner starts a fresh detector
            }
            if AUTOMATIC.load(Ordering::Acquire) {
                if claim_automatic_recovery() {
                    // SAFETY: the caller of set_automatic_recovery accepted
                    // recover()'s contract on behalf of every queue user.
                    let result = unsafe { crate::amdgpu_navi22_platform::recover() }.await;
                    let _ = writeln!(narf_console::Writer, "amdgpu: navi22 recovery {result:?}");
                    return; // a recovered owner starts a fresh detector
                }
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 GPU recovery limit ({MAX_AUTOMATIC_RECOVERIES} per boot) reached; the GPU stays hung"
                );
                continue;
            }
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 GPU recovery disabled (amdgpu.gpu_recovery=0)"
            );
        }
        next = next_sample(&watchdog, now_ms);
    }
}

/// Start a detector for the current owner; any previous one exits.
pub(crate) fn start() {
    let epoch = EPOCH.fetch_add(1, Ordering::AcqRel) + 1;
    wake_detector();
    narf_scheduler::spawn(monitor(epoch, crate::amdgpu_fence_navi22::generation()));
}
/// Stop the detector (recovery quiesce or device loss); a parked one is
/// woken to exit.
pub(crate) fn stop() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
    wake_detector();
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_tdr_tests.rs"]
mod tests;
