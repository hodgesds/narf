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
//! [`MAX_AUTOMATIC_RECOVERIES`] times per boot: each recovery quarantines
//! (leaks) the old owners' VRAM, so a card that keeps hanging is left
//! stopped rather than recovered until VRAM runs out.
//!
//! Client media rings (VCN decode/encode, JPEG) are timed the same way,
//! each on its own, with Linux's `video_timeout` (also 2 s). A VCN timeout
//! resets that VCN instance first, as Linux's per-queue reset does, and
//! recovers the GPU only when that fails (see `media_timeout`).
use crate::amdgpu_fence_navi22::{signaled, Engine};
use crate::amdgpu_navi22_submit::MediaRing;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

/// Linux default lockup timeout for every kernel queue and, as
/// `video_timeout`, every client media ring.
// linux: n/a (literal msecs_to_jiffies(2000) in amdgpu_device.c:amdgpu_device_get_job_timeout_settings)
pub const TIMEOUT_MS: u64 = 2000;
/// Retry period while the owner is busy (a sample could not be taken).
pub const PERIOD_MS: u64 = 250; // linux: n/a (NARF retry period)
const ENGINES: usize = crate::amdgpu_fence_navi22::ENGINES;
/// One timer per fence engine's kernel queue, then one per client media
/// ring (Linux: one drm_sched per VCN decode/encode and JPEG ring).
const SLOTS: usize = ENGINES + MediaRing::ALL.len();
fn slot(p: &Progress) -> usize {
    p.media
        .map_or(p.engine as usize, |ring| ENGINES + ring.index())
}

/// One queue's software (emitted) and hardware (signalled) fence sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub engine: Engine,
    /// The client media ring on `engine` (VCN decode/encode, JPEG), each
    /// with its own sequence as each has its own drm_sched in Linux; None
    /// for a kernel queue.
    pub media: Option<MediaRing>,
    pub emitted: u32,
    pub signaled: u32,
}

/// One detected stall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hang {
    pub engine: Engine,
    pub media: Option<MediaRing>,
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

/// Pure per-ring timer state, as drm_sched's per-ring job timeout.
#[derive(Debug)]
pub(crate) struct Watchdog {
    timeout_ms: u64,
    slots: [Slot; SLOTS],
}
impl Watchdog {
    pub(crate) fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            slots: [Slot::default(); SLOTS],
        }
    }
    pub(crate) fn observe(&mut self, p: Progress, now_ms: u64) -> Verdict {
        let slot = &mut self.slots[slot(&p)];
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
            media: p.media,
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

/// Test-only: whether a job was emitted since the last call (clears it).
#[cfg(feature = "kernel-test")]
pub(crate) fn __take_job_emitted() -> bool {
    JOBS.swap(false, Ordering::AcqRel)
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
        let samples = match crate::amdgpu_navi22_platform::queue_progress().await {
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
        for hang in record(&mut watchdog, &samples, now_ms) {
            if let Some(ring) = hang.media {
                if media_timeout(hang, ring, generation).await {
                    return; // a recovered owner starts a fresh detector
                }
                continue;
            }
            crate::amdgpu_navi22_cs::hung(hang.engine, generation);
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 ring {:?} timeout, signaled seq={}, emitted seq={} ({} ms)",
                hang.engine,
                hang.signaled,
                hang.emitted,
                hang.stalled_ms
            );
            if hang.engine == Engine::Gfx {
                match crate::amdgpu_navi22_platform::gfx_hang_snapshot().await {
                    Ok(snapshot) => snapshot.report(),
                    Err(error) => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "amdgpu: navi22 Gfx hang snapshot {error:?}"
                        );
                    }
                }
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

/// What `amdgpu_job_timedout` does first with a client media ring's
/// timeout on bare metal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MediaAction {
    /// `amdgpu_gpu_recovery=0`: `-ETIME` on the job and
    /// `drm_sched_suspend_timeout`; nothing is reset and the job waits for
    /// its fence.
    Suspend,
    /// The per-queue reset of the ring's VCN instance
    /// (`amdgpu_vcn_ring_reset`); `Recover` if it fails.
    ResetEngine,
    /// No per-queue reset: `-ETIME` and `amdgpu_device_gpu_recover`.
    Recover,
}
/// `amdgpu_job_timedout`'s first step for media ring `ring`, with Linux
/// `amdgpu_gpu_recovery` set as `automatic`: a VCN 3.0 ring has
/// `AMDGPU_RESET_TYPE_PER_QUEUE` and a reset hook; NARF has no JPEG ring
/// reset (Linux's backs up and re-emits other contexts' work).
pub(crate) fn media_action(automatic: bool, ring: MediaRing) -> MediaAction {
    match (automatic, ring) {
        (false, _) => MediaAction::Suspend,
        (true, MediaRing::Jpeg) => MediaAction::Recover,
        (true, _) => MediaAction::ResetEngine,
    }
}
/// The Linux ring name (`vcn_v3_0_sw_init`, `jpeg_v3_0_sw_init`).
fn ring_name(ring: MediaRing) -> &'static str {
    match ring {
        MediaRing::Dec => "vcn_dec_0",
        MediaRing::Enc(0) => "vcn_enc_0.0",
        MediaRing::Enc(_) => "vcn_enc_0.1",
        MediaRing::Jpeg => "jpeg_dec",
    }
}

/// A client job on media ring `ring` timed out: Linux `amdgpu_job_timedout`
/// on bare metal. True when a whole-GPU recovery ran (the detector exits).
///
/// With `amdgpu.gpu_recovery=0` the job gets `-ETIME` once its fence lands
/// and waits meanwhile (`drm_sched_suspend_timeout`). Otherwise a VCN ring
/// resets its instance (`amdgpu_vcn_reset_engine`): on success every
/// outstanding job of the instance ends with `-ECANCELED` and the rings keep
/// serving. A failed reset, or a JPEG timeout, sets `-ETIME` and recovers
/// the GPU (`amdgpu_device_gpu_recover`) as a kernel-queue hang does, within
/// the same per-boot budget; past it the job waits as without recovery.
async fn media_timeout(hang: Hang, ring: MediaRing, generation: u64) -> bool {
    use core::fmt::Write;
    let name = ring_name(ring);
    let mut w = narf_console::Writer;
    let _ = writeln!(
        w,
        "amdgpu: navi22 ring {name} timeout, signaled seq={}, emitted seq={} ({} ms)",
        hang.signaled, hang.emitted, hang.stalled_ms
    );
    // Timeout-only evidence from the media owner (amdgpu_job_core_dump).
    if let Some(boot) = crate::amdgpu_navi22_platform::owner().await.as_mut() {
        boot.media_timeout_report(ring, hang.emitted);
    }
    match media_action(AUTOMATIC.load(Ordering::Acquire), ring) {
        MediaAction::Suspend => {
            crate::amdgpu_navi22_cs::media_timed_out(ring, generation);
            let _ = writeln!(
                w,
                "amdgpu: navi22 GPU recovery disabled (amdgpu.gpu_recovery=0); ring {name} timeout suspended"
            );
            return false;
        }
        MediaAction::ResetEngine => {
            let _ = writeln!(w, "amdgpu: navi22 Starting {name} ring reset");
            match crate::amdgpu_navi22_platform::reset_media_engine(0, generation).await {
                Ok(()) => {
                    let _ = writeln!(w, "amdgpu: navi22 Ring {name} reset succeeded");
                    return false;
                }
                Err(error) => {
                    let _ = writeln!(w, "amdgpu: navi22 Ring {name} reset failed ({error:?})");
                }
            }
        }
        MediaAction::Recover => {}
    }
    if claim_automatic_recovery() {
        crate::amdgpu_navi22_cs::media_hung(ring, generation);
        // SAFETY: the caller of set_automatic_recovery accepted recover()'s
        // contract on behalf of every queue user.
        let result = unsafe { crate::amdgpu_navi22_platform::recover() }.await;
        let _ = writeln!(w, "amdgpu: navi22 recovery {result:?}");
        return true;
    }
    crate::amdgpu_navi22_cs::media_timed_out(ring, generation);
    let _ = writeln!(
        w,
        "amdgpu: navi22 GPU recovery limit ({MAX_AUTOMATIC_RECOVERIES} per boot) reached; ring {name} timeout suspended"
    );
    false
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
