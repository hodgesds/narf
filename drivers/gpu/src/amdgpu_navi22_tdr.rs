//! Navi22 kernel-queue hang detection. Linux arms a drm_sched job timer
//! (`adev->{gfx,compute,sdma}_timeout`, 2 s by default since
//! `amdgpu_device_get_job_timeout_settings`) when a job reaches the ring and
//! re-arms it on each completion; `amdgpu_job_timedout` then reports
//! "ring %s timeout, signaled seq=%u, emitted seq=%u" and, with
//! `amdgpu_gpu_recovery`, starts recovery. NARF kernel queues have no job
//! scheduler, so this watchdog samples each queue's emitted sequence and its
//! fence writeback: a queue with unsignalled work whose fence has not moved
//! for the timeout is hung. Detection is always active and logs once per
//! stall. Like Linux's default `amdgpu_gpu_recovery=-1` on a dGPU, a hang
//! starts recovery (`set_automatic_recovery`, on by default for RX 6000;
//! `amdgpu.gpu_recovery=0` turns it off), at most
//! [`MAX_AUTOMATIC_RECOVERIES`] times per boot: each recovery quarantines
//! (leaks) the old owners' VRAM, so a card that keeps hanging is left
//! stopped rather than recovered until VRAM runs out.
use crate::amdgpu_fence_navi22::{signaled, Engine};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

/// Linux default lockup timeout for every kernel queue.
// linux: n/a (literal msecs_to_jiffies(2000) in amdgpu_device.c:amdgpu_device_get_job_timeout_settings)
pub const TIMEOUT_MS: u64 = 2000;
/// Sampling period; the detection latency is at most TIMEOUT + PERIOD.
pub const PERIOD_MS: u64 = 250; // linux: n/a (NARF sampling period)
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

/// Detector task for one owner generation; exits on `stop` or device loss.
pub(crate) async fn monitor(epoch: u64) {
    use core::fmt::Write;
    let mut watchdog = Watchdog::new(TIMEOUT_MS);
    loop {
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(PERIOD_MS).as_instant()).await;
        if EPOCH.load(Ordering::Acquire) != epoch {
            return;
        }
        let samples = match crate::amdgpu_navi22_platform::queue_progress().await {
            Ok(samples) => samples,
            Err(crate::amdgpu_navi22_boot::Error::Busy) => continue, // owner busy
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
            crate::amdgpu_navi22_cs::hung(hang.engine);
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 ring {:?} timeout, signaled seq={}, emitted seq={} ({} ms)",
                hang.engine,
                hang.signaled,
                hang.emitted,
                hang.stalled_ms
            );
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
    }
}

/// Start a detector for the current owner; any previous one exits.
pub(crate) fn start() {
    let epoch = EPOCH.fetch_add(1, Ordering::AcqRel) + 1;
    narf_scheduler::spawn(monitor(epoch));
}
/// Stop the detector (recovery quiesce or device loss).
pub(crate) fn stop() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_tdr_tests.rs"]
mod tests;
