//! Kernel-resident drain task for the per-process DrawRing
//! registry.
//!
//! Spawned once at boot. Each scheduler tick polls every
//! registered ring and executes queued draw commands against the
//! shared FbWriter. Throughput is one ring round per scheduler
//! quantum — fine for the human-input cadence the framebuffer is
//! actually driven at.
//!
//! No UIPI yet — a producer that wants faster turn-around than
//! the next tick must call SYS_FB_DRAIN_KICK (added separately
//! when the use case arrives). The cadence-only approach gets the
//! interesting userspace-writes-to-FB chain working without
//! crossing into the architecture's interrupt-delivery path.

use core::pin::Pin;
use core::task::{Context, Poll};
use core::future::Future;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{registry, FbWriter};

static DRAIN_TICKS:    AtomicU64 = AtomicU64::new(0);
static DRAIN_EXECUTED: AtomicU64 = AtomicU64::new(0);
static DRAIN_ERRORS:   AtomicU64 = AtomicU64::new(0);

/// Snapshot the per-tick / per-call counters. Returns
/// `(ticks, executed, errors)`.
pub fn stats() -> (u64, u64, u64) {
    (
        DRAIN_TICKS.load(Ordering::Relaxed),
        DRAIN_EXECUTED.load(Ordering::Relaxed),
        DRAIN_ERRORS.load(Ordering::Relaxed),
    )
}

/// Run one drain pass. Public so a future SYS_FB_DRAIN_KICK
/// syscall handler can synchronously prod a drain.
pub fn drain_once(writer: &FbWriter) -> (u32, u32) {
    DRAIN_TICKS.fetch_add(1, Ordering::Relaxed);
    let (ok, err) = registry::drain_all(writer);
    DRAIN_EXECUTED.fetch_add(ok  as u64, Ordering::Relaxed);
    DRAIN_ERRORS.fetch_add(  err as u64, Ordering::Relaxed);
    (ok, err)
}

/// Future shape: poll → drain → return Pending → repeat. The
/// scheduler re-polls on every tick because we don't install a
/// waker (no condition gates the next pass).
pub struct DrainTask {
    writer: FbWriter,
}

impl core::fmt::Debug for DrainTask {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DrainTask").finish_non_exhaustive()
    }
}

impl DrainTask {
    pub fn new(writer: FbWriter) -> Self { Self { writer } }
}

impl Future for DrainTask {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        // Run one pass, then yield. The scheduler's next tick
        // will re-poll us; on every poll we drain whatever has
        // accumulated since the previous round.
        drain_once(&self.writer);
        Poll::Pending
    }
}

/// Test-only counter reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    DRAIN_TICKS.store(0, Ordering::Relaxed);
    DRAIN_EXECUTED.store(0, Ordering::Relaxed);
    DRAIN_ERRORS.store(0, Ordering::Relaxed);
}
