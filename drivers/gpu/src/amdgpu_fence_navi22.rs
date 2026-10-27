//! Navi22 kernel-queue fence waits. Engines write 32-bit sequence numbers
//! (RELEASE_MEM, WRITE_DATA, SDMA FENCE) into owned VRAM writeback; waiters
//! sample that memory under a hard deadline. Polling is the only mandatory
//! completion path. The interrupt handler owner may additionally call
//! [`notify`] after decoding a GFX EOP / SDMA trap so waiters re-sample
//! immediately instead of at the next poll tick. Nothing here depends on IH.
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_lib::sync::IrqSafeSpinLock;

/// Kernel queues that emit fences. The index is the hook slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Gfx,
    Compute,
    Kiq,
    Sdma0,
    Sdma1,
    /// VCN instance decode/encode rings (one slot per instance) and JPEG.
    Vcn0,
    Vcn1,
    Jpeg,
    Sdma2,
    Sdma3,
}
pub(crate) const ENGINES: usize = 10; // linux: n/a (NARF hook slot count)
/// Interval between memory samples when no interrupt arrives.
pub const POLL_US: u64 = 1000; // linux: n/a (NARF poll policy)

static WAKERS: [IrqSafeSpinLock<Option<Waker>>; ENGINES] =
    [const { IrqSafeSpinLock::new(None) }; ENGINES];
static INTERRUPTS: [AtomicU64; ENGINES] = [const { AtomicU64::new(0) }; ENGINES];
/// Bumped when the device is reset or lost: work emitted before it can
/// never signal, so every waiter that started earlier completes with error.
static GENERATION: AtomicU64 = AtomicU64::new(0);
static CHANGE: AtomicU64 = AtomicU64::new(0);
static NEXT_CHANGE_WAITER: AtomicU64 = AtomicU64::new(1);
static CHANGE_WAITERS: IrqSafeSpinLock<alloc::vec::Vec<(u64, Waker)>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

pub(crate) fn change_sequence() -> u64 {
    CHANGE.load(Ordering::Acquire)
}

/// Wake every VMID/job waiter on any fence IRQ, or its hard deadline.
/// Registration is per future, so concurrent clients cannot replace each
/// other's wakers. Capturing the sequence before sampling prevents lost IRQs.
pub(crate) async fn wait_change(observed: u64, deadline_ns: u64) {
    struct Changed {
        id: u64,
        observed: u64,
        sleep: narf_time::SleepUntil,
    }
    impl Future for Changed {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            {
                let mut waiters = CHANGE_WAITERS.lock();
                if let Some((_, waker)) = waiters.iter_mut().find(|(id, _)| *id == self.id) {
                    if !waker.will_wake(cx.waker()) {
                        *waker = cx.waker().clone();
                    }
                } else {
                    waiters.push((self.id, cx.waker().clone()));
                }
            }
            if CHANGE.load(Ordering::Acquire) != self.observed {
                return Poll::Ready(());
            }
            Pin::new(&mut self.sleep).poll(cx)
        }
    }
    impl Drop for Changed {
        fn drop(&mut self) {
            CHANGE_WAITERS.lock().retain(|(id, _)| *id != self.id);
        }
    }
    Changed {
        id: NEXT_CHANGE_WAITER.fetch_add(1, Ordering::Relaxed),
        observed,
        sleep: narf_time::SleepUntil::new(
            narf_time::Deadline::after_ns(deadline_ns.saturating_sub(narf_time::monotonic_ns()))
                .as_instant(),
        ),
    }
    .await
}

/// Recovery/device-loss hook (`amdgpu_fence_driver_force_completion`):
/// abandon every outstanding wait and wake it to complete with its error.
pub fn abandon_all() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
    notify_all();
}
/// Observability: number of resets/device losses that abandoned work.
pub fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

/// IH hook: an engine reported completion. Safe from IRQ or task context:
/// the stored waker is only woken by reference, never dropped here.
pub fn notify(engine: Engine) {
    CHANGE.fetch_add(1, Ordering::AcqRel);
    // Wake by reference only: IRQ context never allocates or drops a waker.
    for (_, waker) in CHANGE_WAITERS.lock().iter() {
        waker.wake_by_ref();
    }
    INTERRUPTS[engine as usize].fetch_add(1, Ordering::AcqRel);
    if let Some(waker) = WAKERS[engine as usize].lock().as_ref() {
        waker.wake_by_ref();
    }
}
/// Device-loss hook: wake every waiter so it re-samples (reads of a removed
/// device return all-ones and fail) instead of sleeping until its deadline.
pub fn notify_all() {
    for engine in [
        Engine::Gfx,
        Engine::Compute,
        Engine::Kiq,
        Engine::Sdma0,
        Engine::Sdma1,
        Engine::Vcn0,
        Engine::Vcn1,
        Engine::Jpeg,
        Engine::Sdma2,
        Engine::Sdma3,
    ] {
        notify(engine);
    }
}
/// Observability: notifications delivered for `engine` since boot.
pub fn interrupts(engine: Engine) -> u64 {
    INTERRUPTS[engine as usize].load(Ordering::Relaxed)
}
/// Wrap-safe "fence value `current` has reached `target`".
pub fn signaled(current: u32, target: u32) -> bool {
    current.wrapping_sub(target) as i32 >= 0
}

/// Resolves on the next poll after either the poll interval elapses or the
/// engine is notified. Every wake leads to a fresh memory sample.
/// One poll interval: ready when the engine's interrupt fires or `sleep`
/// elapses, whichever is first. A re-poll that neither event caused (a
/// spinning executor such as `block_on_spin`, or a sibling future's wake)
/// keeps waiting; treating every second poll as a wake turned the interval
/// into a busy loop whose sample count scaled with the CPU and the timeout.
struct Tick {
    engine: Engine,
    sleep: narf_time::SleepUntil,
    /// `INTERRUPTS[engine]` when the tick was armed.
    seen: Option<u64>,
}
impl Future for Tick {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let interrupts = &INTERRUPTS[self.engine as usize];
        let seen = match self.seen {
            Some(seen) => seen,
            None => {
                // Snapshot before publishing the waker: an interrupt between
                // the two still changes the counter checked below.
                let seen = interrupts.load(Ordering::Acquire);
                self.seen = Some(seen);
                seen
            }
        };
        {
            // Replacing (and dropping) the previous waker happens in task
            // context.
            let mut slot = WAKERS[self.engine as usize].lock();
            if !slot
                .as_ref()
                .is_some_and(|waker| waker.will_wake(cx.waker()))
            {
                *slot = Some(cx.waker().clone());
            }
        }
        if interrupts.load(Ordering::Acquire) != seen {
            return Poll::Ready(());
        }
        Pin::new(&mut self.sleep).poll(cx)
    }
}

/// Sample until `sample` yields a value, it errors, or `deadline` passes.
/// The sample runs once more after expiry so a completion racing the deadline
/// is never misreported as a timeout.
///
/// `poll_limit` is the kernel-test poll budget threaded from the caller's
/// register model (its `Io::wait_poll_limit`): when armed, a wait that has
/// sampled `poll_limit` times without completing returns `timeout` by count
/// instead of burning the wall-clock deadline under the spin executor
/// (#879). Production callers pass `None` and always wait on time; the
/// parameter is ignored outside kernel-test builds.
pub(crate) async fn wait<T, E>(
    engine: Engine,
    deadline: narf_time::Deadline,
    timeout: E,
    poll_limit: Option<u32>,
    mut sample: impl FnMut() -> Result<Option<T>, E>,
) -> Result<T, E> {
    let generation = GENERATION.load(Ordering::Acquire);
    #[cfg(feature = "kernel-test")]
    let mut polls = poll_limit;
    loop {
        let expired = deadline.expired();
        if let Some(value) = sample()? {
            return Ok(value);
        }
        // Abandoned by a reset/device loss: complete now, with the error.
        if expired || GENERATION.load(Ordering::Acquire) != generation {
            return Err(timeout);
        }
        #[cfg(feature = "kernel-test")]
        if let Some(left) = &mut polls {
            if *left == 0 {
                return Err(timeout);
            }
            *left -= 1;
        }
        Tick {
            engine,
            sleep: narf_time::SleepUntil::new(narf_time::Deadline::after_us(POLL_US).as_instant()),
            seen: None,
        }
        .await;
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use core::cell::Cell;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn navi22_fence_wait_is_bounded_and_wrap_safe() -> TestResult {
        if !signaled(5, 5) || !signaled(1, u32::MAX) || signaled(4, 5) || signaled(u32::MAX, 1) {
            return TestResult::Fail("fence wrap comparison");
        }
        let calls = Cell::new(0);
        let result = narf_scheduler::block_on_spin(wait(
            Engine::Sdma1,
            narf_time::Deadline::after_ms(5),
            "timeout",
            None,
            || {
                calls.set(calls.get() + 1);
                Ok::<Option<()>, _>(None)
            },
        ));
        if result != Err("timeout") || calls.get() < 2 {
            return TestResult::Fail("fence wait not bounded");
        }
        let seen = Cell::new(0);
        let result = narf_scheduler::block_on_spin(wait(
            Engine::Gfx,
            narf_time::Deadline::after_ms(1000),
            0,
            None,
            || {
                seen.set(seen.get() + 1);
                if seen.get() == 3 {
                    Ok(Some(7))
                } else if seen.get() == 2 {
                    notify(Engine::Gfx);
                    Ok(None)
                } else {
                    Ok(None)
                }
            },
        ));
        let before = interrupts(Engine::Kiq);
        notify_all();
        if result != Ok(7) || interrupts(Engine::Kiq) != before + 1 {
            return TestResult::Fail("fence hook did not resample");
        }
        let failed = narf_scheduler::block_on_spin(wait(
            Engine::Compute,
            narf_time::Deadline::after_ms(1000),
            1,
            None,
            || Err::<Option<()>, _>(9),
        ));
        if failed != Err(9) {
            return TestResult::Fail("fence sample error swallowed");
        }
        // A reset abandons a pending wait well before its deadline.
        let polls = Cell::new(0);
        let abandoned = narf_scheduler::block_on_spin(wait(
            Engine::Sdma0,
            narf_time::Deadline::after_ms(60_000),
            "abandoned",
            None,
            || {
                polls.set(polls.get() + 1);
                if polls.get() == 2 {
                    abandon_all();
                }
                Ok::<Option<()>, _>(None)
            },
        ));
        if abandoned != Err("abandoned") || polls.get() != 2 {
            return TestResult::Fail("reset did not complete abandoned work");
        }
        // An armed poll limit bounds the sample count itself: with a 60 s
        // deadline a never-signalling wait returns by count after the
        // initial sample plus the budgeted polls (#879).
        let capped = Cell::new(0);
        let result = narf_scheduler::block_on_spin(wait(
            Engine::Sdma1,
            narf_time::Deadline::after_ms(60_000),
            "timeout",
            Some(3),
            || {
                capped.set(capped.get() + 1);
                Ok::<Option<()>, _>(None)
            },
        ));
        if result != Err("timeout") || capped.get() != 4 {
            return TestResult::Fail("fence poll limit did not bound samples");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/cp-navi22",
        navi22_fence_wait_is_bounded_and_wrap_safe
    );
}

#[cfg(feature = "kernel-test")]
mod change_tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::AtomicUsize;
    use narf_kernel_test::{kernel_test_in, TestResult};
    struct Counter(AtomicUsize);
    impl alloc::task::Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn rdna2_fence_changes_wake_all_and_cancel_cleanly() -> TestResult {
        let a = Arc::new(Counter(AtomicUsize::new(0)));
        let b = Arc::new(Counter(AtomicUsize::new(0)));
        let wa = Waker::from(a.clone());
        let wb = Waker::from(b.clone());
        let mut ca = Context::from_waker(&wa);
        let mut cb = Context::from_waker(&wb);
        let sequence = change_sequence();
        let deadline = narf_time::monotonic_ns().saturating_add(1_000_000_000);
        let before = CHANGE_WAITERS.lock().len();
        let mut fa = alloc::boxed::Box::pin(wait_change(sequence, deadline));
        let mut fb = alloc::boxed::Box::pin(wait_change(sequence, deadline));
        if fa.as_mut().poll(&mut ca).is_ready() || fb.as_mut().poll(&mut cb).is_ready() {
            return TestResult::Fail("fence wait completed without IRQ/deadline");
        }
        notify(Engine::Sdma2);
        if a.0.load(Ordering::Relaxed) == 0
            || b.0.load(Ordering::Relaxed) == 0
            || fa.as_mut().poll(&mut ca).is_pending()
            || fb.as_mut().poll(&mut cb).is_pending()
        {
            return TestResult::Fail("IRQ lost or only one client woke");
        }
        drop(fa);
        drop(fb);
        let sequence = change_sequence();
        notify(Engine::Gfx);
        let mut raced = core::pin::pin!(wait_change(sequence, deadline));
        if raced.as_mut().poll(&mut ca).is_pending() {
            return TestResult::Fail("IRQ between sampling and registration was lost");
        }
        if CHANGE_WAITERS.lock().len() != before {
            return TestResult::Fail("completed/cancelled fence wait retained a waker");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/rdna2",
        rdna2_fence_changes_wake_all_and_cancel_cleanly
    );
}
