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
}
const ENGINES: usize = 5;
/// Interval between memory samples when no interrupt arrives.
pub const POLL_US: u64 = 1000;

static WAKERS: [IrqSafeSpinLock<Option<Waker>>; ENGINES] =
    [const { IrqSafeSpinLock::new(None) }; ENGINES];
static INTERRUPTS: [AtomicU64; ENGINES] = [const { AtomicU64::new(0) }; ENGINES];
/// Bumped when the device is reset or lost: work emitted before it can
/// never signal, so every waiter that started earlier completes with error.
static GENERATION: AtomicU64 = AtomicU64::new(0);

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
    INTERRUPTS[engine as usize].fetch_add(1, Ordering::Relaxed);
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
struct Tick {
    engine: Engine,
    sleep: narf_time::SleepUntil,
    armed: bool,
}
impl Future for Tick {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.armed {
            return Poll::Ready(());
        }
        self.armed = true;
        // Replacing (and dropping) the previous waker happens in task context.
        *WAKERS[self.engine as usize].lock() = Some(cx.waker().clone());
        Pin::new(&mut self.sleep).poll(cx)
    }
}

/// Sample until `sample` yields a value, it errors, or `deadline` passes.
/// The sample runs once more after expiry so a completion racing the deadline
/// is never misreported as a timeout.
pub(crate) async fn wait<T, E>(
    engine: Engine,
    deadline: narf_time::Deadline,
    timeout: E,
    mut sample: impl FnMut() -> Result<Option<T>, E>,
) -> Result<T, E> {
    let generation = GENERATION.load(Ordering::Acquire);
    loop {
        let expired = deadline.expired();
        if let Some(value) = sample()? {
            return Ok(value);
        }
        // Abandoned by a reset/device loss: complete now, with the error.
        if expired || GENERATION.load(Ordering::Acquire) != generation {
            return Err(timeout);
        }
        Tick {
            engine,
            sleep: narf_time::SleepUntil::new(narf_time::Deadline::after_us(POLL_US).as_instant()),
            armed: false,
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
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/cp-navi22",
        navi22_fence_wait_is_bounded_and_wrap_safe
    );
}
