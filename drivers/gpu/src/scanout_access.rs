//! CPU views of a replaceable scanout. Publication changes are short locked
//! operations; pixel access holds only an epoch reference, with IRQs enabled.
//! This is a CPU lifetime barrier, not proof that display DMA has stopped.

use alloc::{sync::Arc, vec::Vec};
use core::ops::{Deref, DerefMut};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Default)]
struct Epochs {
    current: Option<Arc<()>>,
    retired: Vec<Arc<()>>,
}

struct Access(IrqSafeSpinLock<Epochs>);
impl Access {
    const fn new() -> Self {
        Self(IrqSafeSpinLock::new(Epochs {
            current: None,
            retired: Vec::new(),
        }))
    }

    fn snapshot<T>(&self, read: impl FnOnce() -> T) -> View<T> {
        let mut epochs = self.0.lock();
        let epoch = epochs.current.get_or_insert_with(|| Arc::new(())).clone();
        let pin = narf_scheduler::preempt_disable();
        View {
            value: read(),
            _epoch: epoch,
            _pin: pin,
        }
    }

    fn replace(&self, change: impl FnOnce()) {
        let mut epochs = self.0.lock();
        change();
        if let Some(old) = epochs.current.take() {
            epochs.retired.push(old);
        }
        epochs.retired.retain(|e| Arc::strong_count(e) != 1);
    }

    fn quiescent(&self) -> bool {
        let mut epochs = self.0.lock();
        epochs.retired.retain(|e| Arc::strong_count(e) != 1);
        epochs.retired.is_empty()
    }

    async fn wait(&self) {
        while !self.quiescent() {
            narf_scheduler::yield_now().await;
        }
    }
}

static ACCESS: Access = Access::new();

/// A snapshot whose CPU accesses must finish before retirement can complete.
/// It is !Send and disables involuntary preemption so its final device-memory
/// fence runs on the CPU that performed the accesses. Do not yield or await
/// while holding it. IRQs remain enabled and no lock is held while drawing.
/// A view does not serialize overlapping pixel writers.
#[derive(Debug)]
pub struct View<T> {
    value: T,
    _epoch: Arc<()>,
    _pin: narf_scheduler::PreemptGuard,
}
impl<T> Deref for View<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T> DerefMut for View<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}
impl<T> Drop for View<T> {
    fn drop(&mut self) {
        // Finish WC stores and device reads before publishing quiescence on
        // another CPU. An ordinary Arc release alone does not drain WC memory.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: architectural memory barriers, no operand or memory access.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("mfence", options(nostack, preserves_flags));
            #[cfg(target_arch = "aarch64")]
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Capture the mapping and geometry together with their lifetime lease.
/// `read` must be short and must not call `snapshot` or `replace` recursively.
///
/// # Safety
/// Every replacement of the captured mapping must use `replace`. Any pointer
/// or framebuffer obtained from the value may be used only while the View is
/// alive, on this CPU, without suspension. Its destructor must not access the
/// mapping. Pixel exclusivity remains the caller's responsibility.
pub unsafe fn snapshot<T>(read: impl FnOnce() -> T) -> View<T> {
    ACCESS.snapshot(read)
}

/// Change a mapping atomically with respect to CPU snapshots. This does not
/// wait for previous accesses: callers must retain the previous allocation
/// until `wait_retired` completes, plus independent hardware fetch retirement.
/// The callback must not recursively enter this module or wait for a writer.
pub fn replace(change: impl FnOnce()) {
    ACCESS.replace(change);
}

/// Wait for views of all replaced mappings, including older flips. Current
/// mapping writers cannot starve this barrier. Cancellation leaves the epochs
/// retained, so another call must still wait for outstanding old accesses.
pub async fn wait_retired() {
    ACCESS.wait().await;
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use core::{
        cell::Cell,
        future::Future,
        task::{Context, Poll, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn replaced_scanout_waits_for_old_views_only() -> TestResult {
        let access = Access::new();
        let address = Cell::new(1);
        let old = access.snapshot(|| address.get());
        access.replace(|| address.set(2));
        let current = access.snapshot(|| address.get());
        assert_eq!((*old, *current), (1, 2));
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut wait = core::pin::pin!(access.wait());
            assert_eq!(wait.as_mut().poll(&mut cx), Poll::Pending);
        } // Cancel the wait, not the outstanding view.
        assert!(!access.quiescent());
        drop(old);
        let mut wait = core::pin::pin!(access.wait());
        assert_eq!(wait.as_mut().poll(&mut cx), Poll::Ready(()));
        // A writer on the new display remains live throughout retirement.
        assert_eq!(*current, 2);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/scanout-access",
        replaced_scanout_waits_for_old_views_only
    );

    fn withdrawal_includes_views_from_earlier_flips() -> TestResult {
        let access = Access::new();
        let old_front = access.snapshot(|| 1);
        access.replace(|| {});
        let next_front = access.snapshot(|| 2);
        access.replace(|| {});
        drop(next_front);
        assert!(!access.quiescent());
        drop(old_front);
        assert!(access.quiescent());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/scanout-access",
        withdrawal_includes_views_from_earlier_flips
    );
}
