//! Subsystem smokes for `narf-lib`.
//!
//! Migrated from `narf-verification` so the primitives validate
//! themselves rather than relying on the mega-harness. Tests register
//! via `narf_kernel_test::kernel_test_in!("lib", _)` so the runner
//! groups output under the lib subsystem.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_typed_id_sanity() -> TestResult {
    use crate::id::{CpuId, DomainId, TaskId};
    if CpuId::new(7).raw() != 7 {
        return TestResult::Fail("CpuId::raw mismatch");
    }
    if DomainId::FRAME.raw() != 0 {
        return TestResult::Fail("FRAME != 0");
    }
    if DomainId::SCRATCH.raw() != 15 {
        return TestResult::Fail("SCRATCH != 15");
    }
    if TaskId::new(0xDEAD).raw() != 0xDEAD {
        return TestResult::Fail("TaskId::raw mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_typed_id_sanity);

fn smoke_spin_lock_cycle() -> TestResult {
    use crate::sync::{IrqsEnabled, SpinLock};
    let l = SpinLock::new(0u32);
    {
        let mut g = l.lock(IrqsEnabled);
        *g = 42;
    }
    if *l.lock(IrqsEnabled) == 42 {
        TestResult::Pass
    } else {
        TestResult::Fail("SpinLock round-trip lost its value")
    }
}
kernel_test_in!("lib", smoke_spin_lock_cycle);

fn smoke_bitmap_first_set() -> TestResult {
    use crate::bitmap::Bitmap;
    let mut b: Bitmap<128> = Bitmap::new();
    b.set(5);
    b.set(70);
    match (b.first_set(), b.count_ones()) {
        (Some(5), 2) => TestResult::Pass,
        _ => TestResult::Fail("Bitmap first_set/count_ones wrong"),
    }
}
kernel_test_in!("lib", smoke_bitmap_first_set);

fn smoke_box_roundtrip() -> TestResult {
    extern crate alloc;
    use alloc::boxed::Box;
    let b: Box<[u32; 4]> = Box::new([1, 2, 3, 4]);
    let sum: u32 = b.iter().sum();
    if sum == 10 {
        TestResult::Pass
    } else {
        TestResult::Fail("Box<[u32;4]> sum wrong")
    }
}
kernel_test_in!("lib", smoke_box_roundtrip);

fn smoke_lib_current_domain_hook() -> TestResult {
    // narf-arch provides `narf_arch_current_domain` as the weak hook
    // `narf-lib` calls. Stage-3 default: 0 == DomainId::FRAME. Any
    // drift here breaks every assert_in_domain / assert_tcb caller.
    use crate::assert::current_domain;
    use crate::id::DomainId;

    if current_domain() != DomainId::FRAME {
        return TestResult::Fail("arch hook returned non-FRAME domain at boot");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_lib_current_domain_hook);

fn smoke_lib_assert_in_domain_passes_on_frame() -> TestResult {
    // The always-on assert variant must not panic when the expected
    // domain matches. Stage-3 default has every task running in FRAME.
    use crate::id::DomainId;
    crate::assert_in_domain!(DomainId::FRAME);
    crate::assert_tcb!();
    TestResult::Pass
}
kernel_test_in!("lib", smoke_lib_assert_in_domain_passes_on_frame);

fn smoke_lib_bug_on_false_is_silent() -> TestResult {
    // bug_on! is a panic-path macro; a false condition must NOT panic.
    // Also implicitly tests the format-args path compiles.
    crate::bug_on!(false, "should not fire");
    crate::bug_on!(1 + 1 != 2, "arithmetic drift: {}", 42);
    TestResult::Pass
}
kernel_test_in!("lib", smoke_lib_bug_on_false_is_silent);

// ── relocated from verification (subsystem 'lib') ──

// ── async Mutex ───────────────────────────────────────────────────

extern crate alloc;

fn smoke_async_mutex_try_lock_round_trip() -> TestResult {
    use crate::mutex::Mutex;
    let m: Mutex<u32> = Mutex::new(7);
    let g = match m.try_lock() {
        Some(g) => g,
        None => return TestResult::Fail("try_lock on free mutex returned None"),
    };
    if *g != 7 {
        return TestResult::Fail("guard read wrong value");
    }
    if m.try_lock().is_some() {
        return TestResult::Fail("try_lock while held should return None");
    }
    drop(g);
    if m.try_lock().is_none() {
        return TestResult::Fail("try_lock after release should succeed");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_async_mutex_try_lock_round_trip);

fn smoke_async_mutex_release_wakes_waiter() -> TestResult {
    use crate::mutex::Mutex;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};

    struct CountingWaker {
        n: AtomicUsize,
    }
    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.n.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.n.fetch_add(1, Ordering::Relaxed);
        }
    }

    let m: Mutex<u32> = Mutex::new(0);
    let holder = m.try_lock().unwrap();

    let cw = Arc::new(CountingWaker {
        n: AtomicUsize::new(0),
    });
    let waker: Waker = cw.clone().into();
    let mut cx = Context::from_waker(&waker);

    let mut f = m.lock();
    if !matches!(Pin::new(&mut f).poll(&mut cx), Poll::Pending) {
        return TestResult::Fail("poll on contended lock should be Pending");
    }
    if cw.n.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("no wake expected before release");
    }

    drop(holder);
    if cw.n.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("release must wake exactly one waiter");
    }
    if !matches!(Pin::new(&mut f).poll(&mut cx), Poll::Ready(_)) {
        return TestResult::Fail("woken waiter should grab lock");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_async_mutex_release_wakes_waiter);

fn smoke_async_mutex_fifo_order() -> TestResult {
    use crate::mutex::Mutex;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};

    struct CW {
        n: AtomicUsize,
    }
    impl Wake for CW {
        fn wake(self: Arc<Self>) {
            self.n.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.n.fetch_add(1, Ordering::Relaxed);
        }
    }
    let mk = || {
        let cw = Arc::new(CW {
            n: AtomicUsize::new(0),
        });
        let w: Waker = cw.clone().into();
        (w, cw)
    };

    let m: Mutex<u32> = Mutex::new(0);
    let holder = m.try_lock().unwrap();
    let (w1, cw1) = mk();
    let (w2, cw2) = mk();
    let mut cx1 = Context::from_waker(&w1);
    let mut cx2 = Context::from_waker(&w2);
    let mut f1 = m.lock();
    let mut f2 = m.lock();
    let _ = Pin::new(&mut f1).poll(&mut cx1);
    let _ = Pin::new(&mut f2).poll(&mut cx2);

    drop(holder);
    if cw1.n.load(Ordering::Relaxed) != 1 || cw2.n.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("first release should wake only first waiter (FIFO)");
    }
    let g1 = match Pin::new(&mut f1).poll(&mut cx1) {
        Poll::Ready(g) => g,
        Poll::Pending => return TestResult::Fail("woken first waiter should be Ready"),
    };
    drop(g1);
    if cw2.n.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("second release should wake second waiter");
    }
    let _g2 = match Pin::new(&mut f2).poll(&mut cx2) {
        Poll::Ready(g) => g,
        Poll::Pending => return TestResult::Fail("second waiter should grab lock"),
    };
    TestResult::Pass
}
kernel_test_in!("lib", smoke_async_mutex_fifo_order);

fn smoke_async_mutex_dropped_waiter_chains() -> TestResult {
    // Release wakes A; A is dropped before re-polling. The Drop impl
    // must hand the lock down the chain so B isn't stranded.
    use crate::mutex::Mutex;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};

    struct CW {
        n: AtomicUsize,
    }
    impl Wake for CW {
        fn wake(self: Arc<Self>) {
            self.n.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.n.fetch_add(1, Ordering::Relaxed);
        }
    }
    let mk = || {
        let cw = Arc::new(CW {
            n: AtomicUsize::new(0),
        });
        let w: Waker = cw.clone().into();
        (w, cw)
    };

    let m: Mutex<u32> = Mutex::new(0);
    let holder = m.try_lock().unwrap();
    let (wa, cwa) = mk();
    let (wb, cwb) = mk();
    let mut cxa = Context::from_waker(&wa);
    let mut cxb = Context::from_waker(&wb);
    let mut fa = m.lock();
    let mut fb = m.lock();
    let _ = Pin::new(&mut fa).poll(&mut cxa);
    let _ = Pin::new(&mut fb).poll(&mut cxb);

    drop(holder);
    if cwa.n.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("A should be woken first");
    }
    drop(fa);
    if cwb.n.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("dropping woken-uncompleted waiter must wake next in chain");
    }
    if !matches!(Pin::new(&mut fb).poll(&mut cxb), Poll::Ready(_)) {
        return TestResult::Fail("B should be Ready after chained wake");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_async_mutex_dropped_waiter_chains);

fn smoke_percpu_storage_isolation() -> TestResult {
    // PerCpu<T: Copy> — verify the BSP cell is reachable + iter()
    // yields MAX_CPUS entries. Mutation requires T's interior
    // mutability (e.g. T = AtomicU32 once PerCpu drops the Copy
    // bound, or T = u32 wrapped in a UnsafeCell-bearing newtype);
    // for this smoke the structural surface is what matters.
    use crate::percpu::PerCpu;
    static SEED: PerCpu<u32> = PerCpu::new(0x4242);
    let v = *SEED.this_cpu();
    if v != 0x4242 {
        return TestResult::Fail("PerCpu init didn't propagate to BSP cell");
    }
    let n = SEED.iter().count();
    if n != crate::percpu::MAX_CPUS {
        return TestResult::Fail("PerCpu iter() count mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_percpu_storage_isolation);
