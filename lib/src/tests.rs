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

// ── deep narf-lib coverage ────────────────────────────────────────
//
// Closes invariants the existing 12 smokes only touched at the
// headline: Bitmap full API surface, sync::Once / OnceLock, context
// in_irq nesting, IrqSafeSpinLock release path + try_lock.

fn smoke_bitmap_new_empty_state() -> TestResult {
    use crate::bitmap::Bitmap;
    let b: Bitmap<128> = Bitmap::new();
    if b.count_ones() != 0 {
        return TestResult::Fail("fresh bitmap reported non-zero count");
    }
    if b.first_set().is_some() {
        return TestResult::Fail("empty bitmap reported a set bit");
    }
    if b.first_clear() != Some(0) {
        return TestResult::Fail("empty bitmap first_clear != 0");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_bitmap_new_empty_state);

fn smoke_bitmap_set_clear_toggle() -> TestResult {
    use crate::bitmap::Bitmap;
    let mut b: Bitmap<128> = Bitmap::new();
    b.set(0);
    b.set(64);
    b.set(127);
    if !b.get(0) || !b.get(64) || !b.get(127) {
        return TestResult::Fail("set bits not retrievable");
    }
    if b.get(1) || b.get(63) {
        return TestResult::Fail("unset bits read true");
    }
    if b.count_ones() != 3 {
        return TestResult::Fail("count_ones didn't match");
    }
    b.clear(0);
    if b.get(0) {
        return TestResult::Fail("clear didn't clear bit");
    }
    if b.count_ones() != 2 {
        return TestResult::Fail("count_ones didn't decrement on clear");
    }
    if b.toggle(64) != true {
        return TestResult::Fail("toggle of a set bit didn't return true");
    }
    if b.get(64) {
        return TestResult::Fail("toggle didn't flip set bit");
    }
    if b.toggle(64) != false {
        return TestResult::Fail("toggle of newly-cleared bit didn't return false");
    }
    if !b.get(64) {
        return TestResult::Fail("toggle didn't flip cleared bit back on");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_bitmap_set_clear_toggle);

fn smoke_bitmap_iter_set_yields_in_order() -> TestResult {
    use crate::bitmap::Bitmap;
    let mut b: Bitmap<128> = Bitmap::new();
    b.set(3);
    b.set(5);
    b.set(64);
    b.set(127);
    let mut iter = b.iter_set();
    if iter.next() != Some(3) {
        return TestResult::Fail("iter_set order wrong at 3");
    }
    if iter.next() != Some(5) {
        return TestResult::Fail("iter_set order wrong at 5");
    }
    if iter.next() != Some(64) {
        return TestResult::Fail("iter_set order wrong at 64");
    }
    if iter.next() != Some(127) {
        return TestResult::Fail("iter_set order wrong at 127");
    }
    if iter.next() != None {
        return TestResult::Fail("iter_set yielded extra items");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_bitmap_iter_set_yields_in_order);

fn smoke_bitmap_new_full_masks_trailing_bits() -> TestResult {
    use crate::bitmap::Bitmap;
    let b: Bitmap<3> = Bitmap::new_full();
    if !b.get(0) || !b.get(1) || !b.get(2) {
        return TestResult::Fail("new_full didn't set in-range bits");
    }
    if b.get(3) {
        return TestResult::Fail("new_full leaked into out-of-range bit");
    }
    if b.count_ones() != 3 {
        return TestResult::Fail("new_full count_ones wrong");
    }
    if b.first_clear().is_some() {
        return TestResult::Fail("full bitmap reported a clear bit");
    }
    if b.first_set() != Some(0) {
        return TestResult::Fail("first_set on full bitmap != 0");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_bitmap_new_full_masks_trailing_bits);

fn smoke_bitmap_first_clear_finds_gap_in_full_word() -> TestResult {
    use crate::bitmap::Bitmap;
    let mut b: Bitmap<64> = Bitmap::new_full();
    b.clear(13);
    if b.first_clear() != Some(13) {
        return TestResult::Fail("first_clear didn't find the explicit gap");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_bitmap_first_clear_finds_gap_in_full_word);

fn smoke_sync_once_runs_exactly_once() -> TestResult {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use crate::sync::Once;
    let o = Once::new();
    let n = AtomicUsize::new(0);
    if o.is_completed() {
        return TestResult::Fail("fresh Once reports completed");
    }
    for _ in 0..5 {
        o.call_once(|| { n.fetch_add(1, Ordering::Relaxed); });
    }
    if n.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("Once ran more than once");
    }
    if !o.is_completed() {
        return TestResult::Fail("Once::is_completed false after call_once");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_sync_once_runs_exactly_once);

fn smoke_sync_once_lock_set_get_double_set() -> TestResult {
    use crate::sync::OnceLock;
    let cell: OnceLock<u32> = OnceLock::new();
    if cell.get().is_some() {
        return TestResult::Fail("fresh OnceLock has value");
    }
    if cell.set(42).is_err() {
        return TestResult::Fail("first set returned Err");
    }
    if cell.get() != Some(&42) {
        return TestResult::Fail("get after set returned wrong value");
    }
    match cell.set(99) {
        Ok(()) => return TestResult::Fail("second set succeeded"),
        Err(v) if v == 99 => {}
        Err(_) => return TestResult::Fail("second set returned wrong rejected value"),
    }
    if cell.get() != Some(&42) {
        return TestResult::Fail("double-set mutated stored value");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_sync_once_lock_set_get_double_set);

fn smoke_sync_once_lock_get_or_init() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};
    use crate::sync::OnceLock;
    static INITS: AtomicU32 = AtomicU32::new(0);
    INITS.store(0, Ordering::Relaxed);
    let cell: OnceLock<u32> = OnceLock::new();
    let v1 = *cell.get_or_init(|| {
        INITS.fetch_add(1, Ordering::Relaxed);
        7
    });
    let v2 = *cell.get_or_init(|| {
        INITS.fetch_add(1, Ordering::Relaxed);
        9
    });
    if v1 != 7 || v2 != 7 {
        return TestResult::Fail("get_or_init returned stale value");
    }
    if INITS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("init closure ran more than once");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_sync_once_lock_get_or_init);

fn smoke_context_enter_exit_irq_round_trip() -> TestResult {
    if crate::context::in_irq() {
        return TestResult::Fail("entered test in_irq state");
    }
    crate::context::enter_irq();
    if !crate::context::in_irq() {
        return TestResult::Fail("enter_irq didn't flip in_irq true");
    }
    crate::context::exit_irq();
    if crate::context::in_irq() {
        return TestResult::Fail("exit_irq didn't flip in_irq false");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_context_enter_exit_irq_round_trip);

fn smoke_context_enter_irq_nests() -> TestResult {
    // Two enter_irq + two exit_irq must leave in_irq false. Models
    // nested IRQ handlers (higher-priority arriving during a
    // lower-priority handler).
    if crate::context::in_irq() {
        return TestResult::Fail("entered test in_irq state");
    }
    crate::context::enter_irq();
    crate::context::enter_irq();
    if !crate::context::in_irq() {
        return TestResult::Fail("nested enter didn't keep in_irq true");
    }
    crate::context::exit_irq();
    if !crate::context::in_irq() {
        return TestResult::Fail("inner exit prematurely cleared in_irq");
    }
    crate::context::exit_irq();
    if crate::context::in_irq() {
        return TestResult::Fail("outer exit didn't clear in_irq");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_context_enter_irq_nests);

fn smoke_irq_safe_spin_lock_release_path() -> TestResult {
    // Acquire, mutate, drop, re-acquire and observe. Confirms the
    // lock actually releases (a forgotten release would deadlock).
    use crate::sync::IrqSafeSpinLock;
    let lock = IrqSafeSpinLock::new(0u32);
    {
        let mut g = lock.lock();
        *g = 7;
    }
    if *lock.lock() != 7 {
        return TestResult::Fail("re-acquire didn't see mutation");
    }
    // Second re-acquire is the deadlock-canary path.
    {
        let g = lock.lock();
        if *g != 7 {
            return TestResult::Fail("second re-acquire saw wrong value");
        }
    }
    if *lock.lock() != 7 {
        return TestResult::Fail("post-multiple-acquire reads wrong value");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_irq_safe_spin_lock_release_path);

fn smoke_spin_lock_try_lock_blocked_while_held() -> TestResult {
    // SpinLock (irq-token variant) does have try_lock — exercise it.
    use crate::sync::{IrqsEnabled, SpinLock};
    let lock = SpinLock::new(0u32);
    let g = lock.lock(IrqsEnabled);
    if lock.try_lock(IrqsEnabled).is_some() {
        return TestResult::Fail("try_lock succeeded while lock held");
    }
    drop(g);
    if lock.try_lock(IrqsEnabled).is_none() {
        return TestResult::Fail("try_lock failed after release");
    }
    TestResult::Pass
}
kernel_test_in!("lib", smoke_spin_lock_try_lock_blocked_while_held);
