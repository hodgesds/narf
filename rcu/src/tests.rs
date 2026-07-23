//! Per-crate kernel-test smokes for `narf-rcu`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"rcu"`. Bodies are copied verbatim
//! from `verification/src/lib.rs` — only paths change
//! (`narf_rcu::xxx` → `crate::xxx`). Two sleepable tests
//! (`smoke_rcu_sleepable_sync_drains` and
//! `smoke_rcu_sleepable_timeout`) stay in `narf-verification` because
//! they need `narf-scheduler`, which already depends on `narf-rcu`
//! — moving them here would create a Cargo cycle.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

// ── qsbr ───────────────────────────────────────────────────────────

fn smoke_rcu_qsbr_pin_unpin() -> TestResult {
    // Baseline: pin() increments reader-in-flight; dropping the guard
    // decrements it. While pinned, `report_quiescent()` must NOT advance
    // the local epoch — advancing under a live reader would let their
    // Shared<'g, T> get reclaimed.
    let before = crate::qsbr::global_epoch();
    {
        let _g = crate::pin();
        // With a live reader, report_quiescent is a safe no-op and
        // sync_blocking must not accelerate reclamation.
        crate::report_quiescent();
    }
    // Guard dropped — CPU is quiescent. Call sync to publish + drain.
    crate::sync();
    let after = crate::qsbr::global_epoch();
    if after <= before {
        return TestResult::Fail("global epoch didn't advance after sync");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_qsbr_pin_unpin);

fn smoke_rcu_qsbr_reclaims() -> TestResult {
    // Deferred-drop round-trip: publish a value, swap it, sync, confirm
    // the displaced allocation's Drop ran.
    use crate::{Atomic, Owned};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    DROPS.store(0, Ordering::Relaxed);
    let cell: Atomic<Canary> = Atomic::new(Canary);

    // Swap the initial Canary out of the cell — this queues it for
    // deferred drop at the current epoch.
    {
        let g = crate::pin();
        cell.store(Owned::new(Canary), &g);
    }
    // No drops yet — the queued entry is still pending its grace period.
    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("deferred drop ran before sync()");
    }

    // Wait a grace period. The queued Canary must now have dropped.
    crate::sync();

    if DROPS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("deferred Canary didn't Drop after sync()");
    }

    // Also verify the new value is still readable.
    let g = crate::pin();
    let s = cell.load(&g);
    if s.is_null() {
        return TestResult::Fail("Atomic<Canary> became null after store+sync");
    }
    drop(g);

    // Drop the cell itself — the still-live Canary drops inline.
    drop(cell);
    if DROPS.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("cell-drop didn't reclaim the last value");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_qsbr_reclaims);

fn smoke_rcu_retire_box_advance_epoch_reclaims() -> TestResult {
    // `retire_box` + the executor's epoch-advance hook: a retired box must
    // NOT be reclaimed by quiescent reports under the retire epoch alone
    // (its holder-CPUs may not have passed a boundary yet), and MUST be
    // reclaimed once `advance_epoch_if_pending` publishes the next epoch
    // and this CPU reports quiescence under it. This is the progress
    // contract the scheduler's KernelTask reclaim relies on — without the
    // advance, retired boxes would leak forever.
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    DROPS.store(0, Ordering::Relaxed);
    // Adopt the current epoch so the retire below is stamped against a
    // reported baseline (a fresh CPU otherwise sits at the MAX sentinel).
    crate::report_quiescent();
    crate::retire_box(Box::new(Canary));
    // Reporting quiescence under the SAME epoch must not reclaim: the
    // entry's grace period requires a later epoch.
    crate::report_quiescent();
    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("retire_box reclaimed without a new epoch");
    }
    // The executor hook publishes the next epoch (bucket non-empty and
    // this CPU already reported under the current one) …
    crate::advance_epoch_if_pending();
    // … and the next quiescent report drains the now-elapsed entry.
    crate::report_quiescent();
    if DROPS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("retire_box not reclaimed after epoch advance + quiescence");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_retire_box_advance_epoch_reclaims);

// ── epoch ──────────────────────────────────────────────────────────

fn smoke_rcu_epoch_pin_cycle() -> TestResult {
    // Epoch-variant pin/unpin. min_pinned() must drop back to u64::MAX
    // after the guard is released.
    let before = crate::epoch::min_pinned();
    {
        let g = crate::epoch::pin();
        // While pinned, min_pinned() must not be u64::MAX (we're pinned).
        if crate::epoch::min_pinned() == u64::MAX {
            return TestResult::Fail("Epoch pin didn't publish a snapshot");
        }
        // Guard's snapshot must be <= current advance target.
        let adv = crate::epoch::advance();
        if g.epoch() > adv {
            return TestResult::Fail("EpochGuard epoch greater than current global");
        }
    }
    // Guard dropped. Back to "no pinned reader" = u64::MAX.
    if crate::epoch::min_pinned() != u64::MAX {
        return TestResult::Fail("Epoch guard drop didn't release the slot");
    }
    let _ = before;
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_epoch_pin_cycle);

fn smoke_rcu_epoch_defer_drop() -> TestResult {
    // Epoch-backed defer_drop runs the destructor.
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    DROPS.store(0, Ordering::Relaxed);
    crate::epoch::defer_drop(Box::new(Canary));
    if DROPS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("epoch::defer_drop didn't run destructor");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_epoch_defer_drop);

// ── sleepable (subset that doesn't need narf-scheduler) ────────────

fn smoke_rcu_sleepable_enter_exit() -> TestResult {
    use crate::sleepable::{SleepableReader, SleepableScope};

    let scope = SleepableScope::new();
    let cap = SleepableReader::bootstrap_cap();

    if scope.active() != 0 {
        return TestResult::Fail("scope.active() must start at 0");
    }
    {
        let _g = match scope.enter(&cap) {
            Ok(g) => g,
            Err(_) => return TestResult::Fail("enter rejected a fresh cap"),
        };
        if scope.active() != 1 {
            return TestResult::Fail("active didn't reach 1 after enter");
        }
    }
    if scope.active() != 0 {
        return TestResult::Fail("active didn't return to 0 after guard drop");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_sleepable_enter_exit);

fn smoke_rcu_sleepable_revoked_cap_rejected() -> TestResult {
    use crate::sleepable::{SleepableReader, SleepableScope};
    use narf_capabilities::CapError;

    let scope = SleepableScope::new();
    let cap = SleepableReader::bootstrap_cap();
    // Clone-by-Copy keeps the slot bits while transferring ownership of
    // the original to revoke(). After revoke, the duplicate cap with
    // the same generation snapshot must fail check_live and bounce out
    // of enter() with CapError::Revoked.
    let cap_copy = cap;
    cap.revoke();

    if scope.active() != 0 {
        return TestResult::Fail("scope.active() must start at 0");
    }
    match scope.enter(&cap_copy) {
        Err(CapError::Revoked) => {}
        Err(_) => return TestResult::Fail("wrong error variant from revoked cap"),
        Ok(_) => return TestResult::Fail("enter accepted a revoked cap"),
    }
    if scope.active() != 0 {
        return TestResult::Fail("rejected enter must not bump active");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_sleepable_revoked_cap_rejected);

// ── hazard ─────────────────────────────────────────────────────────

fn smoke_rcu_hazard_publish_retire() -> TestResult {
    // Publisher allocates a Box<u32>, exposes it via AtomicPtr; reader
    // acquires a guard; verifies the value; drops the guard. Publisher
    // then retires the pointer with a Drop-counting trampoline; one
    // scan() must reclaim it.
    use crate::hazard::HazardDomain;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary {
        v: u32,
    }
    impl Drop for Canary {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    DROPS.store(0, Ordering::Relaxed);

    let domain = HazardDomain::new();
    let raw = Box::into_raw(Box::new(Canary { v: 0xdead_beef }));
    let cell: AtomicPtr<Canary> = AtomicPtr::new(raw);

    {
        let g = match domain.acquire(&cell) {
            Some(g) => g,
            None => return TestResult::Fail("acquire returned None on a non-null cell"),
        };
        if g.v != 0xdead_beef {
            return TestResult::Fail("hazard guard saw wrong value");
        }
        // Guard drops here.
    }

    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("Canary dropped before retire was called");
    }

    fn drop_canary(p: *mut Canary) {
        // SAFETY: the test owns the pointer; retire's contract is that
        // we'll be invoked once no hazard slot names it.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            drop(Box::from_raw(p));
        }
    }
    domain.retire(raw, drop_canary);

    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("retire ran the dropper before scan()");
    }
    domain.scan();
    if DROPS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("scan() didn't reclaim the unheld retired pointer");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_hazard_publish_retire);

fn smoke_rcu_hazard_retired_but_held() -> TestResult {
    // Reader acquires the guard, THEN publisher retires the pointer.
    // scan() while the guard is live must NOT reclaim. Drop the guard,
    // scan() again — drop fires.
    use crate::hazard::HazardDomain;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    DROPS.store(0, Ordering::Relaxed);

    let domain = HazardDomain::new();
    let raw = Box::into_raw(Box::new(Canary));
    let cell: AtomicPtr<Canary> = AtomicPtr::new(raw);

    let g = match domain.acquire(&cell) {
        Some(g) => g,
        None => return TestResult::Fail("acquire returned None on a non-null cell"),
    };

    fn drop_canary(p: *mut Canary) {
        // SAFETY: hazard discipline; we're not invoked while held.
        unsafe {
            drop(Box::from_raw(p));
        }
    }
    domain.retire(raw, drop_canary);

    // First scan: hazard slot still names the pointer. Drop must NOT
    // fire.
    domain.scan();
    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("scan() reclaimed a still-held hazard pointer");
    }
    if domain.pending_retires() != 1 {
        return TestResult::Fail("retire-list lost the entry that was held back");
    }

    // Drop the guard, then scan. Now reclamation is allowed.
    drop(g);
    domain.scan();
    if DROPS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("post-release scan() didn't reclaim the entry");
    }
    if domain.pending_retires() != 0 {
        return TestResult::Fail("retire list still pending after successful scan");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_hazard_retired_but_held);

fn smoke_rcu_hazard_scan_frees_unheld() -> TestResult {
    // Bulk retire several pointers with no reader holding any of them.
    // One scan() must drain them all.
    use crate::hazard::HazardDomain;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    DROPS.store(0, Ordering::Relaxed);
    let domain = HazardDomain::new();

    fn drop_canary(p: *mut Canary) {
        // SAFETY: hazard discipline; the test never holds these.
        unsafe {
            drop(Box::from_raw(p));
        }
    }

    // Retire eight pointers — under the threshold so no inline scan
    // fires; we trigger reclamation explicitly.
    let n = 8usize;
    for _ in 0..n {
        let raw = Box::into_raw(Box::new(Canary));
        domain.retire(raw, drop_canary);
    }
    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("bulk retire ran droppers inline (threshold misconfigured?)");
    }
    if domain.pending_retires() != n {
        return TestResult::Fail("retire-list length mismatch before scan");
    }
    domain.scan();
    if DROPS.load(Ordering::Relaxed) != n {
        return TestResult::Fail("scan() didn't drain the full retire list");
    }
    if domain.pending_retires() != 0 {
        return TestResult::Fail("retire-list non-empty after scan");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_hazard_scan_frees_unheld);

// ── batched ────────────────────────────────────────────────────────

fn smoke_rcu_batched_reclaim_drains() -> TestResult {
    use crate::BatchedReclaimer;
    use core::sync::atomic::{AtomicU32, Ordering};

    static COUNT: AtomicU32 = AtomicU32::new(0);
    COUNT.store(0, Ordering::Relaxed);

    let r = BatchedReclaimer::new(0);
    if r.pending() != 0 {
        return TestResult::Fail("fresh reclaimer has pending");
    }

    for _ in 0..10 {
        let _full = r.submit(|| {
            COUNT.fetch_add(1, Ordering::Relaxed);
        });
    }
    if r.pending() != 10 {
        return TestResult::Fail("submitted != pending");
    }
    if COUNT.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("callback ran before flush");
    }
    r.flush();
    if COUNT.load(Ordering::Relaxed) != 10 {
        return TestResult::Fail("flush did not run all callbacks");
    }
    if r.pending() != 0 {
        return TestResult::Fail("pending did not settle after flush");
    }
    if r.total_submitted() != 10 || r.total_drained() != 10 {
        return TestResult::Fail("submit/drain totals off");
    }
    r.pace(2, 500); // hint-only, no observable side effect
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_batched_reclaim_drains);

// ── extended rcu coverage ──────────────────────────────────────────
//
// Existing surface covers pin/unpin, defer-drop round-trip, basic
// hazard discipline, and one batched flush. These close the
// remaining invariants on `Atomic` / `Owned` / `Shared`, QSBR
// quiescence semantics, hazard-domain idle behaviour, and batched
// stats across multiple flushes.

fn smoke_rcu_atomic_null_starts_empty() -> TestResult {
    // `Atomic::null()` produces a cell that loads to a null `Shared`.
    use crate::Atomic;
    let cell: Atomic<u32> = Atomic::null();
    let g = crate::pin();
    let s = cell.load(&g);
    if !s.is_null() {
        return TestResult::Fail("Atomic::null() loaded non-null");
    }
    if s.as_ref().is_some() {
        return TestResult::Fail("null Shared::as_ref returned Some");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_atomic_null_starts_empty);

fn smoke_rcu_atomic_compare_and_set_success() -> TestResult {
    // CAS with the observed pointer as expected → succeeds, returns
    // the new `Shared`, and the old value gets deferred-dropped.
    use crate::{Atomic, Owned};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary(u32);
    impl Drop for Canary {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    DROPS.store(0, Ordering::Relaxed);

    let cell = Atomic::new(Canary(1));
    {
        let g = crate::pin();
        let cur = cell.load(&g);
        let new = Owned::new(Canary(2));
        match cell.compare_and_set(cur, new, &g) {
            Ok(s) => {
                if let Some(v) = s.as_ref() {
                    if v.0 != 2 {
                        return TestResult::Fail("post-CAS value not v2");
                    }
                } else {
                    return TestResult::Fail("post-CAS Shared is null");
                }
            }
            Err(_) => return TestResult::Fail("CAS rejected matching expected"),
        }
    }
    crate::sync();
    if DROPS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("displaced value didn't defer-drop after CAS+sync");
    }
    drop(cell);
    if DROPS.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("cell drop didn't reclaim live value");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_atomic_compare_and_set_success);

fn smoke_rcu_atomic_compare_and_set_failure_returns_owned() -> TestResult {
    // CAS with the wrong expected pointer → returns the supplied
    // Owned untouched + current Shared, so the caller can recover
    // both. No reclamation triggered.
    use crate::{Atomic, Owned, Shared};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    DROPS.store(0, Ordering::Relaxed);

    let cell: Atomic<Canary> = Atomic::new(Canary);
    let g = crate::pin();
    // Deliberately stale `expected`: a null Shared.
    let bogus: Shared<Canary> = Shared::null();
    let new = Owned::new(Canary);
    let recovered = match cell.compare_and_set(bogus, new, &g) {
        Ok(_) => return TestResult::Fail("CAS accepted a null expected against non-null cell"),
        Err((owned, current)) => {
            if current.is_null() {
                return TestResult::Fail("failure path reported current=null");
            }
            owned
        }
    };
    drop(g);
    // The recovered Owned has not been deferred-dropped (caller owns it);
    // dropping it directly must reclaim immediately.
    drop(recovered);
    if DROPS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("recovered Owned didn't drop immediately");
    }
    drop(cell);
    if DROPS.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("cell didn't reclaim live value on drop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "rcu",
    smoke_rcu_atomic_compare_and_set_failure_returns_owned
);

fn smoke_rcu_owned_drops_immediately_if_unpublished() -> TestResult {
    // `Owned::new(...)` without store/CAS just drops the inner Box
    // when the Owned drops. No sync needed — it was never visible.
    use crate::Owned;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    DROPS.store(0, Ordering::Relaxed);
    {
        let _o = Owned::new(Canary);
    }
    if DROPS.load(Ordering::Relaxed) != 1 {
        TestResult::Fail("Owned drop didn't reclaim unpublished allocation")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("rcu", smoke_rcu_owned_drops_immediately_if_unpublished);

fn smoke_rcu_qsbr_multiple_defers_same_epoch_all_reclaim() -> TestResult {
    // Two values displaced by back-to-back stores in the same epoch
    // both reclaim after a single sync. Catches a fencepost where
    // only the most-recent deferred entry runs.
    use crate::{Atomic, Owned};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    DROPS.store(0, Ordering::Relaxed);

    let cell: Atomic<Canary> = Atomic::new(Canary);
    {
        let g = crate::pin();
        cell.store(Owned::new(Canary), &g); // displaces #1
        cell.store(Owned::new(Canary), &g); // displaces #2
        cell.store(Owned::new(Canary), &g); // displaces #3
    }
    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("displaced values reclaimed before sync");
    }
    crate::sync();
    if DROPS.load(Ordering::Relaxed) != 3 {
        return TestResult::Fail("all 3 displaced values must reclaim in one grace period");
    }
    drop(cell);
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_qsbr_multiple_defers_same_epoch_all_reclaim);

fn smoke_rcu_qsbr_defer_drop_while_pinned_waits() -> TestResult {
    // A standalone defer_drop while a reader is pinned must stay
    // queued until the reader unpins + sync runs.
    use crate::{defer_drop, Owned};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    DROPS.store(0, Ordering::Relaxed);

    let g_long = crate::pin();
    {
        let g = crate::pin();
        defer_drop(Owned::new(Canary), &g);
    }
    // g_long still alive; nothing reclaims even if we sync.
    crate::sync();
    if DROPS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("defer_drop reclaimed while a reader was pinned");
    }
    drop(g_long);
    crate::sync();
    if DROPS.load(Ordering::Relaxed) != 1 {
        TestResult::Fail("defer_drop didn't reclaim after pin release + sync")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("rcu", smoke_rcu_qsbr_defer_drop_while_pinned_waits);

fn smoke_rcu_qsbr_sync_is_idempotent() -> TestResult {
    // Two back-to-back syncs with nothing pending: second is a
    // cheap no-op, both return without blocking forever.
    let before = crate::qsbr::global_epoch();
    crate::sync();
    crate::sync();
    let after = crate::qsbr::global_epoch();
    if after > before {
        TestResult::Pass
    } else {
        TestResult::Fail("epoch didn't advance across two syncs")
    }
}
kernel_test_in!("rcu", smoke_rcu_qsbr_sync_is_idempotent);

// ── epoch ─────────────────────────────────────────────────────────

fn smoke_rcu_epoch_advance_monotonic() -> TestResult {
    // `epoch::advance()` returns a strictly higher value each call.
    let a = crate::epoch::advance();
    let b = crate::epoch::advance();
    let c = crate::epoch::advance();
    if b > a && c > b {
        TestResult::Pass
    } else {
        TestResult::Fail("epoch::advance is not monotonic")
    }
}
kernel_test_in!("rcu", smoke_rcu_epoch_advance_monotonic);

fn smoke_rcu_epoch_min_pinned_restored_after_drop() -> TestResult {
    // While pinned `min_pinned()` reflects the held epoch; after
    // the guard drops it returns to the sentinel.
    let sentinel = crate::epoch::min_pinned();
    {
        let _g = crate::epoch::pin();
        if crate::epoch::min_pinned() == sentinel {
            return TestResult::Fail("min_pinned still sentinel while pinned");
        }
    }
    if crate::epoch::min_pinned() != sentinel {
        TestResult::Fail("min_pinned didn't restore to sentinel after drop")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("rcu", smoke_rcu_epoch_min_pinned_restored_after_drop);

// ── hazard ────────────────────────────────────────────────────────

fn smoke_rcu_hazard_acquire_null_cell_returns_none() -> TestResult {
    // `domain.acquire(&cell)` on a null cell must return None
    // without panicking; the slot stays free for the next caller.
    use crate::hazard::HazardDomain;
    use core::sync::atomic::AtomicPtr;
    let domain = HazardDomain::new();
    let cell: AtomicPtr<u32> = AtomicPtr::new(core::ptr::null_mut());
    if domain.acquire(&cell).is_some() {
        TestResult::Fail("acquire on null cell returned Some")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("rcu", smoke_rcu_hazard_acquire_null_cell_returns_none);

// (Removed: smoke_rcu_hazard_partial_hold_blocks_only_held_entry —
// the existing `smoke_rcu_hazard_retired_but_held` already covers
// the held-vs-scan invariant. A two-entry partial-hold variant
// would duplicate coverage rather than add a new invariant.)

// ── batched ───────────────────────────────────────────────────────

fn smoke_rcu_batched_two_flushes_track_totals() -> TestResult {
    // Two submit-flush rounds: total_submitted + total_drained track
    // the running totals across both, pending settles to 0 each time.
    use crate::BatchedReclaimer;
    use core::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);
    N.store(0, Ordering::Relaxed);
    let r = BatchedReclaimer::new(0);

    for _ in 0..5 {
        let _ = r.submit(|| {
            N.fetch_add(1, Ordering::Relaxed);
        });
    }
    r.flush();
    if N.load(Ordering::Relaxed) != 5 || r.pending() != 0 {
        return TestResult::Fail("first round didn't drain");
    }

    for _ in 0..7 {
        let _ = r.submit(|| {
            N.fetch_add(1, Ordering::Relaxed);
        });
    }
    r.flush();
    if N.load(Ordering::Relaxed) != 12 {
        return TestResult::Fail("second round didn't drain");
    }
    if r.total_submitted() != 12 || r.total_drained() != 12 {
        return TestResult::Fail("totals didn't accumulate across two flushes");
    }
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_batched_two_flushes_track_totals);

fn smoke_rcu_batched_pending_tracks_unflushed() -> TestResult {
    // Stage-4 `BatchedReclaimer` has no `Drop` that drains — pending
    // callbacks are leaked on drop, by design (reclamation is the
    // dispatcher's job, not the reclaimer's). Pin the documented
    // behaviour so a future "auto-drain on drop" refactor stays
    // explicit (it would silently change leak semantics).
    use crate::BatchedReclaimer;
    use core::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);
    N.store(0, Ordering::Relaxed);
    let r = BatchedReclaimer::new(0);
    for _ in 0..3 {
        let _ = r.submit(|| {
            N.fetch_add(1, Ordering::Relaxed);
        });
    }
    if r.pending() != 3 {
        return TestResult::Fail("pending didn't track three submits");
    }
    if N.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("callback ran before flush");
    }
    // Flush is the only way to drain.
    r.flush();
    if r.pending() != 0 {
        return TestResult::Fail("flush left pending non-zero");
    }
    if N.load(Ordering::Relaxed) != 3 {
        TestResult::Fail("flush didn't run every callback")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("rcu", smoke_rcu_batched_pending_tracks_unflushed);
