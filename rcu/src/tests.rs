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
    use core::sync::atomic::{AtomicUsize, Ordering};
    use crate::{Atomic, Owned};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) { DROPS.fetch_add(1, Ordering::Relaxed); }
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
        fn drop(&mut self) { DROPS.fetch_add(1, Ordering::Relaxed); }
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
            Ok(g)  => g,
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
    use narf_capabilities::CapError;
    use crate::sleepable::{SleepableReader, SleepableScope};

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
        Ok(_)  => return TestResult::Fail("enter accepted a revoked cap"),
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
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
    use crate::hazard::HazardDomain;

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary { v: u32 }
    impl Drop for Canary {
        fn drop(&mut self) { DROPS.fetch_add(1, Ordering::Relaxed); }
    }

    DROPS.store(0, Ordering::Relaxed);

    let domain = HazardDomain::new();
    let raw = Box::into_raw(Box::new(Canary { v: 0xdead_beef }));
    let cell: AtomicPtr<Canary> = AtomicPtr::new(raw);

    {
        let g = match domain.acquire(&cell) {
            Some(g) => g,
            None    => return TestResult::Fail("acquire returned None on a non-null cell"),
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
        unsafe { drop(Box::from_raw(p)); }
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
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
    use crate::hazard::HazardDomain;

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) { DROPS.fetch_add(1, Ordering::Relaxed); }
    }

    DROPS.store(0, Ordering::Relaxed);

    let domain = HazardDomain::new();
    let raw = Box::into_raw(Box::new(Canary));
    let cell: AtomicPtr<Canary> = AtomicPtr::new(raw);

    let g = match domain.acquire(&cell) {
        Some(g) => g,
        None    => return TestResult::Fail("acquire returned None on a non-null cell"),
    };

    fn drop_canary(p: *mut Canary) {
        // SAFETY: hazard discipline; we're not invoked while held.
        unsafe { drop(Box::from_raw(p)); }
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
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use crate::hazard::HazardDomain;

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Canary;
    impl Drop for Canary {
        fn drop(&mut self) { DROPS.fetch_add(1, Ordering::Relaxed); }
    }

    DROPS.store(0, Ordering::Relaxed);
    let domain = HazardDomain::new();

    fn drop_canary(p: *mut Canary) {
        // SAFETY: hazard discipline; the test never holds these.
        unsafe { drop(Box::from_raw(p)); }
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
    use core::sync::atomic::{AtomicU32, Ordering};
    use crate::BatchedReclaimer;

    static COUNT: AtomicU32 = AtomicU32::new(0);
    COUNT.store(0, Ordering::Relaxed);

    let r = BatchedReclaimer::new(0);
    if r.pending() != 0 { return TestResult::Fail("fresh reclaimer has pending"); }

    for _ in 0..10 {
        let _full = r.submit(|| { COUNT.fetch_add(1, Ordering::Relaxed); });
    }
    if r.pending() != 10 { return TestResult::Fail("submitted != pending"); }
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
    r.pace(2, 500);   // hint-only, no observable side effect
    TestResult::Pass
}
kernel_test_in!("rcu", smoke_rcu_batched_reclaim_drains);
