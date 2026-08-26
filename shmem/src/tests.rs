//! Per-crate smoke tests for `narf-shmem`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under the `"shmem"` subsystem.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_shmem_create_destroy_round_trip() -> TestResult {
    use crate::{__reset_for_test, count, create, destroy, len_of, phys_at, pid_of};
    __reset_for_test();
    let pid_a = 9001u64;
    // Single-page region.
    let h1 = match create(pid_a, 4096) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("create 4 KiB"),
    };
    if h1 == 0 {
        return TestResult::Fail("zero handle");
    }
    if len_of(h1) != Some(4096) {
        return TestResult::Fail("len mismatch single page");
    }
    if pid_of(h1) != Some(pid_a) {
        return TestResult::Fail("pid mismatch");
    }
    // Multi-page: 7 KiB rounds to 8 KiB (2 pages).
    let h2 = match create(pid_a, 7000) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("create 7000 bytes"),
    };
    if h1 == h2 {
        return TestResult::Fail("handles aliased");
    }
    if len_of(h2) != Some(8192) {
        return TestResult::Fail("len roundup wrong");
    }
    // phys_at must straddle pages cleanly: phys at +0 and +4096
    // are different (different frames) but at +0 and +1 are
    // contiguous (same frame).
    let p0 = phys_at(h2, 0).expect("phys 0");
    let p1 = phys_at(h2, 1).expect("phys 1");
    let p4096 = phys_at(h2, 4096).expect("phys 4096");
    if p1 != p0 + 1 {
        return TestResult::Fail("phys_at intra-page math wrong");
    }
    if p4096 == p0 + 4096 {
        // Frame allocator rarely returns contiguous pages — this
        // would be a real (but unlikely) coincidence; the smoke
        // is structural so don't flake on it.
    }
    // Out-of-range offset rejected.
    if phys_at(h2, 8192).is_some() {
        return TestResult::Fail("phys_at past end accepted");
    }
    // 0-len rejected.
    if create(pid_a, 0).is_ok() {
        return TestResult::Fail("0-len should reject");
    }
    // Page-rounding must reject overflow instead of wrapping a hostile huge
    // length into a tiny/zero allocation.
    if create(pid_a, u64::MAX).is_ok() {
        return TestResult::Fail("overflowing length should reject");
    }
    if count() != 2 {
        return TestResult::Fail("count mismatch");
    }
    if !destroy(h1) {
        return TestResult::Fail("destroy h1");
    }
    if destroy(h1) {
        return TestResult::Fail("double-destroy succeeded");
    }
    if count() != 1 {
        return TestResult::Fail("count after destroy");
    }
    if !destroy(h2) {
        return TestResult::Fail("destroy h2");
    }
    if count() != 0 {
        return TestResult::Fail("count after both destroys");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_create_destroy_round_trip);

fn smoke_shmem_removed_handle_waits_for_last_mapping() -> TestResult {
    use crate::{__reset_for_test, count, create, destroy, frames_of, len_of, syscall_vtable};
    __reset_for_test();
    let handle = create(9002, 4096).expect("create");
    let phys = frames_of(handle).expect("frames")[0].raw();
    let vtable = syscall_vtable();

    // Model one AddressSpace SHARED alias. IPC_RMID removes the name and
    // rejects new attachments, but the mapped page must remain movable and
    // backed until that alias is torn down.
    (vtable.retain_frame)(phys);
    if !destroy(handle) {
        return TestResult::Fail("destroy");
    }
    if count() != 0 || len_of(handle).is_some() || frames_of(handle).is_some() {
        return TestResult::Fail("removed handle remained publicly visible");
    }
    if !(vtable.owns_frame)(phys) {
        return TestResult::Fail("mapped page reclaimed before final alias");
    }
    (vtable.release_frame)(phys);
    if (vtable.owns_frame)(phys) {
        return TestResult::Fail("page survived final alias release");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_removed_handle_waits_for_last_mapping);

fn smoke_shmem_sg_iter_walks_pages() -> TestResult {
    use crate::{__reset_for_test, create, sg_iter, SgEntry};
    __reset_for_test();
    // Three-page region. Frame allocator returns non-contiguous
    // pages in general; the SG iter must handle either contiguity
    // pattern correctly.
    let pid = 9201u64;
    let h = match create(pid, 12 * 1024) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("create"),
    };

    // (a) Whole-region walk: 3 entries summing to 12 KiB.
    let entries: alloc::vec::Vec<SgEntry> = sg_iter(h, 0, 12 * 1024).expect("sg_iter").collect();
    if entries.len() != 3 {
        return TestResult::Fail("whole-region: expected 3 entries");
    }
    let total: u64 = entries.iter().map(|e| e.len as u64).sum();
    if total != 12 * 1024 {
        return TestResult::Fail("whole-region: lengths don't sum to 12 KiB");
    }
    for e in &entries {
        if e.len != 4096 {
            return TestResult::Fail("whole-region: every entry must be 4 KiB");
        }
    }

    // (b) Mid-region slice: offset 100, len 7000. Crosses the
    // first page boundary at 4096, lands in the second page.
    let entries: alloc::vec::Vec<SgEntry> = sg_iter(h, 100, 7000).expect("sg_iter mid").collect();
    if entries.len() != 2 {
        return TestResult::Fail("mid-region: expected 2 entries");
    }
    if entries[0].len != 4096 - 100 {
        return TestResult::Fail("mid-region: first entry length wrong");
    }
    if entries[1].len != 7000 - (4096 - 100) {
        return TestResult::Fail("mid-region: second entry length wrong");
    }
    let total: u64 = entries.iter().map(|e| e.len as u64).sum();
    if total != 7000 {
        return TestResult::Fail("mid-region: lengths don't sum to 7000");
    }

    // (c) Single-page slice: stays within page 1.
    let entries: alloc::vec::Vec<SgEntry> =
        sg_iter(h, 4200, 1024).expect("sg_iter single").collect();
    if entries.len() != 1 || entries[0].len != 1024 {
        return TestResult::Fail("single-page slice");
    }

    // (d) Out-of-range rejected.
    if sg_iter(h, 0, 12 * 1024 + 1).is_some() {
        return TestResult::Fail("oob slice accepted");
    }
    // (e) Bad handle rejected.
    if sg_iter(0xDEADBEEF, 0, 4096).is_some() {
        return TestResult::Fail("bad handle accepted");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_sg_iter_walks_pages);

fn smoke_shmem_exit_observer_reaps_handles() -> TestResult {
    // Mirrors the fb exit-observer smoke. notify_task_exited(pid)
    // must reap every shmem region the dying pid owned.
    use crate::{__reset_for_test, count, create, destroy_all_for_pid};
    use narf_userspace::user_task::{
        __test_clear_exit_observers, notify_task_exited, register_process_exit_observer,
    };
    __reset_for_test();
    __test_clear_exit_observers();
    register_process_exit_observer(|pid, _tid| {
        let _ = destroy_all_for_pid(pid);
    });
    let pid_dies = 9101u64;
    let pid_keeps = 9102u64;
    let _ = create(pid_dies, 4096).expect("h1");
    let _ = create(pid_dies, 4096).expect("h2");
    let _ = create(pid_keeps, 4096).expect("h3");
    if count() != 3 {
        return TestResult::Fail("setup");
    }
    notify_task_exited(pid_dies, pid_dies);
    if count() != 1 {
        return TestResult::Fail("observer didn't reap dying pid's shmem");
    }
    notify_task_exited(pid_keeps, pid_keeps);
    if count() != 0 {
        return TestResult::Fail("survivor not reaped on its own exit");
    }
    __reset_for_test();
    __test_clear_exit_observers();
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_exit_observer_reaps_handles);

// ── deep shmem coverage ───────────────────────────────────────────
//
// Closes the remaining invariants on shmem's public surface that
// the 3 round-trip smokes don't reach.

fn smoke_shmem_create_rejects_zero_len() -> TestResult {
    use crate::{__reset_for_test, create, ShmemError};
    __reset_for_test();
    match create(7777, 0) {
        Err(ShmemError::BadLen) => TestResult::Pass,
        _ => TestResult::Fail("create(0) didn't surface BadLen"),
    }
}
kernel_test_in!("shmem", smoke_shmem_create_rejects_zero_len);

fn smoke_shmem_create_rejects_oversize_request() -> TestResult {
    // MAX_PAGES_PER_HANDLE * PAGE = 1 MiB; one byte past that
    // rejects with BadLen.
    use crate::{__reset_for_test, create, ShmemError};
    __reset_for_test();
    match create(7778, 1024 * 1024 + 1) {
        Err(ShmemError::BadLen) => TestResult::Pass,
        Ok(h) => {
            let _ = crate::destroy(h);
            TestResult::Fail("oversized create unexpectedly succeeded")
        }
        Err(_) => TestResult::Fail("oversized create surfaced wrong error"),
    }
}
kernel_test_in!("shmem", smoke_shmem_create_rejects_oversize_request);

fn smoke_shmem_unknown_handle_accessors_return_none() -> TestResult {
    // phys_at / len_of / pid_of / frames_of on an unknown handle
    // all return None without panicking.
    use crate::{__reset_for_test, frames_of, len_of, phys_at, pid_of};
    __reset_for_test();
    let bogus = 0xDEAD_BEEFu64;
    if phys_at(bogus, 0).is_some() {
        return TestResult::Fail("phys_at returned Some for bogus handle");
    }
    if len_of(bogus).is_some() {
        return TestResult::Fail("len_of returned Some for bogus handle");
    }
    if pid_of(bogus).is_some() {
        return TestResult::Fail("pid_of returned Some for bogus handle");
    }
    if frames_of(bogus).is_some() {
        return TestResult::Fail("frames_of returned Some for bogus handle");
    }
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_unknown_handle_accessors_return_none);

fn smoke_shmem_lock_state_tracks_backing_frames() -> TestResult {
    use crate::{__reset_for_test, create, destroy, frames_of, syscall_vtable};
    __reset_for_test();
    let handle = create(8000, 4096).expect("create locked backing");
    let phys = frames_of(handle).expect("locked backing frames")[0].raw();
    let vtable = syscall_vtable();
    if (vtable.frame_locked)(phys) {
        let _ = destroy(handle);
        return TestResult::Fail("fresh shmem backing started locked");
    }
    if (vtable.lock)(handle, 7, 1000, 4096, false).is_err() || !(vtable.frame_locked)(phys) {
        let _ = destroy(handle);
        return TestResult::Fail("SHM_LOCK state did not reach the backing frame");
    }
    if !(vtable.unlock)(handle) || (vtable.frame_locked)(phys) {
        let _ = destroy(handle);
        return TestResult::Fail("SHM_UNLOCK state did not leave the backing frame");
    }
    if (vtable.lock)(handle, 7, 1000, 4096, false).is_err() {
        let _ = destroy(handle);
        return TestResult::Fail("first per-user SHM_LOCK charge failed");
    }
    let second = create(8000, 4096).expect("second locked backing");
    if (vtable.lock)(second, 7, 1000, 4096, false)
        != Err(narf_userspace::handlers::ShmemLockError::Limit)
    {
        let _ = destroy(handle);
        let _ = destroy(second);
        return TestResult::Fail("per-user SHM_LOCK accounting exceeded its limit");
    }
    let _ = destroy(handle);
    if (vtable.lock)(second, 7, 1000, 4096, false).is_err() {
        let _ = destroy(second);
        return TestResult::Fail("destroy did not release the SHM_LOCK user charge");
    }
    let _ = destroy(second);
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_lock_state_tracks_backing_frames);

fn smoke_shmem_removed_lock_charge_survives_alias() -> TestResult {
    use crate::{__reset_for_test, create, destroy, frames_of, syscall_vtable};
    __reset_for_test();
    let vtable = syscall_vtable();
    let first = create(8003, 4096).expect("first backing");
    let first_phys = frames_of(first).expect("first frames")[0].raw();
    (vtable.retain_frame)(first_phys);
    if (vtable.lock)(first, 9, 1001, 4096, false).is_err() || !destroy(first) {
        return TestResult::Fail("setup removed locked alias");
    }

    let second = create(8003, 4096).expect("second backing");
    if (vtable.lock)(second, 9, 1001, 4096, false)
        != Err(narf_userspace::handlers::ShmemLockError::Limit)
    {
        return TestResult::Fail("IPC_RMID released a live alias's lock charge");
    }
    (vtable.release_frame)(first_phys);
    if (vtable.lock)(second, 9, 1001, 4096, false).is_err() {
        return TestResult::Fail("final alias release retained the lock charge");
    }
    let _ = destroy(second);
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_removed_lock_charge_survives_alias);

fn smoke_shmem_handle_id_monotonic() -> TestResult {
    // create() hands out monotonically-increasing handle ids; the
    // counter survives destroy().
    use crate::{__reset_for_test, create, destroy};
    __reset_for_test();
    let h1 = create(8001, 4096).expect("create#1");
    let h2 = create(8001, 4096).expect("create#2");
    let h3 = create(8002, 4096).expect("create#3");
    if !(h1 < h2 && h2 < h3) {
        return TestResult::Fail("handle ids not monotonic");
    }
    destroy(h2);
    let h4 = create(8001, 4096).expect("create#4");
    if h4 <= h3 {
        return TestResult::Fail("destroy + create didn't bump past the freed id");
    }
    let _ = destroy(h1);
    let _ = destroy(h3);
    let _ = destroy(h4);
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_handle_id_monotonic);

fn smoke_shmem_destroy_all_for_pid_only_owner() -> TestResult {
    // destroy_all_for_pid(p) tears down only p's regions; other
    // pids' regions survive.
    use crate::{__reset_for_test, count, create, destroy_all_for_pid};
    __reset_for_test();
    let p_dying = 8100u64;
    let p_keeps = 8101u64;
    let _ = create(p_dying, 4096).expect("a");
    let _ = create(p_dying, 4096).expect("b");
    let _ = create(p_keeps, 4096).expect("c");
    if count() != 3 {
        return TestResult::Fail("setup count != 3");
    }
    let reaped = destroy_all_for_pid(p_dying);
    if reaped != 2 {
        return TestResult::Fail("destroy_all_for_pid didn't reap exactly 2");
    }
    if count() != 1 {
        return TestResult::Fail("survivor count != 1");
    }
    // The survivor must belong to p_keeps.
    let _ = destroy_all_for_pid(p_keeps);
    if count() != 0 {
        return TestResult::Fail("survivor cleanup didn't drain");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_destroy_all_for_pid_only_owner);

fn smoke_shmem_error_variants_distinct() -> TestResult {
    use crate::ShmemError;
    let all = [
        ShmemError::OutOfMemory,
        ShmemError::BadLen,
        ShmemError::NotFound,
        ShmemError::NotOwner,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("ShmemError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_error_variants_distinct);
