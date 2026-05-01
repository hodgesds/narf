//! Per-crate smoke tests for `narf-shmem`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under the `"shmem"` subsystem.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_shmem_create_destroy_round_trip() -> TestResult {
    use crate::{__reset_for_test, count, create, destroy, len_of, pid_of, phys_at};
    __reset_for_test();
    let pid_a = 9001u64;
    // Single-page region.
    let h1 = match create(pid_a, 4096) {
        Ok(h)  => h,
        Err(_) => return TestResult::Fail("create 4 KiB"),
    };
    if h1 == 0 { return TestResult::Fail("zero handle"); }
    if len_of(h1) != Some(4096) {
        return TestResult::Fail("len mismatch single page");
    }
    if pid_of(h1) != Some(pid_a) {
        return TestResult::Fail("pid mismatch");
    }
    // Multi-page: 7 KiB rounds to 8 KiB (2 pages).
    let h2 = match create(pid_a, 7000) {
        Ok(h)  => h,
        Err(_) => return TestResult::Fail("create 7000 bytes"),
    };
    if h1 == h2 { return TestResult::Fail("handles aliased"); }
    if len_of(h2) != Some(8192) {
        return TestResult::Fail("len roundup wrong");
    }
    // phys_at must straddle pages cleanly: phys at +0 and +4096
    // are different (different frames) but at +0 and +1 are
    // contiguous (same frame).
    let p0    = phys_at(h2, 0).expect("phys 0");
    let p1    = phys_at(h2, 1).expect("phys 1");
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
    if count() != 2 { return TestResult::Fail("count mismatch"); }
    if !destroy(h1) { return TestResult::Fail("destroy h1"); }
    if destroy(h1)  { return TestResult::Fail("double-destroy succeeded"); }
    if count() != 1 { return TestResult::Fail("count after destroy"); }
    if !destroy(h2) { return TestResult::Fail("destroy h2"); }
    if count() != 0 { return TestResult::Fail("count after both destroys"); }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_create_destroy_round_trip);

fn smoke_shmem_sg_iter_walks_pages() -> TestResult {
    use crate::{__reset_for_test, create, sg_iter, SgEntry};
    __reset_for_test();
    // Three-page region. Frame allocator returns non-contiguous
    // pages in general; the SG iter must handle either contiguity
    // pattern correctly.
    let pid = 9201u64;
    let h = match create(pid, 12 * 1024) {
        Ok(h)  => h,
        Err(_) => return TestResult::Fail("create"),
    };

    // (a) Whole-region walk: 3 entries summing to 12 KiB.
    let entries: alloc::vec::Vec<SgEntry> = sg_iter(h, 0, 12 * 1024)
        .expect("sg_iter")
        .collect();
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
    let entries: alloc::vec::Vec<SgEntry> = sg_iter(h, 100, 7000)
        .expect("sg_iter mid")
        .collect();
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
    let entries: alloc::vec::Vec<SgEntry> = sg_iter(h, 4200, 1024)
        .expect("sg_iter single")
        .collect();
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
        __test_clear_exit_observers, register_exit_observer, notify_task_exited,
    };
    __reset_for_test();
    __test_clear_exit_observers();
    register_exit_observer(|pid| {
        let _ = destroy_all_for_pid(pid);
    });
    let pid_dies  = 9101u64;
    let pid_keeps = 9102u64;
    let _ = create(pid_dies,  4096).expect("h1");
    let _ = create(pid_dies,  4096).expect("h2");
    let _ = create(pid_keeps, 4096).expect("h3");
    if count() != 3 { return TestResult::Fail("setup"); }
    notify_task_exited(pid_dies);
    if count() != 1 {
        return TestResult::Fail("observer didn't reap dying pid's shmem");
    }
    notify_task_exited(pid_keeps);
    if count() != 0 {
        return TestResult::Fail("survivor not reaped on its own exit");
    }
    __reset_for_test();
    __test_clear_exit_observers();
    TestResult::Pass
}
kernel_test_in!("shmem", smoke_shmem_exit_observer_reaps_handles);
