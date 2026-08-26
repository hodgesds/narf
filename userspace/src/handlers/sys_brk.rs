#[allow(unused_imports)]
use super::*;

/// `brk(2)` core, driven off the ADDRESS SPACE's break (not per-task).
///
/// The break is AS state: `CLONE_VM` threads share it (they share the
/// `AddressSpace`) and a real fork inherits it (`clone_for_fork`). See
/// `AddressSpace::brk_top`.
///
/// The heap is a SINGLE growable VMA rooted at `BRK_DEFAULT_BASE`. A grow
/// extends that VMA in place (`brk_extend_region`) with lazy zero-backed slots;
/// first touch allocates through the user-reserve-aware demand-fault path. A
/// shrink tail-punches the freed range (`punch_fixed`). Repeated small grows
/// therefore stay O(log VMA + pages-added) without allocating resident pages
/// or entering direct reclaim from the syscall.
///
/// Returns the resulting break (Linux `brk` reports the break value, never an
/// errno; glibc's wrapper detects failure by comparing against the request).
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn brk_core(as_ref: &AddressSpace, new_break: u64) -> u64 {
    brk_core_limited(
        as_ref,
        new_break,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        true,
    )
}

fn brk_core_limited(
    as_ref: &AddressSpace,
    new_break: u64,
    data_limit_bytes: u64,
    address_space_limit_bytes: u64,
    memlock_limit_bytes: u64,
    bypass_memlock_limit: bool,
) -> u64 {
    let mut lazy_pages = alloc::vec::Vec::new();
    loop {
        match as_ref.update_brk_limited(
            VirtAddr::new(BRK_DEFAULT_BASE),
            BRK_ARENA_TOP,
            new_break,
            lazy_pages,
            data_limit_bytes,
            address_space_limit_bytes,
            memlock_limit_bytes,
            bypass_memlock_limit,
        ) {
            narf_memory::BrkUpdateResult::Complete(value) => return value,
            narf_memory::BrkUpdateResult::NeedPages(page_count) => {
                // Allocate only inert lazy descriptors and do it outside the
                // IRQ-safe VMA transaction. A CLONE_VM peer may have changed
                // the exact delta; the next serialized attempt revalidates it.
                let mut prepared = alloc::vec::Vec::new();
                if prepared.try_reserve_exact(page_count).is_err() {
                    return as_ref.brk_top().max(BRK_DEFAULT_BASE);
                }
                prepared.resize(page_count, narf_memory::PhysAddr::new(0));
                lazy_pages = prepared;
            }
        }
    }
}

pub(crate) fn sys_brk(ctx: &mut dyn TrapContext) {
    let new_break = ctx.args().arg0;
    let authority = current_mlock_authority();
    let task = current_task_id();
    let defaults = default_rlimits();
    let data_limit = read_rlimit(task, RLIMIT_DATA)
        .unwrap_or(defaults[RLIMIT_DATA])
        .cur;
    let address_space_limit = read_rlimit(task, RLIMIT_AS)
        .unwrap_or(defaults[RLIMIT_AS])
        .cur;
    let result = match current_address_space() {
        Some(as_ref) => brk_core_limited(
            &as_ref,
            new_break,
            data_limit,
            address_space_limit,
            authority.limit_bytes,
            authority.bypass_limit,
        ),
        // No address space (never happens for a real user task): report the
        // arena base so a query looks sane and a set reads as "didn't move".
        None => BRK_DEFAULT_BASE,
    };
    ctx.set_return(SyscallReturn::ok(result));
}

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Regression (kwin heap-UAF SIGSEGV): the program break is ADDRESS-SPACE
    /// state, shared by every CLONE_VM thread and inherited by fork — not
    /// per-task. Per-task keying let a fresh worker thread answer `brk(0)` with
    /// the arena base, which glibc latched into its process-global `__curbrk`;
    /// the main thread's next `sbrk` then computed a mid-heap break and the
    /// shrink path `unmap_region`'d live heap out from under malloc. This test
    /// pins: the break lives on the AS, a query returns the real high break,
    /// a small grow past it never unmaps live heap, fork inherits it, and a
    /// genuine shrink unmaps only regions at/above the new break.
    fn smoke_brk_break_is_address_space_scoped_and_inherited() -> TestResult {
        let base = BRK_DEFAULT_BASE;
        // SAFETY: kernel tests run with paging live and the frame allocator
        // initialised, satisfying new_for_user's contract.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(a) => a,
            Err(_) => return TestResult::Fail("new_for_user failed"),
        };

        // First brk seeds the arena base; the break is stored on the AS.
        if brk_core(&aspace, 0) != base {
            return TestResult::Fail("initial brk(0) did not return the arena base");
        }
        // Two grows.
        if brk_core(&aspace, base + 0x40000) != base + 0x40000 {
            return TestResult::Fail("first grow did not return the new break");
        }
        if brk_core(&aspace, base + 0x100000) != base + 0x100000 {
            return TestResult::Fail("second grow did not return the new break");
        }
        // The break is on the AddressSpace — the value a shared thread now reads
        // (the exact datum per-task keying lost, handing back BRK_DEFAULT_BASE).
        if aspace.brk_top() != base + 0x100000 {
            return TestResult::Fail("break is not stored on the AddressSpace");
        }
        if brk_core(&aspace, 0) != base + 0x100000 {
            return TestResult::Fail("brk(0) query lost the real break");
        }
        // A page well inside the grown heap (the crash offset) is mapped.
        if aspace.lookup(VirtAddr::new(base + 0x77000)).is_none() {
            return TestResult::Fail("grown heap page not mapped");
        }

        // Replay the poison SHAPE safely: a small grow past the true break must
        // stay on the grow path and never unmap live heap. Pre-fix a stale-low
        // break made glibc compute a mid-heap value that hit the shrink path and
        // unmapped exactly base+0x77000.
        if brk_core(&aspace, base + 0x121000) != base + 0x121000 {
            return TestResult::Fail("small grow past the break failed");
        }
        if aspace.lookup(VirtAddr::new(base + 0x77000)).is_none() {
            return TestResult::Fail("a small grow unmapped live heap (the crash)");
        }

        // A real fork inherits the break (clone_for_fork), so the child's first
        // brk does not mass-unmap the cloned heap.
        // SAFETY: paging is live in a kernel test; `aspace` is a freshly built
        // user AS with no concurrent writers.
        let child = match unsafe { aspace.clone_for_fork() } {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("clone_for_fork failed"),
        };
        if child.brk_top() != aspace.brk_top() {
            return TestResult::Fail("fork child did not inherit the parent's break");
        }
        aspace.set_program_data_bytes(0x3456);
        // SAFETY: same freshly-created, live test address space as the first
        // fork clone above, with paging and the frame allocator initialized.
        let child_with_data = match unsafe { aspace.clone_for_fork() } {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("second clone_for_fork failed"),
        };
        if child_with_data.program_data_bytes() != 0x3456 {
            return TestResult::Fail("fork child did not inherit RLIMIT_DATA metadata");
        }

        // Genuine shrink: unmap regions at/above the new break, keep those below.
        if brk_core(&aspace, base + 0x40000) != base + 0x40000 {
            return TestResult::Fail("shrink did not return the new break");
        }
        if aspace.lookup(VirtAddr::new(base + 0x77000)).is_some() {
            return TestResult::Fail("shrink kept a region above the new break");
        }
        if aspace.lookup(VirtAddr::new(base + 0x20000)).is_none() {
            return TestResult::Fail("shrink unmapped a region below the new break");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_brk_break_is_address_space_scoped_and_inherited
    );

    /// Count heap VMAs (bases inside the brk arena) currently registered.
    fn heap_vma_count(aspace: &AddressSpace) -> usize {
        aspace
            .regions_snapshot()
            .iter()
            .filter(|r| (BRK_DEFAULT_BASE..BRK_ARENA_TOP).contains(&r.base.as_u64()))
            .count()
    }

    /// The heap is a SINGLE growable VMA: many small grows extend it in place
    /// (one VMA, not N) with lazy zero slots; a shrink tail-punches. This pins
    /// O(1)-VMA growth, no resident-frame allocation in brk(2), exact
    /// partial-page break semantics, and rollback when registration fails.
    fn smoke_brk_single_growable_vma() -> TestResult {
        let base = BRK_DEFAULT_BASE;
        // SAFETY: kernel tests run with paging live and the frame allocator
        // initialised, satisfying new_for_user's contract.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(a) => a,
            Err(_) => return TestResult::Fail("new_for_user failed"),
        };

        // Seed the arena base.
        if brk_core(&aspace, 0) != base {
            return TestResult::Fail("initial brk(0) did not return the arena base");
        }

        // Many small grows, each one page. Each must advance the break and, as
        // the whole point of the fix, keep exactly ONE heap VMA.
        let grows = 64u64;
        for i in 1..=grows {
            let want = base + i * 0x1000;
            if brk_core(&aspace, want) != want {
                return TestResult::Fail("small grow did not return the new break");
            }
            if heap_vma_count(&aspace) != 1 {
                return TestResult::Fail("small grows registered more than one heap VMA");
            }
        }
        let top = base + grows * 0x1000;
        if aspace.brk_top() != top {
            return TestResult::Fail("break did not advance across small grows");
        }

        // Every grown page belongs to the heap VMA but remains nonresident.
        // First touch, not brk(2), must allocate and zero user backing.
        let region = match aspace.lookup(VirtAddr::new(base)) {
            Some(r) => r,
            None => return TestResult::Fail("heap VMA absent after grows"),
        };
        if region.len != grows * 0x1000 {
            return TestResult::Fail("heap VMA len did not track the grows");
        }
        if region
            .phys
            .iter()
            .any(|phys| *phys != narf_memory::PhysAddr::new(0))
        {
            return TestResult::Fail("brk growth eagerly allocated a resident frame");
        }
        let stats = aspace.memory_stats();
        if stats.resident_pages != 0 {
            return TestResult::Fail("lazy brk VMA contributed resident pages");
        }

        // `top` is page aligned, so growing to `top+0x40` adds exactly one lazy
        // slot and lands the break mid-page.
        let mid = top + 0x40;
        if brk_core(&aspace, mid) != mid {
            return TestResult::Fail("grow into a fresh page did not return the new break");
        }
        if aspace.brk_top() != mid
            || heap_vma_count(&aspace) != 1
            || aspace.lookup(VirtAddr::new(base)).map(|r| r.len) != Some((grows + 1) * 0x1000)
        {
            return TestResult::Fail("grow into a fresh page did not add exactly one page");
        }

        // Exact partial-page break: extending the break WITHIN the now-backed
        // last page moves the break without adding a page or a VMA.
        let within = top + 0x80;
        if brk_core(&aspace, within) != within {
            return TestResult::Fail("within-page grow did not return the new break");
        }
        if aspace.brk_top() != within
            || heap_vma_count(&aspace) != 1
            || aspace.lookup(VirtAddr::new(base)).map(|r| r.len) != Some((grows + 1) * 0x1000)
        {
            return TestResult::Fail("within-page grow changed the heap VMA");
        }

        // Partial-page shrink back within the last page frees no frame and keeps
        // the VMA, but records the smaller break.
        if brk_core(&aspace, mid) != mid {
            return TestResult::Fail("within-page shrink did not return the new break");
        }
        if aspace.brk_top() != mid
            || heap_vma_count(&aspace) != 1
            || aspace.lookup(VirtAddr::new(base)).map(|r| r.len) != Some((grows + 1) * 0x1000)
        {
            return TestResult::Fail("within-page shrink changed the heap VMA");
        }

        // A failed grow leaves the break unchanged (POSIX rollback). Requesting
        // past the arena ceiling is rejected and must report the OLD break.
        let before = aspace.brk_top();
        if brk_core(&aspace, BRK_ARENA_TOP + 0x1000) != before {
            return TestResult::Fail("over-ceiling grow did not report the old break");
        }
        if aspace.brk_top() != before {
            return TestResult::Fail("over-ceiling grow moved the break");
        }

        // A real shrink tail-punches: pages at/above the new break go, the VMA
        // stays single and truncated, pages below remain mapped.
        let shrink_to = base + 8 * 0x1000;
        if brk_core(&aspace, shrink_to) != shrink_to {
            return TestResult::Fail("shrink did not return the new break");
        }
        if heap_vma_count(&aspace) != 1 {
            return TestResult::Fail("shrink split or dropped the single heap VMA");
        }
        if aspace.lookup(VirtAddr::new(base + 32 * 0x1000)).is_some() {
            return TestResult::Fail("shrink kept a page above the new break");
        }
        if aspace.lookup(VirtAddr::new(base + 4 * 0x1000)).is_none() {
            return TestResult::Fail("shrink unmapped a page below the new break");
        }
        match aspace.lookup(VirtAddr::new(base)) {
            Some(r) if r.len == 8 * 0x1000 => {}
            _ => return TestResult::Fail("heap VMA not truncated to the new break"),
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_brk_single_growable_vma);

    /// A user MAP_FIXED mapping at the conventional heap base is not a brk
    /// VMA. The in-place grow optimization must reject the collision rather
    /// than append frames to that foreign mapping and let a later brk shrink
    /// tear it down.
    fn smoke_brk_does_not_annex_foreign_base_vma() -> TestResult {
        let aspace = AddressSpace::empty();
        let base = VirtAddr::new(BRK_DEFAULT_BASE);
        if aspace
            .map_region(Region {
                base,
                len: 0x1000,
                perms: RegionPerms::READ,
                phys: alloc::vec![narf_memory::PhysAddr::new(0)],
            })
            .is_err()
        {
            return TestResult::Fail("foreign base mapping setup failed");
        }
        let before = aspace.lookup(base).expect("foreign mapping disappeared");
        let got = brk_core(&aspace, BRK_DEFAULT_BASE + 0x1000);
        let after = aspace.lookup(base).expect("foreign mapping disappeared");
        if got != BRK_DEFAULT_BASE || aspace.brk_top() != BRK_DEFAULT_BASE {
            return TestResult::Fail("brk advanced across a foreign base mapping");
        }
        if after.len != before.len || after.perms != before.perms || after.phys != before.phys {
            return TestResult::Fail("brk annexed or mutated a foreign base mapping");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_brk_does_not_annex_foreign_base_vma);

    /// Linux rejects requests below start_brk before attempting any unmap.
    /// This prevents a malformed brk from punching unrelated lower VMAs.
    fn smoke_brk_below_base_preserves_foreign_vma() -> TestResult {
        let aspace = AddressSpace::empty();
        let foreign = VirtAddr::new(BRK_DEFAULT_BASE - 0x2000);
        if aspace
            .map_region(Region {
                base: foreign,
                len: 0x2000,
                perms: RegionPerms::READ,
                phys: alloc::vec![narf_memory::PhysAddr::new(0); 2],
            })
            .is_err()
        {
            return TestResult::Fail("lower foreign mapping setup failed");
        }
        if brk_core(&aspace, BRK_DEFAULT_BASE - 0x1000) != BRK_DEFAULT_BASE {
            return TestResult::Fail("below-base brk did not return the old break");
        }
        if aspace.lookup(foreign).map(|region| region.len) != Some(0x2000) {
            return TestResult::Fail("below-base brk punched an unrelated VMA");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_brk_below_base_preserves_foreign_vma);

    /// Failure to tear down an old heap tail must leave mm->brk unchanged.
    fn smoke_brk_shrink_failure_rolls_back_break() -> TestResult {
        let aspace = AddressSpace::empty();
        let high = BRK_DEFAULT_BASE + 0x3000;
        if brk_core(&aspace, high) != high
            || aspace
                .punch_fixed(VirtAddr::new(BRK_DEFAULT_BASE), 0x3000)
                .is_err()
        {
            return TestResult::Fail("shrink rollback setup failed");
        }
        if brk_core(&aspace, BRK_DEFAULT_BASE) != high || aspace.brk_top() != high {
            return TestResult::Fail("failed shrink published a lower break");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_brk_shrink_failure_rolls_back_break);

    /// RLIMIT_DATA is checked on the byte-precise request before page-aligning
    /// it; RLIMIT_AS charges VMA pages but excludes NARF's synthetic guard.
    fn smoke_brk_enforces_linux_data_and_as_limits() -> TestResult {
        let data_as = AddressSpace::empty();
        data_as.set_program_data_bytes(0x1800);
        let exact = BRK_DEFAULT_BASE + 0x800;
        if brk_core_limited(&data_as, exact, 0x2000, u64::MAX, u64::MAX, true) != exact {
            return TestResult::Fail("exact RLIMIT_DATA boundary was rejected");
        }
        if brk_core_limited(
            &data_as,
            exact + 1,
            0x2000,
            u64::MAX,
            u64::MAX,
            true,
        ) != exact
            || data_as.brk_top() != exact
        {
            return TestResult::Fail("same-page brk escaped RLIMIT_DATA");
        }

        let as_as = AddressSpace::empty();
        let ordinary = VirtAddr::new(AddressSpace::MMAP_CURSOR_BASE);
        let guard = VirtAddr::new(AddressSpace::MMAP_CURSOR_BASE + 0x2000);
        if as_as
            .map_region(Region {
                base: ordinary,
                len: 0x1000,
                perms: RegionPerms::READ,
                phys: alloc::vec![narf_memory::PhysAddr::new(0)],
            })
            .is_err()
            || as_as
                .map_region(Region {
                    base: guard,
                    len: 0x1000,
                    perms: RegionPerms::STACK_GUARD | RegionPerms::LOCK_EXEMPT,
                    phys: alloc::vec![narf_memory::PhysAddr::new(0)],
                })
                .is_err()
        {
            return TestResult::Fail("RLIMIT_AS setup mapping failed");
        }
        let one_page = BRK_DEFAULT_BASE + 0x1000;
        if brk_core_limited(&as_as, one_page, u64::MAX, 0x2000, u64::MAX, true) != one_page {
            return TestResult::Fail("synthetic guard was charged to RLIMIT_AS");
        }
        if brk_core_limited(
            &as_as,
            one_page + 0x1000,
            u64::MAX,
            0x2000,
            u64::MAX,
            true,
        ) != one_page
        {
            return TestResult::Fail("brk growth escaped RLIMIT_AS");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_brk_enforces_linux_data_and_as_limits);
}
