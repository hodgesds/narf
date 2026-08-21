#[allow(unused_imports)]
use super::*;

/// `brk(2)` core, driven off the ADDRESS SPACE's break (not per-task).
///
/// The break is AS state: `CLONE_VM` threads share it (they share the
/// `AddressSpace`) and a real fork inherits it (`clone_for_fork`). Keying it
/// per-task let a fresh worker thread — with no entry — answer `brk(0)` with the
/// arena base, which glibc latched into its process-global `__curbrk`; the main
/// thread's next `sbrk` then computed a mid-heap break and the shrink path below
/// `unmap_region`'d live heap out from under malloc (a deterministic heap
/// use-after-unmap SIGSEGV, observed in kwin_wayland). See `AddressSpace::brk_top`.
///
/// Returns the resulting break (Linux `brk` reports the break value, never an
/// errno; glibc's wrapper detects failure by comparing against the request).
fn brk_core(as_ref: &AddressSpace, new_break: u64) -> u64 {
    // Current break, seeding the arena base on first use of this AS.
    let mut cur = as_ref.brk_top();
    if cur == 0 {
        cur = BRK_DEFAULT_BASE;
        as_ref.set_brk_top(cur);
    }

    // Query path: arg0 == 0 just returns the current break.
    if new_break == 0 {
        return cur;
    }

    // Ceiling: never let the heap climb past the arena top (which keeps it below
    // the interpreter bias and the anonymous mmap window). A request above the
    // ceiling fails per POSIX brk's contract — return the unchanged break so
    // glibc/musl fall back to mmap.
    if new_break > BRK_ARENA_TOP {
        return cur;
    }

    // Shrink path: walk the per-grow-call brk regions (each base ≥
    // BRK_DEFAULT_BASE) and unmap any whose base falls entirely within
    // [new_break_aligned, cur). Each unmap_region walks PTEs + frees the
    // underlying frames. A grow region whose base sits BELOW new_break but
    // extends past it is left intact — partial unmapping would need a region-
    // split primitive; documented limitation, over-keep bounded by the grow
    // chunk size.
    if new_break < cur {
        let new_aligned = (new_break + 0xFFF) & !0xFFFu64;
        let mut bases_to_unmap: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        for r in as_ref.regions_snapshot().iter() {
            let rb = r.base.as_u64();
            // Brk-grow regions live in `[BRK_DEFAULT_BASE, cur)` — bounded above
            // by the OLD break. Without the `rb < cur` upper bound, any region
            // above BRK_DEFAULT_BASE matches and gets unmapped, which on a fresh
            // process (cur == BRK_DEFAULT_BASE) silently nukes the user stack the
            // next time the caller does `brk(small_value)` (ld-musl's
            // `__init_libc` does exactly that early in init).
            if rb >= BRK_DEFAULT_BASE && rb < cur && rb >= new_aligned {
                bases_to_unmap.push(rb);
            }
        }
        for b in bases_to_unmap {
            let _ = as_ref.unmap_region(VirtAddr::new(b));
        }
        as_ref.set_brk_top(new_break);
        return new_break;
    }

    // Grow path: allocate frames + install a SINGLE Region for the whole new
    // range. On any failure, roll the break back to `cur` (POSIX brk failure
    // contract) WITHOUT leaking frames or leaving a half-registered region.
    let cur_aligned = (cur + 0xFFF) & !0xFFFu64;
    let new_aligned = (new_break + 0xFFF) & !0xFFFu64;
    let pages = (new_aligned - cur_aligned) >> 12;
    if pages == 0 {
        // Within-page grow — just record the new break, no PTE work.
        as_ref.set_brk_top(new_break);
        return new_break;
    }
    let mut phys_list: alloc::vec::Vec<narf_memory::PhysAddr> =
        alloc::vec::Vec::with_capacity(pages as usize);
    for _ in 0..pages {
        let phys = match narf_memory::alloc_frame() {
            Ok(f) => f.start_address(),
            Err(_) => {
                // Free the frames already reserved for this grow — a
                // `Vec<PhysAddr>` drop frees nothing, so the old code leaked one
                // frame per page on every OOM'd heap grow.
                for p in &phys_list {
                    narf_memory::free_frame(narf_memory::PhysFrame::new(*p));
                }
                return cur;
            }
        };
        // SAFETY: identity-mapped low 4 GiB; phys is page-aligned.
        unsafe {
            core::ptr::write_bytes(phys.raw() as *mut u8, 0, 0x1000);
        }
        phys_list.push(phys);
    }
    if as_ref
        .map_region(Region {
            base: VirtAddr::new(cur_aligned),
            len: pages * 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: phys_list,
        })
        .is_err()
    {
        return cur;
    }
    // SAFETY: `as_ref` is the calling task's AddressSpace (valid root); the brk
    // region was just registered via `map_region`, so materialize installs only
    // its PTEs.
    // SAFETY: Valid memory or trusted environment
    if unsafe { as_ref.materialize() }.is_err() {
        // Un-register the region we just mapped: rolling the break back while
        // leaving the region installed wedges every future grow on Overlap.
        let _ = as_ref.unmap_region(VirtAddr::new(cur_aligned));
        return cur;
    }

    as_ref.set_brk_top(new_break);
    new_break
}

pub(crate) fn sys_brk(ctx: &mut dyn TrapContext) {
    let new_break = ctx.args().arg0;
    let result = match current_address_space() {
        Some(as_ref) => brk_core(&as_ref, new_break),
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
        let child = match unsafe { aspace.clone_for_fork() } {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("clone_for_fork failed"),
        };
        if child.brk_top() != aspace.brk_top() {
            return TestResult::Fail("fork child did not inherit the parent's break");
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
    kernel_test_in!("userspace", smoke_brk_break_is_address_space_scoped_and_inherited);
}
