#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_brk(ctx: &mut dyn TrapContext) {
    let new_break = ctx.args().arg0;
    let task = current_task_id();

    // Snapshot the current break (initialising the slot on first call).
    let cur = match task_map_get(&BRK_TABLE, task) {
        Some(v) => v,
        None => {
            task_map_set(&BRK_TABLE, task, BRK_DEFAULT_BASE);
            BRK_DEFAULT_BASE
        }
    };

    // Query path: arg0 == 0 just returns the current break.
    if new_break == 0 {
        ctx.set_return(SyscallReturn::ok(cur));
        return;
    }

    // Ceiling: never let the heap climb past the arena top (which keeps it
    // below the interpreter bias and the anonymous mmap window). A request
    // above the ceiling fails per POSIX brk's contract — return the unchanged
    // break so glibc/musl fall back to mmap.
    if new_break > BRK_ARENA_TOP {
        ctx.set_return(SyscallReturn::ok(cur));
        return;
    }

    // Shrink path: walk the per-grow-call brk regions (each one
    // base ≥ BRK_DEFAULT_BASE) and unmap any whose base falls
    // entirely within [new_break_aligned, cur_aligned). Each
    // unmap_region call walks PTEs + free_frame's the underlying
    // physical pages so frames return to the allocator. A grow
    // region whose base sits BELOW new_break but extends past it
    // is left intact — partial unmapping would need a region-
    // split primitive; documented limitation, slight over-keep
    // bounded by the grow chunk size (one page on the smallest
    // grow, larger when the user calls brk(big_jump)).
    if new_break < cur {
        if let Some(as_ref) = current_address_space() {
            let new_aligned = (new_break + 0xFFF) & !0xFFFu64;
            let mut bases_to_unmap: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
            for r in as_ref.regions_snapshot().iter() {
                let rb = r.base.as_u64();
                // Brk-grow regions live in `[BRK_DEFAULT_BASE, cur)`
                // — bounded above by the OLD break. Without the
                // `rb < cur` upper bound, any region above
                // `BRK_DEFAULT_BASE` matches and gets unmapped,
                // which on a fresh process (where cur ==
                // BRK_DEFAULT_BASE) silently nukes the user stack
                // at 0x7FFF_FFFC_0000 the next time the caller
                // does `brk(small_value)`. ld-musl's
                // `__init_libc` does exactly that early in init.
                if rb >= BRK_DEFAULT_BASE && rb < cur && rb >= new_aligned {
                    bases_to_unmap.push(rb);
                }
            }
            for b in bases_to_unmap {
                let _ = as_ref.unmap_region(VirtAddr::new(b));
            }
        }
        task_map_set(&BRK_TABLE, task, new_break);
        ctx.set_return(SyscallReturn::ok(new_break));
        return;
    }

    // Grow path: allocate frames + install a SINGLE Region for
    // the whole new range (was one Region per page pre-fix —
    // bookkeeping bloated linearly with heap size and the shrink
    // path had to iterate page-by-page). On failure roll the
    // break back to `cur` (POSIX brk failure contract).
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::ok(cur));
            return;
        }
    };
    let cur_aligned = (cur + 0xFFF) & !0xFFFu64;
    let new_aligned = (new_break + 0xFFF) & !0xFFFu64;
    let pages = (new_aligned - cur_aligned) >> 12;
    if pages == 0 {
        // Within-page grow — just record the new break, no PTE work.
        task_map_set(&BRK_TABLE, task, new_break);
        ctx.set_return(SyscallReturn::ok(new_break));
        return;
    }
    let mut phys_list: alloc::vec::Vec<narf_memory::PhysAddr> =
        alloc::vec::Vec::with_capacity(pages as usize);
    for _ in 0..pages {
        let phys = match narf_memory::alloc_frame() {
            Ok(f) => f.start_address(),
            Err(_) => {
                ctx.set_return(SyscallReturn::ok(cur));
                return;
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
        ctx.set_return(SyscallReturn::ok(cur));
        return;
    }
    // SAFETY: `as_ref` is the calling task's AddressSpace (valid root); the brk
    // region was just registered via `map_region`, so materialize installs only its PTEs.
    // SAFETY: Valid memory or trusted environment
    if unsafe { as_ref.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::ok(cur));
        return;
    }

    task_map_set(&BRK_TABLE, task, new_break);
    ctx.set_return(SyscallReturn::ok(new_break));
}
