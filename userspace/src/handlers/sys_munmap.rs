#[allow(unused_imports)]
use super::*;

/// Remove the page-aligned range requested by `munmap(2)` while preserving
/// any prefix and suffix of an overlapping VMA.
///
/// Linux requires an aligned address and a non-zero length, but rounds the
/// length up to a page.  `AddressSpace::punch_fixed` already provides the
/// required split + PTE teardown + frame-release transaction used by
/// `MAP_FIXED`; sharing that primitive keeps the two overlapping-unmap paths
/// identical.
fn munmap_core(as_ref: &AddressSpace, base: u64, requested_len: u64) -> Result<u64, ()> {
    if base & 0xFFF != 0 || requested_len == 0 {
        return Err(());
    }
    let len = requested_len
        .checked_add(0xFFF)
        .map(|value| value & !0xFFF)
        .filter(|&value| value != 0)
        .ok_or(())?;
    let end = base.checked_add(len).ok_or(())?;
    if end > AddressSpace::USER_HALF_END {
        return Err(());
    }
    as_ref
        .punch_fixed(VirtAddr::new(base), len)
        .map_err(|_| ())?;
    Ok(len)
}

/// Preserve the v1 native-ring `OpCode::Munmap` contract. Unlike Linux
/// syscall 11, that operation was published as base-only and removes the
/// complete VMA beginning at the supplied address. Keep it out of
/// `sys_munmap` so a raw Linux call with `len == 0` still returns `EINVAL`.
pub(crate) fn munmap_native_v1(as_ref: &AddressSpace, base: u64) -> Result<(), ()> {
    let base = VirtAddr::new(base);
    as_ref
        .unmap_region(base)
        .map(|_| ())
        .or_else(|_| as_ref.unmap_huge_region(base))
        .map_err(|_| ())?;
    crate::mapped_file::unmap_current(base.as_u64());
    Ok(())
}

pub(crate) fn sys_munmap(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    match munmap_core(&as_ref, args.arg0, args.arg1) {
        Ok(len) => {
            // Ordered after the unmap, and that order is load-bearing: this
            // call may drop the mapping's last `Arc<dyn FileOps>`, which for
            // a demand-paged file (a BPF arena) can free its backing frames.
            // Releasing it before the address-space punch would expose those
            // freed frames through live PTEs.  The range form mirrors the VMA
            // split so surviving prefix/suffix owners retain their reference.
            crate::mapped_file::punch_current(args.arg0, len);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Err(()) => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // EINVAL
    }
}

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// glibc obtains an oversized PROT_NONE mapping for a secondary malloc
    /// arena, trims the unaligned prefix and suffix with two `munmap` calls,
    /// then enables the arena header with `mprotect`.  The old syscall ignored
    /// `len`: the prefix call removed the whole VMA, making both later calls
    /// fail and causing an unbounded 128 MiB allocation/retry loop in Qt.
    fn smoke_munmap_preserves_glibc_arena_middle() -> TestResult {
        const BASE: u64 = 0x0000_4080_1000_0000;
        const PAGES: u64 = 80;
        const PREFIX_PAGES: u64 = 8;
        const MIDDLE_PAGES: u64 = 40;

        let aspace = Arc::new(AddressSpace::empty());
        if aspace
            .map_region(Region {
                base: VirtAddr::new(BASE),
                len: PAGES * 4096,
                perms: RegionPerms(0),
                phys: alloc::vec![PhysAddr::new(0); PAGES as usize],
            })
            .is_err()
        {
            return TestResult::Fail("could not register oversized arena VMA");
        }

        if munmap_core(&aspace, BASE, PREFIX_PAGES * 4096).is_err() {
            return TestResult::Fail("prefix munmap failed");
        }
        let middle_base = BASE + PREFIX_PAGES * 4096;
        let suffix_base = middle_base + MIDDLE_PAGES * 4096;
        if munmap_core(&aspace, suffix_base, (PAGES - PREFIX_PAGES - MIDDLE_PAGES) * 4096)
            .is_err()
        {
            return TestResult::Fail("suffix munmap failed");
        }

        let regions = aspace.regions_snapshot();
        if regions.len() != 1
            || regions[0].base != VirtAddr::new(middle_base)
            || regions[0].len != MIDDLE_PAGES * 4096
        {
            return TestResult::Fail("arena trims did not preserve exactly the middle VMA");
        }

        // This is the operation that immediately follows the two trims in
        // glibc.  It must find the surviving PROT_NONE middle and split it.
        if mprotect_core(
            &aspace,
            VirtAddr::new(middle_base),
            0x21_000,
            0b011,
        )
        .is_err()
        {
            return TestResult::Fail("mprotect could not enable the retained arena header");
        }
        let enabled = aspace.lookup(VirtAddr::new(middle_base));
        if !enabled.is_some_and(|region| {
            region.len == 0x21_000
                && region.perms.contains(RegionPerms::READ | RegionPerms::WRITE)
        }) {
            return TestResult::Fail("arena header permissions were not applied");
        }

        // Linux rounds a non-page-multiple length upward.
        if munmap_core(&aspace, middle_base, 0x1_001).is_err()
            || aspace.lookup(VirtAddr::new(middle_base + 0x1000)).is_some()
            || aspace.lookup(VirtAddr::new(middle_base + 0x2000)).is_none()
        {
            return TestResult::Fail("munmap length was not rounded up to whole pages");
        }
        if munmap_core(&aspace, AddressSpace::USER_HALF_END, 4096).is_ok() {
            return TestResult::Fail("munmap accepted a range beyond the user address space");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_munmap_preserves_glibc_arena_middle);
}
