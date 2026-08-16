#[allow(unused_imports)]
use super::*;

const MREMAP_MAYMOVE: u32 = 1;
const MREMAP_FIXED: u32 = 2;
const MREMAP_DONTUNMAP: u32 = 4;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOMEM: i64 = 12;

fn round_len(requested: u64) -> Result<u64, i64> {
    if requested == 0 {
        return Err(EINVAL);
    }
    requested
        .checked_add(0xFFF)
        .map(|value| value & !0xFFF)
        .filter(|value| *value != 0)
        .ok_or(ENOMEM)
}

/// Core Linux-compatible `mremap` operation for a complete private VMA.
///
/// Supported operations are no-op, real tail shrink, in-place lazy grow,
/// MAYMOVE relocation when growth collides, and FIXED relocation after
/// replacing the target window. `MREMAP_DONTUNMAP` remains explicitly
/// rejected: its old-range fault/userfaultfd contract cannot be approximated
/// by retaining an ordinary alias without violating private-map ownership.
fn mremap_core(
    as_ref: &AddressSpace,
    old_addr: u64,
    old_len_requested: u64,
    new_len_requested: u64,
    flags: u32,
    new_addr: u64,
) -> Result<u64, i64> {
    if old_addr & 0xFFF != 0
        || flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
        || flags & MREMAP_FIXED != 0 && flags & MREMAP_MAYMOVE == 0
        || flags & MREMAP_DONTUNMAP != 0
    {
        return Err(EINVAL);
    }
    let old_len = round_len(old_len_requested)?;
    let new_len = round_len(new_len_requested)?;
    let old_end = old_addr.checked_add(old_len).ok_or(EFAULT)?;
    if old_end > AddressSpace::USER_HALF_END {
        return Err(EFAULT);
    }

    // NARF's region table is the VMA authority. Require the complete region
    // instead of merging fragments with potentially different permissions or
    // backing owners. Ordinary anonymous mmap and allocator mremap calls have
    // exactly this shape.
    let source = as_ref.lookup(VirtAddr::new(old_addr)).ok_or(EFAULT)?;
    if source.base.as_u64() != old_addr
        || source.len != old_len
        || source.perms.contains(RegionPerms::SHARED)
    {
        return Err(EFAULT);
    }

    if flags & MREMAP_FIXED != 0 {
        let new_end = new_addr.checked_add(new_len).ok_or(EINVAL)?;
        if new_addr & 0xFFF != 0
            || new_addr < AddressSpace::USER_FIXED_FLOOR
            || new_end > AddressSpace::USER_HALF_END
            || old_addr < new_end && new_addr < old_end
        {
            return Err(EINVAL);
        }
        // Linux MREMAP_FIXED replaces an existing target mapping. Punching is
        // completed before the ownership-preserving move; the source is
        // disjoint and remains intact if validation above fails.
        as_ref
            .punch_fixed(VirtAddr::new(new_addr), new_len)
            .map_err(|_| ENOMEM)?;
        crate::mapped_file::punch_current(new_addr, new_len);
        // SAFETY: mremap_core holds an Arc-owned live address space; both
        // disjoint ranges were page/bounds validated above.
        unsafe {
            as_ref.relocate_region(
                VirtAddr::new(old_addr),
                old_len,
                VirtAddr::new(new_addr),
                new_len,
            )
        }
        .map_err(|_| ENOMEM)?;
        return Ok(new_addr);
    }

    if new_len == old_len {
        return Ok(old_addr);
    }
    if new_len < old_len {
        let tail = old_addr + new_len;
        as_ref
            .punch_fixed(VirtAddr::new(tail), old_len - new_len)
            .map_err(|_| EFAULT)?;
        crate::mapped_file::punch_current(tail, old_len - new_len);
        return Ok(old_addr);
    }
    if as_ref
        .grow_region(VirtAddr::new(old_addr), new_len)
        .is_ok()
    {
        return Ok(old_addr);
    }
    if flags & MREMAP_MAYMOVE == 0 {
        return Err(ENOMEM);
    }

    let destination = as_ref.reserve_mmap_va(new_len);
    if destination == 0 {
        return Err(ENOMEM);
    }
    // SAFETY: reserve_mmap_va returned a disjoint page-aligned user range and
    // source validation above established a complete private region.
    unsafe {
        as_ref.relocate_region(
            VirtAddr::new(old_addr),
            old_len,
            VirtAddr::new(destination),
            new_len,
        )
    }
    .map_err(|_| ENOMEM)?;
    Ok(destination)
}

/// `mremap(old_addr, old_len, new_len, flags, new_addr)` — resize or move a
/// complete private mapping while preserving its resident backing.
pub(crate) fn sys_mremap(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    match mremap_core(
        &as_ref,
        args.arg0,
        args.arg1,
        args.arg2,
        args.arg3 as u32,
        args.arg4,
    ) {
        Ok(address) => ctx.set_return(SyscallReturn::ok(address)),
        Err(errno) => ctx.set_return(SyscallReturn::ok((-errno) as u64)),
    }
}

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn lazy_region(base: u64, pages: u64) -> Region {
        Region {
            base: VirtAddr::new(base),
            len: pages * 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: (0..pages)
                .map(|index| PhysAddr::new(0x0200_0000 + index * 4096))
                .collect(),
        }
    }

    fn smoke_mremap_shrink_really_unmaps_tail() -> TestResult {
        const BASE: u64 = AddressSpace::MMAP_CURSOR_BASE;
        let aspace = AddressSpace::empty();
        if aspace.map_region(lazy_region(BASE, 4)).is_err() {
            return TestResult::Fail("initial region failed");
        }
        if mremap_core(&aspace, BASE, 4 * 4096, 2 * 4096, 0, 0) != Ok(BASE) {
            return TestResult::Fail("shrink failed");
        }
        let Some(region) = aspace.lookup(VirtAddr::new(BASE)) else {
            return TestResult::Fail("shrunk region disappeared");
        };
        if region.len != 2 * 4096
            || region.phys.len() != 2
            || aspace.lookup(VirtAddr::new(BASE + 2 * 4096)).is_some()
        {
            return TestResult::Fail("shrink reported success without removing its tail");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_mremap_shrink_really_unmaps_tail);

    fn smoke_mremap_maymove_preserves_backing_and_grows_lazily() -> TestResult {
        const BASE: u64 = AddressSpace::MMAP_CURSOR_BASE;
        let aspace = AddressSpace::empty();
        let source = lazy_region(BASE, 2);
        let expected = source.phys.clone();
        if aspace.map_region(source).is_err()
            || aspace.map_region(lazy_region(BASE + 2 * 4096, 2)).is_err()
        {
            return TestResult::Fail("could not create grow collision");
        }
        if mremap_core(&aspace, BASE, 2 * 4096, 4 * 4096, 0, 0) != Err(ENOMEM) {
            return TestResult::Fail("colliding grow without MAYMOVE did not fail");
        }
        let moved = match mremap_core(
            &aspace,
            BASE,
            2 * 4096,
            4 * 4096,
            MREMAP_MAYMOVE,
            0,
        ) {
            Ok(address) if address != BASE => address,
            _ => return TestResult::Fail("MAYMOVE did not relocate"),
        };
        let Some(region) = aspace.lookup(VirtAddr::new(moved)) else {
            return TestResult::Fail("moved region missing");
        };
        if aspace.lookup(VirtAddr::new(BASE)).is_some()
            || region.len != 4 * 4096
            || region.phys[..2] != expected
            || region.phys[2..].iter().any(|phys| phys.raw() != 0)
        {
            return TestResult::Fail("MAYMOVE lost backing or did not create a lazy tail");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mremap_maymove_preserves_backing_and_grows_lazily
    );

    fn smoke_mremap_fixed_replaces_target() -> TestResult {
        const SOURCE: u64 = AddressSpace::MMAP_CURSOR_BASE;
        const TARGET: u64 = AddressSpace::MMAP_CURSOR_BASE + 0x20_0000;
        let aspace = AddressSpace::empty();
        let source = lazy_region(SOURCE, 2);
        let expected = source.phys.clone();
        if aspace.map_region(source).is_err() || aspace.map_region(lazy_region(TARGET, 3)).is_err()
        {
            return TestResult::Fail("could not register source and target");
        }
        let result = mremap_core(
            &aspace,
            SOURCE,
            2 * 4096,
            3 * 4096,
            MREMAP_MAYMOVE | MREMAP_FIXED,
            TARGET,
        );
        let Some(region) = aspace.lookup(VirtAddr::new(TARGET)) else {
            return TestResult::Fail("fixed target missing");
        };
        if result != Ok(TARGET)
            || aspace.lookup(VirtAddr::new(SOURCE)).is_some()
            || region.len != 3 * 4096
            || region.phys[..2] != expected
            || region.phys[2].raw() != 0
        {
            return TestResult::Fail("MREMAP_FIXED did not replace target correctly");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_mremap_fixed_replaces_target);

    fn smoke_mremap_rejects_unsafe_flag_shapes() -> TestResult {
        const BASE: u64 = AddressSpace::MMAP_CURSOR_BASE;
        let aspace = AddressSpace::empty();
        if aspace.map_region(lazy_region(BASE, 2)).is_err() {
            return TestResult::Fail("initial region failed");
        }
        if mremap_core(&aspace, BASE, 8192, 8192, MREMAP_FIXED, BASE + 0x20_0000)
            != Err(EINVAL)
            || mremap_core(
                &aspace,
                BASE,
                8192,
                8192,
                MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
                0,
            ) != Err(EINVAL)
            || mremap_core(
                &aspace,
                BASE,
                8192,
                8192,
                MREMAP_MAYMOVE | MREMAP_FIXED,
                BASE + 4096,
            ) != Err(EINVAL)
        {
            return TestResult::Fail("unsafe mremap flag/address shape was accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("userspace", smoke_mremap_rejects_unsafe_flag_shapes);
}
