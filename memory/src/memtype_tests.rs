//! Memory-type smokes for user leaves (`crate::memtype`).
//!
//! * the default (write-back) encoding is bit-identical to the encoder that
//!   predates memory types, for every permission combination and frame kind;
//! * every memory type encodes as Linux's `pgprot_*` does, for 4 KiB,
//!   2 MiB and 1 GiB leaves, and never touches PKS key / MTE tag selectors;
//! * a device range mapped write-combining into a user address space gets a
//!   write-combining leaf that survives `mprotect`;
//! * a write-combining request on System RAM is refused (write-back leaf,
//!   refusal counted) — the alias rule.

#![cfg(all(
    feature = "kernel-test",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use crate::address_space::{__user_huge_leaf_flags_for_test, __user_leaf_flags_for_test};
use crate::memtype::{effective_memory_type, ram_alias_refusals, region_may_request, MemoryType};
use crate::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};
use narf_kernel_test::{kernel_test_in, TestResult};

// Test VAs live in the low 512 GiB (x86_64 PML4[0]), which a user root keeps
// private and empty. PML4[1] beyond its first GiB carries the kernel's 1 GiB
// high-MMIO identity leaves, so a large leaf there would collide.
const PAGE: u64 = 0x1000;
const GIB: u64 = 1 << 30;

/// A physical address that is certainly not System RAM: 1 GiB past the end
/// of every boot RAM range (and at least 4 GiB), 1 GiB aligned so 2 MiB and
/// 1 GiB leaves can use it too. Never dereferenced — the tests only build
/// and read descriptors for it, in roots that are never activated.
fn device_phys() -> Option<PhysAddr> {
    let end = crate::frame::managed_phys_end().max(4 * GIB);
    let phys = end.div_ceil(GIB) * GIB + GIB;
    let phys = PhysAddr::new(phys);
    (!crate::frame::is_system_ram(phys)
        && !crate::frame::is_system_ram(PhysAddr::new(phys.raw() + GIB - PAGE)))
    .then_some(phys)
}

fn ram_frame() -> Option<crate::frame::PhysFrame> {
    crate::alloc_frame().ok()
}

/// A special (device) mapping's permissions, as `sys_mmap` builds them.
fn device_perms(base: RegionPerms) -> RegionPerms {
    base | RegionPerms::SHARED | RegionPerms::LOCK_EXEMPT
}

/// Every permission combination the leaf encoder can see.
fn perm_combinations() -> alloc::vec::Vec<RegionPerms> {
    let bits = [
        RegionPerms::READ,
        RegionPerms::WRITE,
        RegionPerms::EXEC,
        RegionPerms::SHARED,
        RegionPerms::LOCK_EXEMPT,
        RegionPerms::COW,
        RegionPerms::GUARDED,
        RegionPerms::PINNABLE_RAM,
        RegionPerms::FILE_DEMAND,
        RegionPerms::LOCKED,
    ];
    let mut out = alloc::vec::Vec::with_capacity(1 << bits.len());
    for mask in 0u32..(1 << bits.len()) {
        let mut perms = RegionPerms(0);
        for (i, bit) in bits.iter().enumerate() {
            if mask & (1 << i) != 0 {
                perms = perms | *bit;
            }
        }
        out.push(perms);
    }
    out
}

// ── The encoder exactly as it was before memory types (verbatim) ───────

#[cfg(target_arch = "x86_64")]
fn legacy_user_leaf_flags(perms: RegionPerms, writable: bool) -> crate::x86_64::paging::PtFlags {
    use crate::x86_64::paging::PtFlags;
    let mut flags = PtFlags::USER;
    if writable {
        flags |= PtFlags::WRITABLE;
    }
    if !perms.contains(RegionPerms::EXEC) {
        flags |= PtFlags::NO_EXEC;
    }
    flags
}

#[cfg(target_arch = "aarch64")]
fn legacy_user_leaf_flags(perms: RegionPerms, writable: bool) -> crate::aarch64::paging::PtFlags {
    use crate::aarch64::paging::PtFlags;
    let mut flags = if writable {
        PtFlags::AP_RW_EL0
    } else {
        PtFlags::AP_RO_EL0
    };
    if !perms.contains(RegionPerms::EXEC) {
        flags = flags | PtFlags::UXN | PtFlags::PXN;
    } else if perms.contains(RegionPerms::GUARDED) {
        flags = flags | PtFlags::GUARDED;
    }
    flags
}

/// Default mappings encode bit-for-bit as before: every permission set,
/// both writable states, and every frame kind (none, RAM, device). An
/// explicit `with_memory_type(WriteBack)` is the same as not asking.
fn smoke_memtype_default_wb_bit_identical() -> TestResult {
    let Some(dev) = device_phys() else {
        return TestResult::Skip("no non-RAM physical address to test with");
    };
    let Some(frame) = ram_frame() else {
        return TestResult::Skip("frame allocator drained");
    };
    let frames = [PhysAddr::new(0), frame.start_address(), dev];
    let mut result = TestResult::Pass;
    'outer: for perms in perm_combinations() {
        for explicit in [perms, perms.with_memory_type(MemoryType::WriteBack)] {
            if explicit != perms {
                result = TestResult::Fail("with_memory_type(WriteBack) changed the perms");
                break 'outer;
            }
            for writable in [false, true] {
                let legacy = legacy_user_leaf_flags(perms, writable).bits();
                for &phys in &frames {
                    if __user_leaf_flags_for_test(explicit, writable, phys).bits() != legacy {
                        result = TestResult::Fail("default 4 KiB leaf encoding changed");
                        break 'outer;
                    }
                    if __user_huge_leaf_flags_for_test(explicit, writable, phys).bits() != legacy {
                        result = TestResult::Fail("default large leaf encoding changed");
                        break 'outer;
                    }
                }
            }
        }
    }
    crate::free_frame(frame);
    result
}
kernel_test_in!("memory/memtype", smoke_memtype_default_wb_bit_identical);

/// The memory-type field round-trips and stays out of the POSIX prot bits,
/// so `mprotect` (which replaces only `PROT_MASK`) cannot drop it.
fn smoke_memtype_region_perms_field() -> TestResult {
    let base = RegionPerms::READ | RegionPerms::WRITE | RegionPerms::SHARED;
    for mt in MemoryType::ALL {
        let p = base.with_memory_type(mt);
        if p.memory_type() != mt {
            return TestResult::Fail("memory type did not round-trip");
        }
        if p.prot_only() != base.prot_only() {
            return TestResult::Fail("memory type leaked into PROT_MASK");
        }
        if RegionPerms(p.0 & !RegionPerms::PROT_MASK.0).memory_type() != mt {
            return TestResult::Fail("memory type is not an internal (preserved) flag");
        }
    }
    if RegionPerms::default().memory_type() != MemoryType::WriteBack {
        return TestResult::Fail("default perms are not write-back");
    }
    TestResult::Pass
}
kernel_test_in!("memory/memtype", smoke_memtype_region_perms_field);

#[cfg(target_arch = "x86_64")]
fn expected_x86_4k(mt: MemoryType) -> Result<u64, &'static str> {
    use narf_arch::x86_64::pat::{cachemode2pte, enabled, programmed_value, NARF_PAT};
    let bits = cachemode2pte(mt.cache_mode());
    // Under the Linux full layout the bits are fixed; under any other layout
    // the table is authoritative.
    if enabled() && programmed_value() == NARF_PAT {
        let want = match mt {
            MemoryType::WriteBack => 0,
            MemoryType::WriteCombining => 1 << 3,
            MemoryType::Uncached => 1 << 4,
            MemoryType::WriteThrough => (1 << 7) | (1 << 4) | (1 << 3),
        };
        if bits != want {
            return Err("cache-mode table disagrees with the full PAT layout");
        }
    }
    Ok(bits)
}

/// Every memory type, 4 KiB and large: x86_64 PWT/PCD/PAT from the
/// programmed PAT (PAT at bit 7 in a 4 KiB PTE, bit 12 in a large leaf);
/// aarch64 AttrIndx 3 (Normal-NC) / 4 (Device-nGnRnE) with UXN|PXN. The
/// selectors never overlap the PKS key field, the MTE Tagged index, or the
/// permission bits.
fn smoke_memtype_leaf_encodings() -> TestResult {
    let Some(dev) = device_phys() else {
        return TestResult::Skip("no non-RAM physical address to test with");
    };
    let rw = device_perms(RegionPerms::READ | RegionPerms::WRITE);
    for mt in MemoryType::ALL {
        let perms = rw.with_memory_type(mt);
        if effective_memory_type(perms, dev) != mt {
            return TestResult::Fail("device frame did not get the requested type");
        }
        let small = __user_leaf_flags_for_test(perms, true, dev).bits();
        let large = __user_huge_leaf_flags_for_test(perms, true, dev).bits();
        let legacy = legacy_user_leaf_flags(perms, true).bits();
        #[cfg(target_arch = "x86_64")]
        {
            use crate::x86_64::paging::PtFlags;
            let want = match expected_x86_4k(mt) {
                Ok(bits) => bits,
                Err(e) => return TestResult::Fail(e),
            };
            if small != legacy | want {
                return TestResult::Fail("x86_64 4 KiB leaf has the wrong cache bits");
            }
            let want_large = narf_arch::x86_64::pat::protval_4k_2_large(want);
            if large != legacy | want_large {
                return TestResult::Fail("x86_64 large leaf has the wrong cache bits");
            }
            if large & PtFlags::PAT_4K.bits() != 0 {
                return TestResult::Fail("large leaf carries PAT at bit 7 (HUGE_PAGE)");
            }
            if (small | large) & PtFlags::PK_MASK.bits() != 0 {
                return TestResult::Fail("memory type touched the protection-key field");
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            use crate::aarch64::paging::PtFlags;
            let attr = small & PtFlags::ATTR_MASK.bits();
            let want = match mt {
                MemoryType::WriteBack => PtFlags::ATTR_NORMAL.bits(),
                MemoryType::WriteCombining => PtFlags::ATTR_NORMAL_NC.bits(),
                MemoryType::Uncached | MemoryType::WriteThrough => {
                    PtFlags::ATTR_DEVICE_NGNRNE.bits()
                }
            };
            if attr != want {
                return TestResult::Fail("aarch64 leaf has the wrong AttrIndx");
            }
            if attr == PtFlags::ATTR_TAGGED.bits() {
                return TestResult::Fail("a user memory type selected MTE Normal-Tagged");
            }
            let xn = PtFlags::UXN.bits() | PtFlags::PXN.bits();
            if mt != MemoryType::WriteBack && small & xn != xn {
                return TestResult::Fail("non-cacheable user leaf is executable (Linux forces XN)");
            }
            if large != small {
                return TestResult::Fail("aarch64 block attributes differ from page attributes");
            }
        }
        // W^X: a memory type never adds write permission, and never adds
        // execute permission.
        if small & !legacy & permission_bits() != 0 {
            return TestResult::Fail("memory type granted a permission bit");
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory/memtype", smoke_memtype_leaf_encodings);

#[cfg(target_arch = "x86_64")]
fn permission_bits() -> u64 {
    use crate::x86_64::paging::PtFlags;
    PtFlags::WRITABLE.bits() | PtFlags::USER.bits()
}

#[cfg(target_arch = "aarch64")]
fn permission_bits() -> u64 {
    use crate::aarch64::paging::PtFlags;
    // AP[2:1] (bits 7:6) and the Guarded Page bit.
    (0b11 << 6) | PtFlags::GUARDED.bits()
}

/// Only special mappings may carry a non-WB type; anything else — private
/// anonymous, COW, declared allocator RAM — encodes write-back even when the
/// field is set, without consulting the frame.
fn smoke_memtype_only_special_mappings_may_request() -> TestResult {
    let Some(dev) = device_phys() else {
        return TestResult::Skip("no non-RAM physical address to test with");
    };
    let rw = RegionPerms::READ | RegionPerms::WRITE;
    let refused = [
        rw,
        rw | RegionPerms::SHARED,
        rw | RegionPerms::LOCK_EXEMPT,
        device_perms(rw) | RegionPerms::COW,
        device_perms(rw) | RegionPerms::PINNABLE_RAM,
    ];
    for perms in refused {
        let perms = perms.with_memory_type(MemoryType::WriteCombining);
        if region_may_request(perms) {
            return TestResult::Fail("a non-special mapping may request a memory type");
        }
        if effective_memory_type(perms, dev) != MemoryType::WriteBack {
            return TestResult::Fail("a non-special mapping got a non-WB type");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/memtype",
    smoke_memtype_only_special_mappings_may_request
);

/// The alias rule: a write-combining (or any non-WB) request on a frame of
/// System RAM — which the kernel direct map holds write-back — yields a
/// write-back leaf and is counted, as Linux's `reserve_pfn_range` /
/// `track_pfn_insert` replace the request with the RAM page's memtype.
fn smoke_memtype_refuses_ram_alias() -> TestResult {
    let Some(frame) = ram_frame() else {
        return TestResult::Skip("frame allocator drained");
    };
    let ram = frame.start_address();
    let result = (|| {
        if !crate::frame::is_system_ram(ram) {
            return TestResult::Fail("an allocator frame is not System RAM");
        }
        let rw = device_perms(RegionPerms::READ | RegionPerms::WRITE);
        for mt in [
            MemoryType::WriteCombining,
            MemoryType::Uncached,
            MemoryType::WriteThrough,
        ] {
            let perms = rw.with_memory_type(mt);
            let before = ram_alias_refusals();
            if effective_memory_type(perms, ram) != MemoryType::WriteBack {
                return TestResult::Fail("RAM frame got a non-WB memory type");
            }
            if ram_alias_refusals() <= before {
                return TestResult::Fail("RAM alias refusal was not counted");
            }
            let legacy = legacy_user_leaf_flags(perms, true).bits();
            if __user_leaf_flags_for_test(perms, true, ram).bits() != legacy {
                return TestResult::Fail("RAM leaf carries cache-type bits");
            }
        }
        TestResult::Pass
    })();
    crate::free_frame(frame);
    result
}
kernel_test_in!("memory/memtype", smoke_memtype_refuses_ram_alias);

/// Boot-identified kernel and ACPI RAM is protected even when it was never
/// donated to the buddy allocator. Check the first and last page of every
/// authoritative boot RAM interval and the kernel image explicitly.
fn smoke_memtype_refuses_reserved_boot_ram_aliases() -> TestResult {
    let ranges = crate::frame::known_boot_ram_for_test();
    if ranges.is_empty() {
        return TestResult::Fail("boot RAM alias classification was not initialized");
    }
    let perms = device_perms(RegionPerms::READ | RegionPerms::WRITE);
    for (start, len) in ranges {
        for at in [start, (start + len - 1) & !(PAGE - 1)] {
            let phys = PhysAddr::new(at);
            if !crate::frame::is_system_ram(phys)
                || [MemoryType::WriteCombining, MemoryType::Uncached]
                    .iter()
                    .any(|&mt| {
                        effective_memory_type(perms.with_memory_type(mt), phys)
                            != MemoryType::WriteBack
                    })
            {
                return TestResult::Fail("reserved boot RAM accepted a conflicting cache alias");
            }
        }
    }
    let (start, end) = crate::kaslr::image_phys_bounds();
    if start < end && !crate::frame::is_system_ram(PhysAddr::new(start)) {
        return TestResult::Fail("kernel image was absent from the RAM cache policy");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/memtype",
    smoke_memtype_refuses_reserved_boot_ram_aliases
);

#[cfg(target_arch = "x86_64")]
fn leaf_at(root: PhysAddr, v: VirtAddr) -> Option<(u64, u64)> {
    // SAFETY: `root` is a live address-space root owned by the test.
    unsafe { crate::x86_64::paging::leaf_flags_at(root, v) }.map(|(f, size)| (f.bits(), size))
}

#[cfg(target_arch = "aarch64")]
fn leaf_at(root: PhysAddr, v: VirtAddr) -> Option<(u64, u64)> {
    // SAFETY: `root` is a live address-space root owned by the test.
    unsafe { crate::aarch64::paging::leaf_flags_at(root, v) }.map(|(f, size)| (f.bits(), size))
}

#[cfg(target_arch = "x86_64")]
fn cache_selector(bits: u64, size: u64) -> u64 {
    use crate::x86_64::paging::PtFlags;
    let mask = if size == PAGE {
        PtFlags::CACHE_MASK_4K
    } else {
        PtFlags::CACHE_MASK_LARGE
    };
    bits & mask.bits()
}

#[cfg(target_arch = "aarch64")]
fn cache_selector(bits: u64, _size: u64) -> u64 {
    bits & crate::aarch64::paging::PtFlags::ATTR_MASK.bits()
}

fn expected_selector(mt: MemoryType, size: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let bits = crate::memtype::x86_leaf_bits_4k(mt).bits();
        if size == PAGE {
            bits
        } else {
            narf_arch::x86_64::pat::protval_4k_2_large(bits)
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = size;
        crate::memtype::aarch64_leaf_bits(mt).bits()
            & crate::aarch64::paging::PtFlags::ATTR_MASK.bits()
    }
}

#[cfg(target_arch = "x86_64")]
fn leaf_writable(bits: u64) -> bool {
    bits & crate::x86_64::paging::PtFlags::WRITABLE.bits() != 0
}

#[cfg(target_arch = "aarch64")]
fn leaf_writable(bits: u64) -> bool {
    bits & (0b11 << 6) == crate::aarch64::paging::PtFlags::AP_RW_EL0.bits()
}

/// A device range mapped into a user address space through the real
/// `map_region` + `materialize` path gets leaves of the requested type —
/// write-combining first, then every other type; `mprotect` to read-only
/// keeps the type; a RAM frame in the same region is mapped write-back next
/// to them.
fn smoke_memtype_device_range_user_leaves() -> TestResult {
    let Some(dev) = device_phys() else {
        return TestResult::Skip("no non-RAM physical address to test with");
    };
    let Some(frame) = ram_frame() else {
        return TestResult::Skip("frame allocator drained");
    };
    // SAFETY: paging and the frame allocator are live in the kernel suite.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => {
            crate::free_frame(frame);
            return TestResult::Skip("new_for_user failed");
        }
    };
    let phys = alloc::vec![
        dev,
        PhysAddr::new(dev.raw() + PAGE),
        frame.start_address(),
        PhysAddr::new(dev.raw() + 3 * PAGE),
    ];
    let order = [
        MemoryType::WriteCombining,
        MemoryType::Uncached,
        MemoryType::WriteThrough,
        MemoryType::WriteBack,
    ];
    let mut result = TestResult::Pass;
    for (n, mt) in order.into_iter().enumerate() {
        let base = VirtAddr::new(0x0000_0000_4000_0000 + n as u64 * 0x10_0000);
        let perms = device_perms(RegionPerms::READ | RegionPerms::WRITE).with_memory_type(mt);
        if aspace
            .map_region(Region {
                base,
                len: 4 * PAGE,
                perms,
                phys: phys.clone().into(),
            })
            .is_err()
        {
            result = TestResult::Fail("map_region of the device range failed");
            break;
        }
        let outcome = (|| {
            // SAFETY: aspace owns a live root and the validated regions.
            if unsafe { aspace.materialize() }.is_err() {
                return Err("materialize failed");
            }
            let check = |want_writable: bool| -> Result<(), &'static str> {
                for (i, &p) in phys.iter().enumerate() {
                    let v = VirtAddr::new(base.as_u64() + i as u64 * PAGE);
                    let (bits, size) = leaf_at(aspace.root, v).ok_or("device page not mapped")?;
                    if size != PAGE {
                        return Err("device page mapped at the wrong size");
                    }
                    let want = if crate::frame::is_system_ram(p) {
                        MemoryType::WriteBack
                    } else {
                        mt
                    };
                    if cache_selector(bits, size) != expected_selector(want, size) {
                        return Err(if crate::frame::is_system_ram(p) {
                            "RAM page in a non-WB region is not write-back"
                        } else {
                            "device page does not carry the requested memory type"
                        });
                    }
                    if leaf_writable(bits) != want_writable {
                        return Err("leaf writability wrong");
                    }
                }
                Ok(())
            };
            check(true)?;
            // mprotect replaces PROT bits only; the memory type survives.
            aspace
                .mprotect_range(base, 4 * PAGE, RegionPerms::READ)
                .map_err(|_| "mprotect_range failed")?;
            check(false)
        })();
        let _ = aspace.unmap_region(base);
        if let Err(e) = outcome {
            result = TestResult::Fail(e);
            break;
        }
    }
    drop(aspace);
    crate::free_frame(frame);
    result
}
kernel_test_in!("memory/memtype", smoke_memtype_device_range_user_leaves);

/// 2 MiB and 1 GiB leaves carry every memory type, and a large leaf's PAT
/// bit (x86_64 bit 12) is never read back as an address bit: `translate`,
/// `leaf_flags_at` and `unmap_*` all return the true physical base.
fn smoke_memtype_large_leaves() -> TestResult {
    let Some(dev) = device_phys() else {
        return TestResult::Skip("no non-RAM physical address to test with");
    };
    // SAFETY: paging and the frame allocator are live in the kernel suite.
    let aspace = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Skip("new_for_user failed"),
    };
    let perms_base = device_perms(RegionPerms::READ | RegionPerms::WRITE);
    let va_2m = VirtAddr::new(0x0000_0000_8000_0000);
    let va_1g = VirtAddr::new(0x0000_0040_0000_0000);
    let mut result = TestResult::Pass;
    'types: for mt in MemoryType::ALL {
        let perms = perms_base.with_memory_type(mt);
        let flags = __user_huge_leaf_flags_for_test(perms, true, dev);
        for (va, size) in [(va_2m, 2u64 << 20), (va_1g, GIB)] {
            // SAFETY: a fresh root owned by this test; `dev` is never accessed
            // and the root is never activated, so only the descriptor matters.
            let mapped = unsafe {
                #[cfg(target_arch = "x86_64")]
                {
                    use crate::x86_64::paging::{map_1gb, map_2mb};
                    if size == GIB {
                        map_1gb(aspace.root, va, dev, flags)
                    } else {
                        map_2mb(aspace.root, va, dev, flags)
                    }
                }
                #[cfg(target_arch = "aarch64")]
                {
                    use crate::aarch64::paging::{map_1gb, map_2mb};
                    if size == GIB {
                        map_1gb(aspace.root, va, dev, flags)
                    } else {
                        map_2mb(aspace.root, va, dev, flags)
                    }
                }
            };
            if mapped.is_err() {
                result = TestResult::Fail("large leaf install failed");
                break 'types;
            }
            let leaf = leaf_at(aspace.root, va);
            // SAFETY: same live test-owned root.
            let translated = unsafe {
                #[cfg(target_arch = "x86_64")]
                {
                    crate::x86_64::paging::translate(aspace.root, VirtAddr::new(va.as_u64() + PAGE))
                }
                #[cfg(target_arch = "aarch64")]
                {
                    crate::aarch64::paging::translate(
                        aspace.root,
                        VirtAddr::new(va.as_u64() + PAGE),
                    )
                }
            };
            // SAFETY: same live test-owned root; removes the leaf just made.
            let unmapped = unsafe {
                #[cfg(target_arch = "x86_64")]
                {
                    use crate::x86_64::paging::{unmap_1gb, unmap_2mb};
                    if size == GIB {
                        unmap_1gb(aspace.root, va)
                    } else {
                        unmap_2mb(aspace.root, va)
                    }
                }
                #[cfg(target_arch = "aarch64")]
                {
                    use crate::aarch64::paging::{unmap_1gb, unmap_2mb};
                    if size == GIB {
                        unmap_1gb(aspace.root, va)
                    } else {
                        unmap_2mb(aspace.root, va)
                    }
                }
            };
            let Some((bits, leaf_size)) = leaf else {
                result = TestResult::Fail("large leaf not found");
                break 'types;
            };
            if leaf_size != size {
                result = TestResult::Fail("large leaf has the wrong size");
                break 'types;
            }
            if cache_selector(bits, size) != expected_selector(mt, size) {
                result = TestResult::Fail("large leaf has the wrong memory-type selector");
                break 'types;
            }
            if translated != Some(PhysAddr::new(dev.raw() + PAGE)) {
                result = TestResult::Fail("translate misread a large leaf's PAT bit as address");
                break 'types;
            }
            if unmapped.ok() != Some(dev) {
                result = TestResult::Fail("unmap returned the wrong large-leaf base");
                break 'types;
            }
        }
    }
    drop(aspace);
    result
}
kernel_test_in!("memory/memtype", smoke_memtype_large_leaves);

/// Firmware framebuffers may be backed by ordinary RAM. Verify the actual
/// installed kernel leaf, so the CPU alias agrees with the user WB clamp.
fn smoke_kernel_ioremap_ram_stays_writeback() -> TestResult {
    use crate::ioremap::{ioremap, iounmap, MmioAttrs};
    let Some(frame) = ram_frame() else {
        return TestResult::Skip("frame allocator drained");
    };
    let mut result = TestResult::Pass;
    for attrs in [MmioAttrs::WriteCombining, MmioAttrs::Device] {
        // SAFETY: the allocated RAM frame is exclusively owned until both
        // kernel aliases are retired below; no device DMA targets it.
        let mapping = unsafe { ioremap(frame.start_address().raw(), PAGE, attrs) };
        let Ok(mapping) = mapping else {
            result = TestResult::Fail("kernel RAM window mapping failed");
            break;
        };
        #[cfg(target_arch = "x86_64")]
        // SAFETY: the active root owns the freshly installed mapping; this
        // walk only reads its descriptors while the mapping stays retained.
        let leaf = unsafe {
            crate::x86_64::paging::leaf_flags_at(
                crate::x86_64::paging::read_cr3(),
                VirtAddr::new(mapping.va()),
            )
        };
        #[cfg(target_arch = "aarch64")]
        // SAFETY: the active TTBR1 owns this retained kernel mapping; the
        // walk only inspects its live descriptors before exclusive teardown.
        let leaf = unsafe {
            crate::aarch64::paging::leaf_flags_at(
                crate::aarch64::paging::read_ttbr1_el1(),
                VirtAddr::new(mapping.va()),
            )
        };
        let matches = leaf.is_some_and(|(flags, size)| {
            size == PAGE
                && cache_selector(flags.bits(), size)
                    == expected_selector(MemoryType::WriteBack, size)
        });
        // SAFETY: no access through this exclusive mapping is outstanding.
        unsafe { iounmap(mapping) };
        if !matches {
            result = TestResult::Fail("kernel RAM alias did not retain write-back");
            break;
        }
    }
    crate::free_frame(frame);
    result
}
kernel_test_in!("memory/memtype", smoke_kernel_ioremap_ram_stays_writeback);
