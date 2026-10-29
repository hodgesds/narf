//! Revocable CPU mapping lifetime: published PRIME and GEM views move between
//! VRAM and GTT through the real address-space revocation transaction, while
//! unpublished views, address leases, unknown (fork) aliases, allocation and
//! commit failures all refuse without touching data, PTEs or accounting.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::{
    AddressSpace, AddressSpaceError, MemoryType, PhysAddr, Region, RegionPerms, VirtAddr,
};

const CARD: u32 = 0xfee6;

/// Address spaces the substitute VM hook revokes, plus a one-shot request
/// to add a fence after preflight but before the freeze.
static SPACES: IrqSafeSpinLock<Vec<Arc<AddressSpace>>> = IrqSafeSpinLock::new(Vec::new());
static LATE_FENCE: IrqSafeSpinLock<Option<Arc<GemObject>>> = IrqSafeSpinLock::new(None);

#[derive(Debug)]
struct Signalled;
impl narf_filesystem::DrmFence for Signalled {
    fn is_signalled(&self) -> bool {
        true
    }
    fn wait(&self, _: u64) -> bool {
        true
    }
}

/// The userspace hook with a test-owned process list.
fn hook(
    old: &[u64],
    new: &[u64],
    aliases: fn(u64) -> usize,
    commit: &mut dyn FnMut() -> Result<(), FsError>,
) -> Result<(), FsError> {
    let late = LATE_FENCE.lock().take();
    if let Some(object) = late {
        object.dma_buf().resv.add_fence(
            Arc::new(Signalled),
            narf_filesystem::dma_buf::DmaResvUsage::Bookkeep,
        );
    }
    let spaces = SPACES.lock().clone();
    let old: Vec<_> = old.iter().copied().map(PhysAddr::new).collect();
    let new: Vec<_> = new.iter().copied().map(PhysAddr::new).collect();
    let mut failure = None;
    // SAFETY: the driver retains both generations through this call; the
    // test retains every root in `spaces`.
    let result = unsafe {
        narf_memory::address_space::with_revoked_shared_frames(&spaces, &old, &new, aliases, || {
            commit().map_err(|error| {
                failure = Some(error);
                AddressSpaceError::NotImplemented
            })
        })
    };
    match (failure, result) {
        (Some(error), _) => Err(error),
        (None, Ok(())) => Ok(()),
        (None, Err(_)) => Err(FsError::Busy),
    }
}

fn create(state: &GemState, size: u64, domains: u64) -> u32 {
    let mut b = [0u64; 4];
    b[0] = size;
    b[2] = domains;
    super::super::create(state, b.as_mut_ptr() as usize).unwrap();
    b[0] as u32
}

fn map(
    space: &AddressSpace,
    va: u64,
    frames: &[u64],
    write: bool,
    memory_type: MemoryType,
) -> bool {
    // Match the device-backed sys_mmap path: SHARED alone uses VMA-owned
    // lifetime, while GEM mappings require the external alias registry.
    let mut perms = (RegionPerms::READ
        | RegionPerms::SHARED
        | RegionPerms::EXTERNAL_REFS
        | RegionPerms::LOCK_EXEMPT)
        .with_memory_type(memory_type);
    if write {
        perms = perms | RegionPerms::WRITE;
    }
    let len = frames.len() as u64 * 4096;
    let phys: Vec<_> = frames.iter().copied().map(PhysAddr::new).collect();
    space
        .map_region(Region {
            base: VirtAddr::new(va),
            len,
            perms,
            phys: phys.into(),
        })
        .is_ok()
        // SAFETY: test-owned root that is never activated, so device frames
        // installed here are never dereferenced.
        && unsafe { space.materialize_range(VirtAddr::new(va), len) }.is_ok()
}

/// Compare the actual leaf selector after a move or rollback. The request
/// survives in the VMA; System RAM must still match its WB direct map.
fn cache_matches(space: &AddressSpace, va: u64, phys: u64) -> bool {
    let Some(region) = space.lookup(VirtAddr::new(va)) else {
        return false;
    };
    if region.perms.memory_type() != MemoryType::WriteCombining {
        return false;
    }
    let effective = narf_memory::memtype::effective_memory_type(region.perms, PhysAddr::new(phys));
    // SAFETY: this test owns the live root and never activates it.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            use narf_memory::x86_64::paging::{flags_at, PtFlags};
            flags_at(space.root, VirtAddr::new(va)).is_some_and(|flags| {
                flags.bits() & PtFlags::CACHE_MASK_4K.bits()
                    == narf_memory::memtype::x86_leaf_bits_4k(effective).bits()
            })
        }
        #[cfg(target_arch = "aarch64")]
        {
            use narf_memory::aarch64::paging::{flags_at, PtFlags};
            flags_at(space.root, VirtAddr::new(va)).is_some_and(|flags| {
                flags.bits() & PtFlags::ATTR_MASK.bits()
                    == narf_memory::memtype::aarch64_leaf_bits(effective).bits()
                        & PtFlags::ATTR_MASK.bits()
            })
        }
    }
}

fn translated(space: &AddressSpace, va: u64) -> Option<(u64, bool)> {
    let va = VirtAddr::new(va);
    // SAFETY: test-owned live root, mutated only by this test's calls.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            use narf_memory::x86_64::paging::{flags_at, translate, PtFlags};
            let flags = flags_at(space.root, va)?;
            Some((
                translate(space.root, va)?.raw(),
                flags.contains(PtFlags::WRITABLE),
            ))
        }
        #[cfg(target_arch = "aarch64")]
        {
            use narf_memory::aarch64::paging::{flags_at, translate, PtFlags};
            let flags = flags_at(space.root, va)?;
            Some((
                translate(space.root, va)?.raw(),
                flags.bits() & PtFlags::AP_RO_EL0.bits() != PtFlags::AP_RO_EL0.bits(),
            ))
        }
    }
}

fn relocate(object: &Arc<GemObject>, to_vram: bool) -> Result<(), FsError> {
    narf_scheduler::block_on_spin(async {
        let gate = lock_placement(CARD).await;
        crate::amdgpu_vm::relocate(&gate, object, to_vram).await
    })
}

fn rdna2_cpu_mappings_revoke_rebind_and_refuse_pins() -> TestResult {
    struct Restore(Option<narf_filesystem::mmap_relocation::RelocationHook>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SPACES.lock().clear();
            LATE_FENCE.lock().take();
            narf_filesystem::mmap_relocation::replace(self.0.take());
            crate::amdgpu_cs::retire(CARD, &|_| true);
            unregister_vram_heap(CARD);
        }
    }
    // SAFETY: test-owned roots, never activated.
    let (parent, child) =
        match unsafe { (AddressSpace::new_for_user(), AddressSpace::new_for_user()) } {
            (Ok(parent), Ok(child)) => (Arc::new(parent), Arc::new(child)),
            _ => return TestResult::Skip("test address-space allocation failed"),
        };
    let mut memory = alloc::vec![0u8; 5 * 4096];
    let map_bar = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xb100_0000),
        virt: memory.as_mut_ptr() as u64,
        len: memory.len() as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: this test exclusively owns memory until the registered heap and
    // every object have been dropped; no hardware accesses these mappings.
    let pool =
        unsafe { crate::amdgpu_vram::Pool::from_owned_range(map_bar, 0x8_0000_0000) }.unwrap();
    register_vram_heap(
        CARD,
        VramHeap {
            pool: pool.clone(),
            fb_base: 0x8_0000_0000,
            fb_offset: 0x9_0000_0000,
            unmapped: None,
        },
    );
    let _restore = Restore(narf_filesystem::mmap_relocation::replace(Some(hook)));
    SPACES.lock().push(parent.clone());
    let before = gtt_used();
    let state = GemState::for_card(CARD);
    let handle = create(&state, 3 * 4096, u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM));
    let object = state.object(handle).unwrap();
    object.store_u64(16, 0x1111_2222);
    object.store_u64(8192 + 8, 0x3333_4444);
    let prime = crate::drm_devfs_bridge::amdgpu_dma_buf_file(object.clone()).unwrap();
    let (va_rw, va_ro) = (0x0000_4100_0000_0000u64, 0x0000_4101_0000_0000u64);

    let result = (|| -> Result<(), &'static str> {
        if object.system() {
            return Err("setup: BO did not start in VRAM");
        }
        // Whole-object GEM view, writable; snapshot is not yet published.
        let whole = state
            .mmap_backing(u64::from(handle) << 12, 3 * 4096)
            .map_err(|_| "GEM mmap backing failed")?;
        if whole.memory_type != MemoryType::WriteCombining
            || !map(&parent, va_rw, &whole.frames, true, whole.memory_type)
        {
            return Err("whole view registration failed");
        }
        if relocate(&object, false) != Err(FsError::Busy) || object.system() {
            return Err("unpublished CPU view did not pin its frame snapshot");
        }
        prime.mmap_published(whole.lifetime.as_ref());
        // Independent read-only PRIME view of page 1 only.
        let view = prime
            .mmap_backing(4096, 4096)
            .map_err(|_| "PRIME partial view failed")?;
        if view.memory_type != MemoryType::WriteCombining
            || !map(&parent, va_ro, &view.frames, false, view.memory_type)
        {
            return Err("partial view registration failed");
        }
        prime.mmap_published(view.lifetime.as_ref());
        // A GPU VM alias rebinds together with the CPU aliases.
        let vm = crate::amdgpu_vm::VmState::for_card(CARD);
        let mut va = [0u8; 40];
        va[..4].copy_from_slice(&handle.to_le_bytes());
        va[8..12].copy_from_slice(&uapi::AMDGPU_VA_OP_MAP.to_le_bytes());
        va[12..16].copy_from_slice(&uapi::AMDGPU_VM_PAGE_READABLE.to_le_bytes());
        va[16..24].copy_from_slice(&0x2_0000_0000u64.to_le_bytes());
        va[32..40].copy_from_slice(&(3 * 4096u64).to_le_bytes());
        let nr = crate::drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_GEM_VA;
        crate::amdgpu_vm::dispatch(nr, va.as_ptr() as usize, &vm, &state)
            .map_err(|_| "GPU VA mapping failed")?;
        let check = |label: &'static str| -> Result<(), &'static str> {
            let frames = object.frames(0, 3 * 4096).map_err(|_| label)?;
            let views_follow = (0..3).all(|page| {
                translated(&parent, va_rw + page * 4096) == Some((frames[page as usize], true))
                    && cache_matches(&parent, va_rw + page * 4096, frames[page as usize])
            }) && translated(&parent, va_ro) == Some((frames[1], false))
                && cache_matches(&parent, va_ro, frames[1]);
            let gpu_follows = vm.leaf_entry(0x2_0000_2000).is_some_and(|pte| {
                Some(pte & crate::amdgpu_vm::GMC_HOLE_MASK & !4095) == object.gpu_at(8192)
            });
            if !views_follow
                || !gpu_follows
                || object.load_u64(16) != Some(0x1111_2222)
                || object.load_u64(8192 + 8) != Some(0x3333_4444)
                || !Arc::ptr_eq(&state.object(handle).unwrap(), &object)
                || frames.iter().any(|&frame| alias_count(frame) == 0)
            {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "rdna2 mapping check: {label}: cpu={views_follow} gpu={gpu_follows} data={:?}/{:?} frames={frames:x?}",
                    object.load_u64(16),
                    object.load_u64(8192 + 8),
                );
                for (page, &phys) in frames.iter().enumerate() {
                    let va = va_rw + page as u64 * 4096;
                    let _ = writeln!(
                        narf_console::Writer,
                        "rdna2 page {page}: translation={:x?} cache={} aliases={}",
                        translated(&parent, va),
                        cache_matches(&parent, va, phys),
                        alias_count(phys),
                    );
                }
                return Err(label);
            }
            Ok(())
        };
        check("setup: published views did not map the VRAM generation")?;
        let vram_frames = object.frames(0, 3 * 4096).unwrap();

        // Published VRAM -> GTT -> VRAM, both directions through the freeze.
        relocate(&object, false).map_err(|_| "published views refused GTT move")?;
        if !object.system() || gtt_used() != before + 3 * 4096 {
            return Err("GTT move did not change placement or accounting");
        }
        check("GTT move did not rebind CPU and GPU aliases with data")?;
        if vram_frames.iter().any(|&frame| alias_count(frame) != 0)
            || pool.available() != pool.size()
        {
            return Err("GTT move retained the old VRAM generation");
        }
        relocate(&object, true).map_err(|_| "published views refused VRAM move")?;
        if object.system() || gtt_used() != before {
            return Err("VRAM move did not change placement or accounting");
        }
        check("VRAM move did not rebind CPU and GPU aliases with data")?;

        // Address leases are hard pins and refuse before any copy.
        let lease = object.placement();
        let refused = relocate(&object, false);
        drop(lease);
        let legacy = state
            .mapping_object(u64::from(handle) << 12, 4096)
            .ok_or("legacy mapping failed")?;
        let refused_legacy = relocate(&object, false);
        drop(legacy);
        if refused != Err(FsError::Busy) || refused_legacy != Err(FsError::Busy) || object.system()
        {
            return Err("address lease did not pin the CPU-mapped generation");
        }
        check("refused lease move changed CPU aliases")?;

        // A fence after preflight fails the frozen commit; old frames return.
        *LATE_FENCE.lock() = Some(object.clone());
        if relocate(&object, false) != Err(FsError::Busy) || object.system() {
            return Err("fence added before freeze did not fail the commit");
        }
        check("failed commit did not restore the original aliases")?;
        if gtt_used() != before {
            return Err("failed commit leaked its GTT destination");
        }

        // Destination allocation failure keeps the old generation intact.
        relocate(&object, false).map_err(|_| "second GTT move failed")?;
        let squatter = create(&state, 3 * 4096, u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM));
        if state.object(squatter).is_none_or(|o| o.system()) {
            return Err("setup: VRAM squatter did not land in VRAM");
        }
        if relocate(&object, true) != Err(FsError::NoSpace) || !object.system() {
            return Err("VRAM exhaustion did not refuse the move");
        }
        check("allocation failure changed CPU aliases")?;
        state.remove(squatter);

        // Fork gap: a child holds metadata aliases but is not yet visible.
        let gtt_frames = object.frames(0, 3 * 4096).unwrap();
        let region = Region {
            base: VirtAddr::new(va_rw),
            len: 3 * 4096,
            perms: parent.lookup(VirtAddr::new(va_rw)).unwrap().perms,
            phys: gtt_frames
                .iter()
                .copied()
                .map(PhysAddr::new)
                .collect::<Vec<_>>()
                .into(),
        };
        child
            .map_region(region)
            .map_err(|_| "child metadata alias failed")?;
        if relocate(&object, true) != Err(FsError::Busy) || !object.system() {
            return Err("unknown child alias did not refuse migration");
        }
        // The original CPU tokens and parent aliases go away; the child's
        // metadata alone must keep the backing (and its frames) registered.
        parent
            .unmap_region(VirtAddr::new(va_rw))
            .map_err(|_| "parent unmap failed")?;
        parent
            .unmap_region(VirtAddr::new(va_ro))
            .map_err(|_| "parent partial unmap failed")?;
        drop(whole);
        drop(view);
        if !live_backing(&object) || gtt_frames.iter().any(|&f| alias_count(f) != 1) {
            return Err("fork metadata alias did not retain the CPU backing");
        }
        if relocate(&object, true) != Err(FsError::Busy) || !object.system() {
            return Err("child-only backing moved without its alias census");
        }
        // Publication makes the child known; it then moves with the BO.
        SPACES.lock().push(child.clone());
        relocate(&object, true).map_err(|_| "published child refused migration")?;
        let moved = object.frames(0, 3 * 4096).unwrap();
        let child_follows = child.lookup(VirtAddr::new(va_rw)).is_some_and(|r| {
            (0..3).all(|page| r.phys.get(page).map(|p| p.raw()) == Some(moved[page]))
        });
        if object.system() || !child_follows || moved.iter().any(|&f| alias_count(f) != 1) {
            return Err("child metadata did not follow the moved BO");
        }
        // Fork's lazy metadata also retains WC when its leaves are built.
        // SAFETY: test-owned live root, never activated or dereferenced.
        unsafe { child.materialize_range(VirtAddr::new(va_rw), 3 * 4096) }
            .map_err(|_| "child materialization failed")?;
        if !(0..3).all(|page| cache_matches(&child, va_rw + page * 4096, moved[page as usize])) {
            return Err("child VRAM leaves lost the WC request");
        }
        // Final child unmap releases the backing.
        child
            .unmap_region(VirtAddr::new(va_rw))
            .map_err(|_| "child unmap failed")?;
        if live_backing(&object) || moved.iter().any(|&f| alias_count(f) != 0) {
            return Err("last metadata alias did not retire the CPU backing");
        }
        // With no CPU backing the BO moves through the unmapped path again.
        crate::amdgpu_vm::dispatch(
            nr,
            {
                va[8..12].copy_from_slice(&uapi::AMDGPU_VA_OP_UNMAP.to_le_bytes());
                va.as_ptr() as usize
            },
            &vm,
            &state,
        )
        .map_err(|_| "GPU VA unmap failed")?;
        relocate(&object, false).map_err(|_| "unmapped BO refused GTT move")?;
        if !object.system() || object.load_u64(16) != Some(0x1111_2222) {
            return Err("unmapped move after retirement lost data");
        }
        drop(vm);
        Ok(())
    })();
    drop(prime);
    drop(object);
    drop(state);
    SPACES.lock().clear();
    drop(parent);
    drop(child);
    let leaked = gtt_used() != before || pool.available() != pool.size();
    match result {
        Err(reason) => TestResult::Fail(reason),
        Ok(()) if leaked => TestResult::Fail("CPU mapping moves leaked GTT or VRAM"),
        Ok(()) => TestResult::Pass,
    }
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_cpu_mappings_revoke_rebind_and_refuse_pins
);
