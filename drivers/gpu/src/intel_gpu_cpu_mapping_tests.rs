use super::*;
use narf_filesystem::DirOps;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::{AddressSpace, MemoryType, PhysAddr, Region, RegionPerms, VirtAddr};

fn create(gem: &GemState, pages: u64) -> (u32, Arc<GemObject>) {
    let handle = gem.create(pages * PAGE, |_, _| Ok(())).unwrap();
    (handle, gem.object(handle).unwrap())
}
fn tracked(object: &Arc<GemObject>) -> Option<Arc<CpuBacking>> {
    BACKINGS
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .find(|b| Arc::ptr_eq(&b.object, object) && !b.retired.load(Ordering::Acquire))
}
fn counts(object: &Arc<GemObject>) -> Option<(usize, usize)> {
    tracked(object).map(|b| {
        (
            b.owners.load(Ordering::Acquire),
            b.pending.load(Ordering::Acquire),
        )
    })
}
fn aliases(phys: u64) -> usize {
    FRAMES.lock().get(&phys).map_or(0, |(_, count)| *count)
}
fn map(space: &AddressSpace, va: u64, frames: &[u64], memory_type: MemoryType) {
    let perms = (RegionPerms::READ
        | RegionPerms::WRITE
        | RegionPerms::SHARED
        | RegionPerms::EXTERNAL_REFS
        | RegionPerms::LOCK_EXEMPT)
        .with_memory_type(memory_type);
    space
        .map_region(Region {
            base: VirtAddr::new(va),
            len: frames.len() as u64 * PAGE,
            perms,
            phys: frames
                .iter()
                .copied()
                .map(PhysAddr::new)
                .collect::<Vec<_>>()
                .into(),
        })
        .unwrap();
    // SAFETY: the fixture owns this live root and never activates it.
    unsafe { space.materialize_range(VirtAddr::new(va), frames.len() as u64 * PAGE) }.unwrap();
}

fn smoke_intel_cpu_mapping_pending_publication_and_retired_generation() -> TestResult {
    let gem = GemState::new();
    let (handle, object) = create(&gem, 2);
    let map0 = gem
        .mmap_backing(gem.mmap_offset(handle).unwrap(), PAGE as usize)
        .unwrap();
    assert_eq!(counts(&object), Some((1, 1)));
    assert_eq!(map0.memory_type, MemoryType::WriteBack);
    let old = Arc::downgrade(&tracked(&object).unwrap());
    // Failed/unpublished mmap returns its pending count and all rows.
    drop(map0);
    assert!(counts(&object).is_none());
    assert!(old.upgrade().is_none());
    let map1 = object.backing(PAGE, PAGE as usize).unwrap();
    assert_eq!(counts(&object), Some((1, 1)));
    published(map1.lifetime.as_ref());
    published(map1.lifetime.as_ref());
    assert_eq!(counts(&object), Some((1, 0)));
    let all = object.cpu_frames(0, (2 * PAGE) as usize).unwrap();
    assert!(all.iter().all(|phys| FRAMES.lock().contains_key(phys)));
    assert_eq!(map1.frames, [all[1]]);
    drop(map1);
    assert!(counts(&object).is_none());
    assert!(all.iter().all(|phys| !FRAMES.lock().contains_key(phys)));
    assert!(object.backing(1, 4096).is_err());
    assert!(object.backing(0, 0).is_err());
    assert!(counts(&object).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gem",
    smoke_intel_cpu_mapping_pending_publication_and_retired_generation
);

fn smoke_intel_cpu_mapping_actual_primary_render_and_prime_publication_hooks() -> TestResult {
    let index = crate::drm_registry::register_drm_card(Arc::new(
        crate::drm_devfs_bridge::IntelGpuCard::new(
            alloc::string::String::from("intel-alias-census"),
            0x8086,
            0x56a0,
            0,
            0,
        ),
    ));
    let primary = crate::drm_devfs_bridge::DriDir
        .lookup(&alloc::format!("card{index}"))
        .unwrap();
    let render = crate::drm_devfs_bridge::DriDir
        .lookup(&alloc::format!("renderD{}", index + 128))
        .unwrap();
    let gem = GemState::new();
    let (_, object) = create(&gem, 1);
    let prime = crate::drm_devfs_bridge::intel_dma_buf_file(index, object.clone());
    let a = object.backing(0, 4096).unwrap();
    let b = object.backing(0, 4096).unwrap();
    let c = prime.mmap_backing(0, 4096).unwrap();
    assert_eq!(counts(&object), Some((3, 3)));
    primary.mmap_published(a.lifetime.as_ref());
    render.mmap_published(b.lifetime.as_ref());
    prime.mmap_published(c.lifetime.as_ref());
    assert_eq!(counts(&object), Some((3, 0)));
    // Vendor forwarding must ignore a foreign token rather than consume a
    // pending Intel count. Repeated publication also stays idempotent.
    let foreign: Arc<dyn narf_filesystem::MmapLifetime> = Arc::new(17u64);
    primary.mmap_published(Some(&foreign));
    render.mmap_published(a.lifetime.as_ref());
    assert_eq!(counts(&object), Some((3, 0)));
    drop((a, b, c));
    assert!(counts(&object).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gem",
    smoke_intel_cpu_mapping_actual_primary_render_and_prime_publication_hooks
);

fn smoke_intel_cpu_mapping_real_fork_metadata_outlives_tokens_handles_and_prime() -> TestResult {
    // SAFETY: paging is live; the fixture exclusively owns never-activated roots.
    let parent = match unsafe { AddressSpace::new_for_user() } {
        Ok(space) => space,
        Err(_) => return TestResult::Skip("address-space allocation"),
    };
    let gem = GemState::new();
    let (handle, object) = create(&gem, 2);
    let prime = crate::drm_devfs_bridge::intel_dma_buf_file(0xfee9, object.clone());
    let whole = gem
        .mmap_backing(gem.mmap_offset(handle).unwrap(), (2 * PAGE) as usize)
        .unwrap();
    let partial = prime.mmap_backing(PAGE, PAGE as usize).unwrap();
    let frames = whole.frames.clone();
    const WHOLE: u64 = 0x4100_0000_0000;
    const PARTIAL: u64 = 0x4101_0000_0000;
    map(&parent, WHOLE, &whole.frames, whole.memory_type);
    map(&parent, PARTIAL, &partial.frames, partial.memory_type);
    assert_eq!((aliases(frames[0]), aliases(frames[1])), (1, 2));
    prime.mmap_published(whole.lifetime.as_ref());
    prime.mmap_published(partial.lifetime.as_ref());
    assert_eq!(counts(&object), Some((2, 0)));
    parent
        .mprotect_range(VirtAddr::new(WHOLE + PAGE), PAGE, RegionPerms(0))
        .unwrap();
    assert_eq!((aliases(frames[0]), aliases(frames[1])), (1, 2));
    // The actual fork path retains EXTERNAL_REFS before the child has any
    // scheduler-visible process/file owner. PROT_NONE metadata counts too.
    // SAFETY: the fixture exclusively owns this never-activated parent root.
    let child = unsafe { parent.clone_for_fork() }.unwrap();
    assert_eq!((aliases(frames[0]), aliases(frames[1])), (2, 4));
    let weak = Arc::downgrade(&object);
    gem.close(handle).unwrap();
    drop(prime);
    drop(whole);
    drop(partial);
    assert_eq!(counts(&object), Some((0, 0)));
    drop(object);
    drop(parent);
    assert!(
        weak.upgrade().is_some(),
        "child metadata must retain the BO"
    );
    assert_eq!((aliases(frames[0]), aliases(frames[1])), (1, 2));
    // Partial unmap/drop is the actual metadata-release path, not a counter
    // seam. Remaining lazy/PROT_NONE child aliases keep the BO until teardown.
    child.unmap_region(VirtAddr::new(PARTIAL)).unwrap();
    assert!(weak.upgrade().is_some());
    assert_eq!((aliases(frames[0]), aliases(frames[1])), (1, 1));
    drop(child);
    assert!(weak.upgrade().is_none());
    assert!(frames.iter().all(|phys| !FRAMES.lock().contains_key(phys)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gem",
    smoke_intel_cpu_mapping_real_fork_metadata_outlives_tokens_handles_and_prime
);

fn smoke_intel_cpu_mapping_cpu_bar_census_retains_local_allocation() -> TestResult {
    use crate::intel_gpu_vram::{Vram, VramLayout};
    let frame = match narf_memory::frame::alloc_pages_on(0, 4) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Skip("64 KiB fixture allocation"),
    };
    let bar = narf_bus::bar::MmioRegion {
        phys: frame.start_address(),
        virt: frame.start_address().kernel_mut_ptr::<u8>() as u64,
        len: 65536,
        kind: narf_bus::bar::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: private fixture RAM stands in for one exclusively owned BMG BAR.
    let pool = unsafe {
        Vram::new(
            bar,
            VramLayout {
                tile_size: 65536,
                tile_offset: 0,
                usable: 65536,
            },
        )
    }
    .unwrap();
    let gem = GemState::new();
    let pending = gem.prepare_vram(65536, None, &pool).unwrap();
    let object = pending.object();
    assert!(
        object.backing(0, 4096).is_err(),
        "private initialization stays private"
    );
    assert!(counts(&object).is_none());
    let mut clear = object.begin_cpu_vram_clear().unwrap();
    // SAFETY: test-owned RAM is not hardware and outlives clear and every BO.
    let fence = unsafe { clear.clear_next() }.unwrap();
    drop(clear);
    let handle = gem.publish_vram(pending, &fence, |_, _| Ok(())).unwrap();
    let mapping = object.backing(0, 4096).unwrap();
    assert_eq!(mapping.memory_type, MemoryType::WriteCombining);
    assert_eq!(mapping.frames, [bar.phys.raw()]);
    assert_ne!(mapping.frames[0], object.pages().next().unwrap());
    assert!(narf_filesystem::mmap_relocation::retain_alias(
        mapping.frames[0]
    ));
    published(mapping.lifetime.as_ref());
    let weak = Arc::downgrade(&object);
    gem.close(handle).unwrap();
    drop(mapping);
    drop(object);
    assert_eq!(pool.used(), 65536);
    assert!(weak.upgrade().is_some());
    assert!(narf_filesystem::mmap_relocation::release_alias(
        bar.phys.raw()
    ));
    assert_eq!(pool.used(), 0);
    assert!(weak.upgrade().is_none());
    drop(pool);
    narf_memory::frame::free_pages(frame, 4);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gem",
    smoke_intel_cpu_mapping_cpu_bar_census_retains_local_allocation
);

#[cfg(feature = "amdgpu")]
fn smoke_intel_and_amd_cpu_alias_providers_coexist_without_cross_release() -> TestResult {
    let amd = crate::amdgpu_gem::GemState::for_card(0xfee9);
    let gate = crate::amdgpu_gem::try_placement(0xfee9).unwrap();
    let (handle, _) = amd.create_kernel_system(PAGE, &gate).unwrap();
    drop(gate);
    let a = amd
        .mmap_backing(u64::from(handle) << 12, PAGE as usize)
        .unwrap();
    let intel = GemState::new();
    let (_, object) = create(&intel, 1);
    let b = object.backing(0, PAGE as usize).unwrap();
    assert_ne!(a.frames[0], b.frames[0]);
    assert!(narf_filesystem::mmap_relocation::retain_alias(a.frames[0]));
    assert!(narf_filesystem::mmap_relocation::retain_alias(b.frames[0]));
    assert_eq!(aliases(a.frames[0]), 0);
    assert_eq!(aliases(b.frames[0]), 1);
    assert!(narf_filesystem::mmap_relocation::release_alias(a.frames[0]));
    assert_eq!(aliases(b.frames[0]), 1);
    assert!(narf_filesystem::mmap_relocation::release_alias(b.frames[0]));
    assert_eq!(aliases(b.frames[0]), 0);
    drop(a);
    drop(b);
    assert!(counts(&object).is_none());
    TestResult::Pass
}
#[cfg(feature = "amdgpu")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_gem",
    smoke_intel_and_amd_cpu_alias_providers_coexist_without_cross_release
);
