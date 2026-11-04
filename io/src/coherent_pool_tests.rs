//! Reserved coherent pool and device-coherence smokes (`io/ncdma`).
//!
//! QEMU `virt` and every x86_64 machine are coherent, so the non-coherent
//! path is driven with synthetic devices: allocator pools over owned buddy
//! frames (mapped write-back by the direct map — a bookkeeping model, not a
//! non-cacheable mapping) and, on aarch64, a reserved pool over a synthetic
//! non-RAM range whose leaf attribute is read back but never dereferenced.

extern crate alloc;

use alloc::sync::Arc;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;
use narf_memory::{alloc_pages_on, free_pages, PAGE_SIZE};

use crate::{
    alloc_coherent_for, CoherentPool, DmaBuffer, DmaCoherence, DmaDevice, DmaDirection, IoError,
};

const PAGE: usize = PAGE_SIZE as usize;

/// An 8-page pool over freshly allocated buddy frames, pre-filled with a
/// non-zero pattern so zero-fill is observable. Returns the frame order to
/// free after every pool reference is gone.
fn model_pool(order: u8) -> Option<(Arc<CoherentPool>, narf_memory::PhysFrame)> {
    let frame = alloc_pages_on(0, order).ok()?;
    let phys = frame.start_address();
    let bytes = PAGE << order;
    // SAFETY: freshly allocated frames, reached through the direct map.
    unsafe { core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0xa5, bytes) };
    // SAFETY: the frames stay allocated until the caller frees them after
    // dropping the pool and all of its buffers.
    let pool = unsafe {
        CoherentPool::from_mapping(
            phys.raw(),
            phys.kernel_mut_ptr::<u8>() as usize,
            bytes as u64,
        )
    }
    .ok()?;
    Some((pool, frame))
}

fn offset_of(buf: &DmaBuffer, pool: &CoherentPool) -> u64 {
    buf.dma_addr().raw() - pool.phys().raw()
}

fn zeroed(buf: &DmaBuffer) -> bool {
    buf.as_slice().iter().all(|b| *b == 0)
}

/// `bitmap_find_free_region` placement: naturally aligned runs, first fit,
/// exhaustion, mask refusal without leaking, free and reuse.
fn smoke_io_coherent_pool_alignment_exhaustion_reuse() -> TestResult {
    let Some((pool, frame)) = model_pool(3) else {
        return TestResult::Skip("frame allocator unavailable");
    };
    let dev = DmaDevice::new(DmaCoherence::NonCoherent, Some(pool.clone()), None);
    let alloc = |len| alloc_coherent_for(&dev, len, DomainId::DRIVER_0, u64::MAX);
    let result = (|| {
        let a = alloc(1).map_err(|_| "one page")?;
        let b = alloc(PAGE + 1).map_err(|_| "two pages")?;
        let c = alloc(PAGE).map_err(|_| "hole page")?;
        let d = alloc(4 * PAGE).map_err(|_| "four pages")?;
        if [
            offset_of(&a, &pool),
            offset_of(&b, &pool),
            offset_of(&c, &pool),
        ] != [0, 2 * PAGE as u64, PAGE as u64]
            || offset_of(&d, &pool) != 4 * PAGE as u64
        {
            return Err("runs not first-fit naturally aligned");
        }
        if b.len() != 2 * PAGE || d.len() != 4 * PAGE || !b.is_pool_backed() {
            return Err("pool buffer length / backing");
        }
        if b.cpu_ptr::<u8>() as usize != pool.virt() + 2 * PAGE
            || b.cpu_ptr_at::<u8>(5) as usize != pool.virt() + 2 * PAGE + 5
        {
            return Err("CPU pointer not inside the pool mapping");
        }
        if ![&a, &b, &c, &d].iter().all(|x| zeroed(x)) {
            return Err("pool buffer not zero-filled");
        }
        if !matches!(alloc(1), Err(IoError::NoMemory)) || pool.free_pages() != 0 {
            return Err("exhausted pool still allocated");
        }
        drop(b);
        if pool.free_pages() != 2 {
            return Err("free did not return the run");
        }
        let b2 = alloc(2 * PAGE).map_err(|_| "reuse")?;
        if offset_of(&b2, &pool) != 2 * PAGE as u64 {
            return Err("freed run not reused");
        }
        drop((a, b2, c, d));
        // A mask the pool's high pages exceed: the run is refused and
        // released, never handed out above the mask.
        let mask = pool.phys().raw() + 4 * PAGE as u64 - 1;
        let low = alloc_coherent_for(&dev, 4 * PAGE, DomainId::DRIVER_0, mask)
            .map_err(|_| "masked low run")?;
        if !matches!(
            alloc_coherent_for(&dev, 4 * PAGE, DomainId::DRIVER_0, mask),
            Err(IoError::NoMemory)
        ) || pool.free_pages() != 4
        {
            return Err("run above the DMA mask handed out or leaked");
        }
        drop(low);
        if pool.free_pages() != 8 || !matches!(alloc(16 * PAGE), Err(IoError::NoMemory)) {
            return Err("oversized request or final accounting");
        }
        Ok(())
    })();
    drop(dev);
    let only = Arc::strong_count(&pool) == 1;
    drop(pool);
    free_pages(frame, 3);
    match result {
        Ok(()) if only => TestResult::Pass,
        Ok(()) => TestResult::Fail("pool reference leaked"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "io/ncdma",
    smoke_io_coherent_pool_alignment_exhaustion_reuse
);

/// Linux `dma_alloc_attrs` selection: device pool first, default pool only
/// for a non-coherent device, coherent devices keep the buddy path and a
/// non-coherent device without a pool fails closed.
fn smoke_io_dma_device_pool_selection() -> TestResult {
    let (Some((own, own_frame)), Some((default, default_frame))) = (model_pool(1), model_pool(1))
    else {
        return TestResult::Skip("frame allocator unavailable");
    };
    let in_pool = |b: &DmaBuffer, p: &Arc<CoherentPool>| {
        b.is_pool_backed() && b.dma_addr().raw() >= p.phys().raw()
    };
    let result = (|| {
        let alloc = |dev: &DmaDevice| alloc_coherent_for(dev, 64, DomainId::DRIVER_0, u64::MAX);
        let coherent = alloc(&DmaDevice::coherent()).map_err(|_| "coherent alloc")?;
        if coherent.is_pool_backed()
            || coherent.cpu_ptr::<u8>() != coherent.phys_addr().kernel_ptr::<u8>()
            || !zeroed(&coherent)
        {
            return Err("coherent device left the direct-map buddy path");
        }
        let with_default = DmaDevice::new(DmaCoherence::Coherent, None, Some(default.clone()));
        if with_default.pool().is_some() || alloc(&with_default).map_err(|_| "x")?.is_pool_backed()
        {
            return Err("coherent device took the global default pool");
        }
        let fallback = DmaDevice::new(DmaCoherence::NonCoherent, None, Some(default.clone()));
        if !in_pool(&alloc(&fallback).map_err(|_| "default")?, &default) {
            return Err("non-coherent device skipped the default pool");
        }
        for coherence in [DmaCoherence::Coherent, DmaCoherence::NonCoherent] {
            let dev = DmaDevice::new(coherence, Some(own.clone()), Some(default.clone()));
            if !in_pool(&alloc(&dev).map_err(|_| "own")?, &own) {
                return Err("device memory-region pool did not win");
            }
        }
        let bare = DmaDevice::new(DmaCoherence::NonCoherent, None, None);
        if !matches!(alloc(&bare), Err(IoError::NoCoherentPool)) {
            return Err("non-coherent device without a pool got memory");
        }
        Ok(())
    })();
    drop((own, default));
    free_pages(own_frame, 1);
    free_pages(default_frame, 1);
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!("io/ncdma", smoke_io_dma_device_pool_selection);

/// `CoherentPool::reserved` refuses empty / unaligned ranges and never makes
/// a write-combining alias of System RAM.
fn smoke_io_reserved_pool_refuses_ram_and_bad_ranges() -> TestResult {
    let Ok(frame) = alloc_pages_on(0, 0) else {
        return TestResult::Skip("frame allocator unavailable");
    };
    let ram = frame.start_address().raw();
    // SAFETY: every call is refused before any mapping is made.
    let refused = unsafe {
        [
            CoherentPool::reserved(ram, PAGE as u64),
            CoherentPool::reserved(ram, 0),
            CoherentPool::reserved(ram + 1, PAGE as u64),
            CoherentPool::reserved(ram, PAGE as u64 + 1),
            CoherentPool::reserved(u64::MAX & !(PAGE as u64 - 1), PAGE as u64 * 2),
        ]
    }
    .into_iter()
    .all(|r| matches!(r, Err(IoError::PoolRejected)));
    free_pages(frame, 0);
    if refused {
        TestResult::Pass
    } else {
        TestResult::Fail("RAM or malformed range accepted as a reserved pool")
    }
}
kernel_test_in!(
    "io/ncdma",
    smoke_io_reserved_pool_refuses_ram_and_bad_ranges
);

/// Directional streaming maintenance keeps CPU data and clamps ranges.
fn smoke_io_dma_directional_sync_keeps_data() -> TestResult {
    let Ok(buf) = crate::alloc_coherent(2 * PAGE, DomainId::DRIVER_0) else {
        return TestResult::Skip("frame allocator unavailable");
    };
    for i in 0..2 * PAGE {
        // SAFETY: the buffer is exclusively ours.
        unsafe { buf.cpu_mut_ptr_at::<u8>(i as u64).write_volatile(i as u8) };
    }
    for dir in [
        DmaDirection::ToDevice,
        DmaDirection::FromDevice,
        DmaDirection::Bidirectional,
    ] {
        buf.sync_for_device(3, 70, dir);
        buf.sync_for_device(PAGE, 1 << 20, dir);
        // Invalidation of cache lines the CPU wrote but never cleaned is
        // only lossless because sync_for_device cleaned them first.
        buf.sync_for_cpu(3, 70, dir);
        buf.sync_for_cpu(PAGE - 1, 2, dir);
        buf.sync_for_cpu(PAGE, 1 << 20, dir);
        buf.sync_for_cpu(4 * PAGE, 8, dir);
    }
    // SAFETY: as above.
    let intact =
        (0..2 * PAGE).all(|i| unsafe { buf.cpu_ptr_at::<u8>(i as u64).read_volatile() } == i as u8);
    drop(buf);
    if intact {
        TestResult::Pass
    } else {
        TestResult::Fail("directional maintenance changed CPU data")
    }
}
kernel_test_in!("io/ncdma", smoke_io_dma_directional_sync_keeps_data);

/// A reserved pool over a non-RAM range is mapped Normal-NC (Linux
/// `memremap(MEMREMAP_WC)` = arm64 `MT_NORMAL_NC`), shared on repeat and
/// exclusive against overlap. The synthetic range is never dereferenced.
#[cfg(target_arch = "aarch64")]
fn smoke_io_reserved_pool_maps_normal_nc() -> TestResult {
    use narf_memory::aarch64::paging::{leaf_flags_at, read_ttbr1_el1, PtFlags};
    use narf_memory::{PhysAddr, VirtAddr};
    // Inside QEMU virt's RAM window but far above any configured `-m`.
    const BASE: u64 = 0x3f_0000_0000;
    const SIZE: u64 = 2 * PAGE_SIZE;
    if (0..2).any(|i| narf_memory::frame::is_system_ram(PhysAddr::new(BASE + i * PAGE_SIZE))) {
        return TestResult::Skip("synthetic pool range is System RAM here");
    }
    // SAFETY: an unpopulated, unclaimed physical range; the pool is never
    // allocated from, so nothing reads or writes it.
    let Ok(pool) = (unsafe { CoherentPool::reserved(BASE, SIZE) }) else {
        return TestResult::Fail("reserved pool over non-RAM refused");
    };
    // SAFETY: as above; the same range and an overlapping range.
    let (again, overlap) = unsafe {
        (
            CoherentPool::reserved(BASE, SIZE),
            CoherentPool::reserved(BASE + PAGE_SIZE, SIZE),
        )
    };
    if !again.is_ok_and(|p| Arc::ptr_eq(&p, &pool)) || overlap.unwrap_err() != IoError::PoolRejected
    {
        return TestResult::Fail("pool not shared or overlap accepted");
    }
    // SAFETY: TTBR1 is the live kernel root; the walk only reads tables.
    let root = unsafe { read_ttbr1_el1() };
    let attrs: alloc::vec::Vec<Option<u64>> = (0..2)
        .map(|i| {
            // SAFETY: as above.
            unsafe { leaf_flags_at(root, VirtAddr::new(pool.virt() as u64 + i * PAGE_SIZE)) }
                .map(|(flags, _)| flags.bits() & PtFlags::ATTR_MASK.bits())
        })
        .collect();
    if attrs
        .iter()
        .any(|a| *a != Some(PtFlags::ATTR_NORMAL_NC.bits()))
    {
        return TestResult::Fail("reserved pool leaf is not Normal-NC");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("io/ncdma", smoke_io_reserved_pool_maps_normal_nc);
