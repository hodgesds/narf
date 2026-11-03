//! Production ring allocation on a synthetic non-coherent device.
//!
//! No non-coherent silicon or QEMU machine is available, so the device's
//! reserved pool is modelled over owned buddy frames (write-back mapped):
//! this proves every device-visible ring structure comes from the device's
//! pool, and that a non-coherent device without one is refused. It does not
//! prove non-cacheable behaviour on hardware.
use super::super::*;
use alloc::sync::Arc;
use narf_io::{CoherentPool, DmaCoherence, DmaDevice};
use narf_kernel_test::{kernel_test_in, TestResult};

fn model_pool(order: u8) -> Option<(Arc<CoherentPool>, narf_memory::PhysFrame)> {
    let frame = narf_memory::alloc_pages_on(0, order).ok()?;
    let phys = frame.start_address();
    let bytes = (narf_memory::PAGE_SIZE as usize) << order;
    // SAFETY: the frames stay allocated until after the pool and every
    // buffer from it are dropped; the direct map covers them.
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

fn within(buffer: &narf_io::DmaBuffer, pool: &CoherentPool) -> bool {
    let start = pool.phys().raw();
    let end = start + (pool.pages() as u64) * narf_memory::PAGE_SIZE;
    let addr = buffer.dma_addr().raw();
    buffer.is_pool_backed() && addr >= start && addr + buffer.len() as u64 <= end
}

fn mt7921_rings_use_noncoherent_device_pool() -> TestResult {
    let Some((pool, frame)) = model_pool(7) else {
        return TestResult::Skip("frame allocator unavailable");
    };
    let total = pool.pages();
    let dev = DmaDevice::new(DmaCoherence::NonCoherent, Some(pool.clone()), None);
    let result = (|| {
        let mut rings = Vec::new();
        for (base, rx) in [
            (TX_WM, false),
            (TX_FWDL, false),
            (TX_DATA, false),
            (RX_PRE, true),
            (RX_POST, true),
            (RX_DATA, true),
        ] {
            let ring = Ring::allocate_for(&dev, base, rx).map_err(|_| "ring allocation")?;
            if !within(&ring.descriptors, &pool) || !ring.buffers.iter().all(|b| within(b, &pool)) {
                return Err("ring memory outside the device pool");
            }
            for slot in 0..DEPTH {
                let armed = if rx {
                    ring.word(slot, 0) == ring.buffers[slot].dma_addr().raw() as u32
                        && ring.word(slot, 1) == (MAX_FRAME as u32) << 16
                } else {
                    ring.word(slot, 1) == DONE
                };
                if !armed {
                    return Err("descriptor not armed through the pool mapping");
                }
            }
            rings.push(ring);
        }
        drop(rings);
        if pool.free_pages() != total {
            return Err("ring teardown leaked pool pages");
        }
        // Linux would remap RAM here; NARF has no RAM alias, so refuse.
        let bare = DmaDevice::new(DmaCoherence::NonCoherent, None, None);
        if !matches!(
            Ring::allocate_for(&bare, TX_WM, false),
            Err(Error::Allocation)
        ) {
            return Err("non-coherent device without a pool got rings");
        }
        let coherent = Ring::allocate(TX_WM, false).map_err(|_| "coherent ring")?;
        if coherent.descriptors.is_pool_backed()
            || coherent.buffers.iter().any(|b| b.is_pool_backed())
        {
            return Err("coherent ring left the buddy path");
        }
        Ok(())
    })();
    drop(dev);
    drop(pool);
    narf_memory::free_pages(frame, 7);
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/mt7921/ncdma",
    mt7921_rings_use_noncoherent_device_pool
);

/// A pool too small for one ring fails without leaking a partial ring.
fn mt7921_ring_pool_exhaustion_is_clean() -> TestResult {
    let Some((pool, frame)) = model_pool(2) else {
        return TestResult::Skip("frame allocator unavailable");
    };
    let dev = DmaDevice::new(DmaCoherence::NonCoherent, Some(pool.clone()), None);
    let failed = matches!(
        Ring::allocate_for(&dev, RX_DATA, true),
        Err(Error::Allocation)
    );
    let clean = pool.free_pages() == pool.pages();
    drop(dev);
    drop(pool);
    narf_memory::free_pages(frame, 2);
    match (failed, clean) {
        (true, true) => TestResult::Pass,
        (false, _) => TestResult::Fail("ring larger than the pool allocated"),
        (_, false) => TestResult::Fail("failed ring allocation leaked pool pages"),
    }
}
kernel_test_in!(
    "drivers/wireless/mt7921/ncdma",
    mt7921_ring_pool_exhaustion_is_clean
);
