//! Device DMA coherence and reserved coherent pools (Linux
//! `kernel/dma/coherent.c`).
//!
//! Spec: `io/specification/spec.md` §3 ("Non-coherent devices").
//!
//! [`crate::alloc_coherent`] hands out write-back System RAM through the
//! kernel direct map. That is only coherent when the interconnect snoops CPU
//! caches (every x86_64 platform; QEMU `virt`). On an arm64 SoC whose DMA
//! master does not snoop, Linux's `dma_alloc_coherent` remaps the pages
//! Normal-NC (`DMA_DIRECT_REMAP`). NARF never creates a non-write-back alias
//! of System RAM (`memory/src/memtype.rs`, "Never on System RAM"), so a
//! non-coherent device instead allocates from a firmware-reserved pool:
//!
//! * a `/reserved-memory` child with `compatible = "shared-dma-pool"` and
//!   `no-map` — absent from the System RAM registry — is mapped once,
//!   write-combining (aarch64 Normal-NC, Linux `memremap(MEMREMAP_WC)` in
//!   `dma_init_coherent_memory`), and carved by a page bitmap exactly like
//!   `__dma_alloc_from_coherent` (`bitmap_find_free_region`: naturally
//!   aligned power-of-two page runs);
//! * a device's own `memory-region` pool wins (Linux
//!   `dma_alloc_from_dev_coherent`, checked before any other path);
//! * otherwise a non-coherent device uses the `linux,dma-default` pool
//!   (Linux `CONFIG_DMA_GLOBAL_POOL`, `dma_alloc_from_global_coherent`);
//! * a non-coherent device with neither fails closed with
//!   [`IoError::NoCoherentPool`] — never write-back memory;
//! * a coherent device without a pool takes the unchanged buddy path.
//!
//! Pools are permanent once created, like Linux's `rmem->priv`: the mapping
//! is shared through the ioremap cache, so it is never torn down.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{PhysAddr, PAGE_SIZE};

use crate::{alloc_with, Coherency, DmaBuffer, IoError};

/// Linux `dev_is_dma_coherent`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmaCoherence {
    /// The device snoops CPU caches (`dma-coherent`, every x86_64 device).
    Coherent,
    /// The device does not snoop CPU caches (`dma-noncoherent`, or the arm64
    /// `dma_default_coherent = false` when nothing marks the path coherent).
    NonCoherent,
}

/// Linux `struct dma_coherent_mem`: one reserved region, its kernel mapping
/// and a page-granular allocation bitmap.
pub struct CoherentPool {
    /// Physical (and device, no `dma-ranges` offset) base, page aligned.
    phys: u64,
    pages: usize,
    /// Kernel virtual base of the pool's mapping.
    virt: usize,
    /// One bit per page; set = allocated.
    bitmap: IrqSafeSpinLock<Vec<u64>>,
}

impl fmt::Debug for CoherentPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoherentPool")
            .field("phys", &format_args!("{:#x}", self.phys))
            .field("pages", &self.pages)
            .field("free_pages", &self.free_pages())
            .finish()
    }
}

/// Every reserved pool created so far, keyed by its physical range.
static POOLS: IrqSafeSpinLock<Vec<Arc<CoherentPool>>> = IrqSafeSpinLock::new(Vec::new());

fn check_range(phys: u64, size: u64) -> Result<usize, IoError> {
    let page = PAGE_SIZE;
    if size == 0 || phys % page != 0 || size % page != 0 || phys.checked_add(size).is_none() {
        return Err(IoError::PoolRejected);
    }
    usize::try_from(size / page).map_err(|_| IoError::PoolRejected)
}

impl CoherentPool {
    /// Linux `rmem_dma_device_init` → `dma_init_coherent_memory`: the pool
    /// over reserved `[phys, phys + size)`, mapped write-combining (aarch64
    /// Normal-NC) on first use and shared by every later caller.
    ///
    /// Refuses ([`IoError::PoolRejected`]) an empty or unaligned range, a
    /// range intersecting System RAM (`narf_memory::frame::is_system_ram`,
    /// the alias authority — a non-cacheable alias of RAM is never made), and
    /// a range overlapping a different pool.
    ///
    /// # Safety
    /// `[phys, phys + size)` must be firmware-reserved memory (a `no-map`
    /// `shared-dma-pool`) that nothing else maps or uses: the pool owns it
    /// for the life of the kernel.
    pub unsafe fn reserved(phys: u64, size: u64) -> Result<Arc<Self>, IoError> {
        let pages = check_range(phys, size)?;
        // Creation is serialized under the registry lock so two callers can
        // never build two bitmaps over one shared (cached) mapping.
        let mut pools = POOLS.lock();
        let end = phys + size;
        for pool in pools.iter() {
            let pool_end = pool.phys + (pool.pages as u64) * PAGE_SIZE;
            if pool.phys == phys && pool_end == end {
                return Ok(pool.clone());
            }
            if phys < pool_end && pool.phys < end {
                return Err(IoError::PoolRejected);
            }
        }
        if (0..pages as u64)
            .any(|i| narf_memory::frame::is_system_ram(PhysAddr::new(phys + i * PAGE_SIZE)))
        {
            return Err(IoError::PoolRejected);
        }
        use narf_memory::ioremap::{ioremap, MmioAttrs};
        // SAFETY: caller contract — reserved non-RAM memory owned by the
        // pool; checked above that no page is System RAM, so every leaf gets
        // the requested write-combining (Normal-NC) type.
        let mapping = unsafe { ioremap(phys, size, MmioAttrs::WriteCombining) }
            .map_err(|_| IoError::NotMapped)?;
        let virt = mapping.va() as usize;
        // Evict any line a cacheable alias (the arm64 boot linear window
        // covers the low RAM GiB wholesale) may have allocated, so no stale
        // or dirty line shadows the non-cacheable view. Linux performs the
        // same `arch_dma_prep_coherent` clean+invalidate before handing out
        // remapped memory. Maintenance by VA acts on the physical line
        // regardless of the VA's cacheability attribute.
        crate::cache_clean_invalidate(virt, virt + size as usize);
        let pool = Arc::new(Self {
            phys,
            pages,
            virt,
            bitmap: IrqSafeSpinLock::new(vec![0; pages.div_ceil(64)]),
        });
        pools.push(pool.clone());
        Ok(pool)
    }

    /// A pool over memory the caller has already mapped at `virt`. Used by
    /// tests to drive the allocator and device plumbing over owned frames;
    /// the pool is not registered, so it never aliases a reserved pool.
    ///
    /// # Safety
    /// `virt..virt + size` must map `phys..phys + size`, stay mapped and be
    /// owned by the pool for as long as the returned pool or any buffer
    /// allocated from it is alive. The mapping attribute is the caller's
    /// responsibility: a write-back mapping is coherent only for a snooping
    /// device.
    pub unsafe fn from_mapping(phys: u64, virt: usize, size: u64) -> Result<Arc<Self>, IoError> {
        let pages = check_range(phys, size)?;
        if virt % PAGE_SIZE as usize != 0 {
            return Err(IoError::PoolRejected);
        }
        Ok(Arc::new(Self {
            phys,
            pages,
            virt,
            bitmap: IrqSafeSpinLock::new(vec![0; pages.div_ceil(64)]),
        }))
    }

    /// Physical base of the pool.
    pub fn phys(&self) -> PhysAddr {
        PhysAddr::new(self.phys)
    }

    /// Kernel virtual base of the pool's mapping.
    pub fn virt(&self) -> usize {
        self.virt
    }

    /// Pool size in pages.
    pub fn pages(&self) -> usize {
        self.pages
    }

    /// Unallocated pages.
    pub fn free_pages(&self) -> usize {
        let used: u32 = self.bitmap.lock().iter().map(|w| w.count_ones()).sum();
        self.pages - used as usize
    }

    /// Linux `bitmap_find_free_region(bitmap, size, order)`: the first free,
    /// naturally aligned run of `1 << order` pages, marked allocated.
    fn take(&self, order: u8) -> Option<usize> {
        let run = 1usize << order;
        let mut bits = self.bitmap.lock();
        let mut page = 0;
        while page + run <= self.pages {
            if (page..page + run).all(|p| bits[p / 64] & (1 << (p % 64)) == 0) {
                for p in page..page + run {
                    bits[p / 64] |= 1 << (p % 64);
                }
                return Some(page);
            }
            page += run;
        }
        None
    }

    /// Linux `bitmap_release_region`.
    pub(crate) fn release(&self, page: usize, order: u8) {
        let mut bits = self.bitmap.lock();
        for p in page..(page + (1usize << order)).min(self.pages) {
            bits[p / 64] &= !(1 << (p % 64));
        }
    }

    /// Linux `__dma_alloc_from_coherent`: a zeroed, naturally aligned
    /// power-of-two page run whose every byte is at a bus address
    /// `<= dma_mask`.
    fn alloc(
        self: &Arc<Self>,
        len: usize,
        domain: DomainId,
        dma_mask: u64,
    ) -> Result<DmaBuffer, IoError> {
        let page = PAGE_SIZE as usize;
        if len == 0 {
            return Err(IoError::NoMemory);
        }
        let order = len.div_ceil(page).next_power_of_two().trailing_zeros();
        if order >= usize::BITS || (1usize << order) > self.pages {
            return Err(IoError::NoMemory);
        }
        let order = order as u8;
        let first = self.take(order).ok_or(IoError::NoMemory)?;
        let bytes = page << order;
        let offset = first * page;
        let phys = self.phys + offset as u64;
        if phys + (bytes as u64 - 1) > dma_mask {
            self.release(first, order);
            return Err(IoError::NoMemory);
        }
        let cpu = self.virt + offset;
        // SAFETY: the run is inside the pool's live mapping and was just
        // claimed exclusively in the bitmap. Linux memsets pool memory too.
        unsafe { core::ptr::write_bytes(cpu as *mut u8, 0, bytes) };
        Ok(DmaBuffer {
            phys: PhysAddr::new(phys),
            len: bytes,
            order,
            domain,
            coherency: Coherency::Coherent,
            freed: false,
            slot_index: None,
            cpu_base: core::num::NonZeroUsize::new(cpu),
            pool: Some((self.clone(), first)),
            iommu: None,
        })
    }
}

/// The DMA facts Linux keeps on `struct device` (`dma_coherent`,
/// `dma_mem`) plus the global default pool a non-coherent device falls back
/// to. Built by bus code from firmware (`narf_bus::dma::configure`).
#[derive(Clone, Debug)]
pub struct DmaDevice {
    coherence: DmaCoherence,
    pool: Option<Arc<CoherentPool>>,
    /// The device's IOMMU DMA domain in `IommuMode::PerDomain` (Linux
    /// `iommu_get_dma_domain(dev)`); `None` = DMA addresses are physical.
    iommu: Option<Arc<crate::iommu::IommuDomain>>,
}

impl DmaDevice {
    /// A snooping device with no pool: exactly [`crate::alloc_coherent`].
    pub const fn coherent() -> Self {
        Self {
            coherence: DmaCoherence::Coherent,
            pool: None,
            iommu: None,
        }
    }

    /// Linux `dma_alloc_attrs` pool selection: the device's own
    /// `memory-region` pool always wins; a non-coherent device without one
    /// uses the global default pool (`DMA_GLOBAL_POOL`); a coherent device
    /// never does.
    pub fn new(
        coherence: DmaCoherence,
        device_pool: Option<Arc<CoherentPool>>,
        default_pool: Option<Arc<CoherentPool>>,
    ) -> Self {
        let pool = match (device_pool, coherence) {
            (Some(pool), _) => Some(pool),
            (None, DmaCoherence::NonCoherent) => default_pool,
            (None, DmaCoherence::Coherent) => None,
        };
        Self {
            coherence,
            pool,
            iommu: None,
        }
    }

    /// Route this device's DMA through `domain`: every
    /// [`alloc_coherent_for`] buffer is mapped there and its
    /// `dma_addr()` is the IOVA.
    pub fn with_iommu_domain(mut self, domain: Arc<crate::iommu::IommuDomain>) -> Self {
        self.iommu = Some(domain);
        self
    }

    /// The device's IOMMU DMA domain, if it translates.
    pub fn iommu_domain(&self) -> Option<&Arc<crate::iommu::IommuDomain>> {
        self.iommu.as_ref()
    }

    pub fn coherence(&self) -> DmaCoherence {
        self.coherence
    }

    /// The pool this device allocates coherent memory from, if any.
    pub fn pool(&self) -> Option<&Arc<CoherentPool>> {
        self.pool.as_ref()
    }
}

/// Linux `dma_alloc_coherent(dev, …)` after `dma_set_coherent_mask(dev,
/// dma_mask)`: [`crate::alloc_coherent_masked`] for a coherent device
/// without a pool (bit-identical), the device's reserved pool otherwise, and
/// [`IoError::NoCoherentPool`] for a non-coherent device without one.
///
/// With an IOMMU domain ([`DmaDevice::with_iommu_domain`]) this is Linux
/// `iommu_dma_alloc`: the frames may lie anywhere, `dma_mask` bounds the
/// IOVA instead, and the buffer's `dma_addr()` is that IOVA. In
/// `IommuMode::PerDomain` a device without a domain is refused
/// (`NotMapped`): its physical addresses would fault.
pub fn alloc_coherent_for(
    dev: &DmaDevice,
    len: usize,
    domain: DomainId,
    dma_mask: u64,
) -> Result<DmaBuffer, IoError> {
    let phys_mask = match &dev.iommu {
        Some(_) => u64::MAX,
        None if crate::iommu::mode() == crate::iommu::IommuMode::PerDomain => {
            return Err(IoError::NotMapped)
        }
        None => dma_mask,
    };
    let mut buf = match (&dev.pool, dev.coherence) {
        (Some(pool), _) => pool.alloc(len, domain, phys_mask)?,
        (None, DmaCoherence::Coherent) => {
            let mask = (phys_mask != u64::MAX).then_some(phys_mask);
            alloc_with(len, domain, Coherency::Coherent, mask)?
        }
        (None, DmaCoherence::NonCoherent) => return Err(IoError::NoCoherentPool),
    };
    if let Some(iommu) = &dev.iommu {
        // On failure `buf` drops and returns its frames: nothing was mapped.
        buf.map_into(iommu, dma_mask, true)?;
    }
    Ok(buf)
}
