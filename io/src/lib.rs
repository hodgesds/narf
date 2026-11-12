//! narf-io — DMA buffers, IOMMU context, P2P DMA.
//!
//! Spec: `io/specification/spec.md`. Stage-3 Wave-3a subset: just enough
//! of the DMA-buffer lifecycle to hand a driver a `Cap<DmaBuffer, _>` and
//! let the driver framework thread it into `DriverEnv`. The full IOMMU
//! programming + P2P routing story is later waves.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod amd_vi;
mod amd_vi_tests;
pub mod coherent_pool;
mod coherent_pool_tests;
pub mod iommu;
mod iommu_e2e_tests;
#[doc(hidden)]
pub mod iommu_model;
mod iommu_perdomain_tests;
pub mod iova;
pub mod pool;
pub mod sg;
mod tests;

use core::fmt;

use alloc::sync::Arc;
use alloc::vec::Vec;
pub use coherent_pool::{alloc_coherent_for, CoherentPool, DmaCoherence, DmaDevice};
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_capabilities::{Cap, CapError, CapKind, CapOp, CapType};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{
    alloc_pages_below, alloc_pages_on, free_pages, FrameAllocError, PhysAddr, PhysFrame, PAGE_SIZE,
};

// ── Operations ──────────────────────────────────────────────────────

/// Resolve a DmaBuffer's physical address.
#[derive(Copy, Clone, Debug, Default)]
pub struct GetPhysAddr;

impl<R: narf_capabilities::Rights> CapOp<DmaBuffer, R> for GetPhysAddr {
    type Output = PhysAddr;
    fn execute(self, cap: &Cap<DmaBuffer, R>) -> Result<Self::Output, CapError> {
        resolve(cap.slot().index)
            .map(|b| b.phys_addr())
            .ok_or(CapError::Revoked)
    }
}

// ── Registry ────────────────────────────────────────────────────────
//
// The registry is the cap → buffer indirection that makes
// `BlockRequest::buffer: Cap<DmaBuffer, _>` actually mean "this
// is the buffer to DMA against". A device's `submit()` does:
//
//   let buf = narf_io::resolve(req.buffer.slot().index)?;
//   // …copy into / out of buf.as_slice()…
//
// `register_with_cap(buf)` reserves an object-table slot for the
// buffer and returns a `Cap<DmaBuffer, Write>` whose `slot.index`
// is the registry index. The registry holds the only `Arc` to the
// buffer until either `unregister(cap)` is called explicitly or
// the cap is revoked (`cap.revoke()` bumps the epoch, which
// strictly invalidates all outstanding caps but does not free
// the registry slot — call `unregister` for that). Drop the cap
// without calling `unregister` and the buffer leaks; the API is
// explicit on this point because BlockRequest sometimes outlives
// the cap that authorised it (the device's queue still holds the
// completion in flight).

static REGISTRY: IrqSafeSpinLock<Vec<Option<Registered>>> = IrqSafeSpinLock::new(Vec::new());

/// What a registry slot holds: the object its cap kind names.
#[derive(Clone)]
enum Registered {
    Buffer(Arc<DmaBuffer>),
    Pages(Arc<sg::PageList>),
}

/// Register `buf` in the cap → buffer registry and mint a
/// `Cap<DmaBuffer, Write>` that points at it. The cap's
/// `slot.index` is the registry slot, so devices can `resolve()`
/// back to the buffer from a `BlockRequest::buffer` field.
pub fn register_with_cap(mut buf: DmaBuffer) -> Cap<DmaBuffer, narf_capabilities::Write> {
    // `Cap::bootstrap` registers a fresh DmaBuffer object-table entry
    // and mints the cap for it (SEC-B5, #1293: `Cap::mint` is
    // crate-private to `capabilities/`, so this is the only way to
    // mint from outside the crate). The slot's generation is 1 for a
    // fresh entry — the same value the old hand-built slot read back
    // via `current_epoch` — and `slot.index` is the registry index.
    let cap: Cap<DmaBuffer, narf_capabilities::Write> = Cap::bootstrap();
    let index = cap.slot().index;
    buf.slot_index = Some(index);
    let mut r = REGISTRY.lock();
    if (index as usize) >= r.len() {
        r.resize(index as usize + 1, None);
    }
    r[index as usize] = Some(Registered::Buffer(Arc::new(buf)));
    cap
}

/// Register a page list and mint a `Cap<PageList, Write>` for it, the
/// scatter-gather sibling of [`register_with_cap`]: the cap's `slot.index`
/// is the registry slot a block device resolves back to the list.
pub fn register_pages_with_cap(list: sg::PageList) -> Cap<sg::PageList, narf_capabilities::Write> {
    let cap: Cap<sg::PageList, narf_capabilities::Write> = Cap::bootstrap();
    let index = cap.slot().index;
    let mut r = REGISTRY.lock();
    if (index as usize) >= r.len() {
        r.resize(index as usize + 1, None);
    }
    r[index as usize] = Some(Registered::Pages(Arc::new(list)));
    cap
}

/// Revoke a page-list cap and free its registry slot (see [`unregister`]).
/// The list — and its IOMMU mappings — go when the last `Arc` drops, i.e.
/// after every command in flight over it has completed.
pub fn unregister_pages<R: narf_capabilities::Rights>(cap: Cap<sg::PageList, R>) {
    unregister_by_index(cap.slot().index);
}

/// Cap-gated resolve of a page list: `None` if the cap is revoked, the
/// slot is empty or holds a buffer instead.
pub fn resolve_pages_cap<R: narf_capabilities::Rights>(
    cap: &Cap<sg::PageList, R>,
) -> Option<Arc<sg::PageList>> {
    cap.check_live().ok()?;
    let r = REGISTRY.lock();
    match r.get(cap.slot().index as usize) {
        Some(Some(Registered::Pages(l))) => Some(l.clone()),
        _ => None,
    }
}

/// Revoke the cap and free the registry slot. After this call
/// every other cap referencing the same slot fails `check_live()`.
/// The buffer's frame is freed when the last `Arc<DmaBuffer>` ref
/// drops (typically immediately if no in-flight `resolve()` Arc is
/// held).
pub fn unregister<R: narf_capabilities::Rights>(cap: Cap<DmaBuffer, R>) {
    let index = cap.slot().index;
    let _ = narf_capabilities::object_table::bump_epoch(index);
    let mut r = REGISTRY.lock();
    if let Some(slot) = r.get_mut(index as usize) {
        *slot = None;
    }
}

/// Index-keyed counterpart to `unregister`. Used by the driver
/// framework's reclaim path to drop a `Cap<DmaBuffer, _>`'s backing
/// without the framework having to round-trip through the typed cap.
/// Bumps the object-table epoch (so every outstanding cap fails
/// `check_live`) and clears the registry slot.
pub fn unregister_by_index(index: u32) {
    let _ = narf_capabilities::object_table::bump_epoch(index);
    let mut r = REGISTRY.lock();
    if let Some(slot) = r.get_mut(index as usize) {
        *slot = None;
    }
}

/// Resolve a capability slot index to the underlying DmaBuffer.
/// Returns `None` if the index never existed or has been
/// `unregister`-ed.
pub fn resolve(index: u32) -> Option<Arc<DmaBuffer>> {
    let r = REGISTRY.lock();
    match r.get(index as usize) {
        Some(Some(Registered::Buffer(b))) => Some(b.clone()),
        _ => None,
    }
}

/// Cap-gated resolve: returns `None` if the cap is revoked, the
/// registry slot is empty, or the slot index is out of range.
pub fn resolve_cap<R: narf_capabilities::Rights>(
    cap: &Cap<DmaBuffer, R>,
) -> Option<Arc<DmaBuffer>> {
    cap.check_live().ok()?;
    resolve(cap.slot().index)
}

// ── Errors ──────────────────────────────────────────────────────────

/// Why an `io/` call failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoError {
    NoMemory,
    DomainMismatch,
    OutOfIova,
    NotMapped,
    /// A non-coherent device has no reserved coherent pool. NARF never
    /// remaps System RAM non-cacheable (see `memory/src/memtype.rs`), so it
    /// fails closed instead of handing out write-back memory.
    NoCoherentPool,
    /// A page list with no pages, unaligned frames or fewer frames than
    /// its length needs.
    InvalidPageList,
    /// A reserved DMA pool range was refused: unaligned, empty, overlapping
    /// another pool, or intersecting System RAM.
    PoolRejected,
    /// An IOMMU command (invalidation + completion wait) did not complete
    /// in time; the affected translation must be treated as live.
    Timeout,
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IoError::NoMemory => f.write_str("io: no contiguous DMA memory available"),
            IoError::DomainMismatch => f.write_str("io: buffer domain mismatch"),
            IoError::OutOfIova => f.write_str("io: no IOVA window available"),
            IoError::NotMapped => f.write_str("io: not mapped"),
            IoError::NoCoherentPool => {
                f.write_str("io: non-coherent device has no reserved DMA pool")
            }
            IoError::InvalidPageList => f.write_str("io: page list is empty, unaligned or short"),
            IoError::PoolRejected => f.write_str("io: reserved DMA pool range refused"),
            IoError::Timeout => f.write_str("io: IOMMU command completion timed out"),
        }
    }
}

impl From<FrameAllocError> for IoError {
    fn from(_e: FrameAllocError) -> Self {
        IoError::NoMemory
    }
}

// ── DmaBuffer ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Coherency {
    Coherent,
    Streaming,
}

pub struct DmaBuffer {
    phys: PhysAddr,
    len: usize,
    /// Buddy allocation order (`1 << order` frames). Recorded so `Drop` /
    /// `free_coherent` return the whole contiguous block, not just the head.
    order: u8,
    domain: DomainId,
    coherency: Coherency,
    freed: bool,
    /// Object-table slot index assigned by [`register_with_cap`].
    /// `None` until the buffer is registered. The `(slot_index,
    /// epoch)` pair is what a `Cap<DmaBuffer, _>` stores in its
    /// `slot` field — that's how a device's `submit()` can resolve
    /// the cap back to *this* buffer's `PhysAddr` + length.
    slot_index: Option<u32>,
    /// Kernel virtual base of a reserved-pool buffer (Linux
    /// `dma_coherent_mem::virt_base` + page offset). `None` for buddy
    /// buffers, whose CPU view is the direct map.
    cpu_base: Option<core::num::NonZeroUsize>,
    /// Reserved pool and first page this buffer occupies; released to the
    /// pool (never the buddy) on drop.
    pool: Option<(Arc<CoherentPool>, usize)>,
    /// Per-domain IOMMU mapping `(domain, iova)` when the buffer was
    /// allocated for a device in [`iommu::IommuMode::PerDomain`]
    /// (Linux `iommu_dma_alloc` → `__iommu_dma_map`). The device sees
    /// `iova`, never `phys`.
    /// Boxed so `DmaBuffer` does not grow for the common unmapped case.
    iommu: Option<alloc::boxed::Box<(Arc<iommu::IommuDomain>, u64)>>,
}

impl fmt::Debug for DmaBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DmaBuffer")
            .field("phys", &self.phys)
            .field("len", &self.len)
            .field("domain", &self.domain)
            .field("coherency", &self.coherency)
            .field("pool_backed", &self.pool.is_some())
            .field("iova", &self.iommu.as_deref().map(|(_, iova)| *iova))
            .finish_non_exhaustive()
    }
}

/// A **device-side** DMA address: what hardware dereferences.
///
/// Deliberately opaque. There is no method on this type that yields a
/// pointer, so a driver cannot dereference it — the CPU-side view comes
/// from [`DmaBuffer::cpu_ptr`] / [`DmaBuffer::cpu_mut_ptr`] instead.
///
/// This is Linux's `dma_addr_t` discipline (see `Documentation/core-api/
/// dma-api.txt`): `dma_alloc_coherent` hands back a CPU pointer *and* a
/// separate `dma_addr_t`, and the two are never interchangeable. Rust can
/// enforce what C only annotates — mixing them here is a compile error,
/// not a sparse warning.
///
/// It exists because the alternative cost real bugs. While RAM was
/// identity-mapped, `buf.dma_addr().raw() as *mut u8` both compiled and
/// worked, so ~220 driver sites dereferenced device addresses directly.
/// Every one of them became a kernel #PF the moment user address spaces
/// stopped carrying the identity map.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DmaAddr(u64);

impl DmaAddr {
    /// The raw bus address, for programming into a descriptor field or a
    /// device register. This is the ONLY way out of the newtype, and it
    /// yields a `u64` — never a pointer.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Address of a sub-range, for ring/descriptor arithmetic. Keeping
    /// this in the type is what stops drivers dropping to `raw() + off`
    /// and re-opening the hole.
    #[inline]
    pub const fn offset(self, bytes: u64) -> Self {
        Self(self.0 + bytes)
    }
}

impl fmt::Debug for DmaAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DmaAddr({:#x})", self.0)
    }
}

impl DmaBuffer {
    /// The address to hand the DEVICE. Program this into descriptors and
    /// registers; it cannot be dereferenced (see [`DmaAddr`]).
    #[inline]
    pub fn dma_addr(&self) -> DmaAddr {
        match self.iommu.as_deref() {
            Some((_, iova)) => DmaAddr(*iova),
            None => DmaAddr(self.phys.raw()),
        }
    }

    /// Device-side address of a sub-range, for ring arithmetic.
    #[inline]
    pub fn dma_addr_at(&self, offset: u64) -> DmaAddr {
        self.dma_addr().offset(offset)
    }

    /// The pointer the CPU should use, resolved through the kernel direct
    /// map (x86_64) / TTBR1 high-half window (aarch64). Valid in every
    /// address space, so it survives a user CR3/TTBR0 swap.
    ///
    /// A reserved-pool buffer (non-coherent device, see [`coherent_pool`])
    /// resolves through the pool's own non-cacheable mapping instead.
    #[inline]
    pub fn cpu_ptr<T>(&self) -> *const T {
        if let Some(base) = self.cpu_base.map(core::num::NonZeroUsize::get) {
            return base as *const T;
        }
        self.phys.kernel_ptr::<T>()
    }

    /// Mutable counterpart to [`Self::cpu_ptr`]. Takes `&self` for the
    /// same reason as [`Self::as_byte_ptr`]: a `DmaBuffer` is usually held
    /// behind an `Arc`, and the device may write into it while the CPU
    /// holds only a shared reference.
    #[inline]
    pub fn cpu_mut_ptr<T>(&self) -> *mut T {
        if let Some(base) = self.cpu_base.map(core::num::NonZeroUsize::get) {
            return base as *mut T;
        }
        self.phys.kernel_mut_ptr::<T>()
    }

    /// Const CPU pointer at a byte offset.
    #[inline]
    pub fn cpu_ptr_at<T>(&self, offset: u64) -> *const T {
        if let Some(base) = self.cpu_base.map(core::num::NonZeroUsize::get) {
            return (base + offset as usize) as *const T;
        }
        crate::PhysAddr::new(self.phys.raw() + offset).kernel_ptr::<T>()
    }

    /// CPU pointer at a byte offset — the counterpart to
    /// [`Self::dma_addr_at`] for descriptor-ring walks.
    #[inline]
    pub fn cpu_mut_ptr_at<T>(&self, offset: u64) -> *mut T {
        if let Some(base) = self.cpu_base.map(core::num::NonZeroUsize::get) {
            return (base + offset as usize) as *mut T;
        }
        crate::PhysAddr::new(self.phys.raw() + offset).kernel_mut_ptr::<T>()
    }

    /// Physical base.
    ///
    /// Prefer [`Self::dma_addr`] for the device side and
    /// [`Self::cpu_mut_ptr`] for the CPU side. This accessor is what let
    /// `.raw() as *mut _` become the path of least resistance across the
    /// driver tree; it stays for callers that genuinely need a
    /// `PhysAddr` (page-table and IOMMU plumbing) and will be narrowed
    /// once the remaining drivers move to the typed pair.
    #[inline]
    pub fn phys_addr(&self) -> PhysAddr {
        self.phys
    }

    /// Write back and invalidate the CPU cache lines covering
    /// `offset..offset + len` (clamped to the buffer), for a device that does
    /// not snoop CPU caches: call it after CPU writes the device will read,
    /// and before CPU reads of what the device wrote. Linux maps such buffers
    /// uncached instead (e.g. HD-Audio's `AZX_DCAPS_SNOOP_OFF`); buddy
    /// allocations here are write-back, so maintenance is explicit. Prefer the
    /// directional [`Self::sync_for_device`] / [`Self::sync_for_cpu`] pair.
    pub fn sync(&self, offset: usize, len: usize) {
        if let Some((start, end)) = self.sync_range(offset, len) {
            cache_clean_invalidate(start, end);
        }
    }

    /// Linux `dma_sync_single_for_device` → arm64 `arch_sync_dma_for_device`
    /// (`arch/arm64/mm/dma-mapping.c`): clean `offset..offset + len` to the
    /// point of coherency so a non-snooping device reads what the CPU wrote.
    /// The direction is ignored there too — a FROM_DEVICE buffer is cleaned
    /// so no dirty line can later be evicted over the device's data.
    /// x86_64 has no clean-only baseline instruction; it flushes (CLFLUSH).
    pub fn sync_for_device(&self, offset: usize, len: usize, _dir: DmaDirection) {
        if let Some((start, end)) = self.sync_range(offset, len) {
            cache_clean(start, end);
        }
    }

    /// Linux `dma_sync_single_for_cpu` → arm64 `arch_sync_dma_for_cpu`:
    /// nothing for [`DmaDirection::ToDevice`], otherwise invalidate
    /// `offset..offset + len` so the CPU reads what the device wrote. Partial
    /// lines at either end are cleaned and invalidated rather than discarded
    /// (`dcache_inval_poc`), so neighbouring CPU data survives.
    pub fn sync_for_cpu(&self, offset: usize, len: usize, dir: DmaDirection) {
        if dir == DmaDirection::ToDevice {
            return;
        }
        if let Some((start, end)) = self.sync_range(offset, len) {
            cache_invalidate(start, end);
        }
    }

    /// CPU virtual `[start, end)` of `offset..offset + len`, clamped.
    fn sync_range(&self, offset: usize, len: usize) -> Option<(usize, usize)> {
        let end = offset.saturating_add(len).min(self.len);
        if offset >= end {
            return None;
        }
        let base = self.cpu_ptr::<u8>() as usize;
        Some((base + offset, base + end))
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn domain(&self) -> DomainId {
        self.domain
    }

    #[inline]
    pub fn coherency(&self) -> Coherency {
        self.coherency
    }

    /// Borrow the buffer's contents as bytes. Identity-mapped
    /// physical memory backs the slice — see `alloc_with` for the
    /// safety argument that the mapping is live.
    ///
    /// # Safety contract
    /// The slice's lifetime is tied to `&self`; the buffer's frame
    /// is freed in `Drop` so no caller can outlive the backing
    /// memory.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `kernel_ptr` resolves through the kernel's
        // identity map (x86_64) or TTBR1 high-half RAM window
        // (aarch64), so the slice stays valid across user-task
        // TTBR0/CR3 swaps. `len` is the buffer's true length and
        // `&self` keeps the buffer alive across this borrow.
        // SAFETY: Valid memory or trusted environment
        unsafe { core::slice::from_raw_parts(self.cpu_ptr::<u8>(), self.len) }
    }

    /// Mutable byte view. Same kernel-mapping argument as
    /// [`Self::as_slice`].
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: see `as_slice` — the unique-mut borrow comes from
        // `&mut self`, so no aliasing is possible.
        // SAFETY: Valid memory or trusted environment
        unsafe { core::slice::from_raw_parts_mut(self.cpu_mut_ptr::<u8>(), self.len) }
    }

    /// Read this buffer's object-table slot index, if it has been
    /// registered via [`register_with_cap`]. Devices use this to
    /// resolve a `BlockRequest::buffer` cap back to the buffer.
    #[inline]
    pub fn slot_index(&self) -> Option<u32> {
        self.slot_index
    }

    /// Raw byte pointer into the kernel-mapped buffer region.
    /// Lifted to `&self` (not `&mut self`) because a `DmaBuffer`
    /// is normally accessed through an `Arc` from the registry —
    /// the device may DMA-write into it while a CPU-side observer
    /// only holds a shared reference. Resolves through the kernel
    /// identity map (x86_64) or TTBR1 high-half (aarch64), so the
    /// pointer stays valid across user-task page-table swaps.
    ///
    /// # Safety
    /// Callers must serialise CPU-side mutation against any
    /// concurrent device access. The cooperative single-CPU
    /// executor makes this trivial — copy in / out without
    /// yielding mid-borrow.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.cpu_ptr::<u8>()
    }

    /// See [`Self::as_ptr`].
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.cpu_mut_ptr::<u8>()
    }

    /// Whether this buffer came from a reserved coherent pool (mapped
    /// non-cacheable) rather than the buddy allocator's write-back RAM.
    #[inline]
    pub fn is_pool_backed(&self) -> bool {
        self.pool.is_some()
    }

    /// IOMMU domain ID this buffer is mapped in, when its DMA address
    /// is a per-domain IOVA rather than the physical address.
    #[inline]
    pub fn iommu_domain_id(&self) -> Option<u16> {
        self.iommu.as_deref().map(|(d, _)| d.domain_id())
    }

    /// Map this buffer into `domain` (read/write) with an IOVA at or
    /// below `dma_mask`, making [`Self::dma_addr`] return the IOVA.
    pub(crate) fn map_into(
        &mut self,
        domain: &Arc<iommu::IommuDomain>,
        dma_mask: u64,
        pci: bool,
    ) -> Result<(), IoError> {
        if self.iommu.is_some() {
            return Err(IoError::DomainMismatch);
        }
        let iova = domain.map_below(
            self.phys.raw(),
            self.len as u64,
            iommu::IommuPerms::READ_WRITE,
            dma_mask,
            pci,
        )?;
        self.iommu = Some(alloc::boxed::Box::new((domain.clone(), iova)));
        Ok(())
    }

    /// Return the storage to its owner exactly once. A per-domain IOVA
    /// is torn down first (PTE clear → IOTLB invalidate + wait → IOVA
    /// free); if that invalidation fails the frames are leaked rather
    /// than reused, since the device may still translate to them.
    fn release(&mut self) {
        if self.freed {
            return;
        }
        self.freed = true;
        if let Some(mapping) = self.iommu.take() {
            let (domain, iova) = *mapping;
            if domain.unmap(iova, self.len as u64).is_err() {
                self.pool = None;
                return;
            }
        }
        match self.pool.take() {
            Some((pool, page)) => pool.release(page, self.order),
            None => free_pages(PhysFrame::new(self.phys), self.order),
        }
    }
}

impl CapType for DmaBuffer {
    const KIND: CapKind = CapKind::DmaBuffer;
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        self.release();
    }
}

/// Linux `enum dma_data_direction` for streaming-buffer cache maintenance.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmaDirection {
    /// `DMA_BIDIRECTIONAL`.
    Bidirectional,
    /// `DMA_TO_DEVICE`: the device only reads the buffer.
    ToDevice,
    /// `DMA_FROM_DEVICE`: the device only writes the buffer.
    FromDevice,
}

/// Smallest data-cache line in bytes (aarch64 `CTR_EL0.DminLine`, Linux
/// `dcache_line_size`).
#[cfg(target_arch = "aarch64")]
fn dcache_line() -> usize {
    let ctr: u64;
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    // SAFETY: CTR_EL0 is readable at EL1.
    unsafe { core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    4usize << ((ctr >> 16) & 0xf)
}

/// x86_64: CLFLUSH every 64-byte line of `start..end` between MFENCEs.
#[cfg(target_arch = "x86_64")]
fn clflush_range(start: usize, end: usize) {
    let mut line = start & !63;
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    // SAFETY: fences and CLFLUSH of the caller's mapped buffer lines.
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
        while line < end {
            core::arch::asm!("clflush [{}]", in(reg) line, options(nostack, preserves_flags));
            line += 64;
        }
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// Clean and invalidate every data-cache line touching `start..end`, then
/// order the maintenance before later device-visible accesses.
pub(crate) fn cache_clean_invalidate(start: usize, end: usize) {
    #[cfg(target_arch = "x86_64")]
    clflush_range(start, end);
    #[cfg(target_arch = "aarch64")]
    {
        let step = dcache_line();
        let mut line = start & !(step - 1);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        // SAFETY: DC CIVAC of the caller's mapped buffer lines, then DSB.
        unsafe {
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
            while line < end {
                core::arch::asm!("dc civac, {}", in(reg) line, options(nostack, preserves_flags));
                line += step;
            }
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

/// Linux arm64 `dcache_clean_poc`: DC CVAC every line of `start..end`.
fn cache_clean(start: usize, end: usize) {
    #[cfg(target_arch = "x86_64")]
    clflush_range(start, end);
    #[cfg(target_arch = "aarch64")]
    {
        let step = dcache_line();
        let mut line = start & !(step - 1);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        // SAFETY: DC CVAC of the caller's mapped buffer lines, then DSB.
        unsafe {
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
            while line < end {
                core::arch::asm!("dc cvac, {}", in(reg) line, options(nostack, preserves_flags));
                line += step;
            }
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

/// Linux arm64 `dcache_inval_poc`: DC IVAC whole lines of `start..end`, but
/// DC CIVAC a partial first or last line so bytes outside the range that
/// share it are written back rather than discarded.
fn cache_invalidate(start: usize, end: usize) {
    #[cfg(target_arch = "x86_64")]
    clflush_range(start, end);
    #[cfg(target_arch = "aarch64")]
    {
        let step = dcache_line();
        let mask = step - 1;
        let first = start & !mask;
        let last = end & !mask;
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        // SAFETY: DC (C)IVAC of the caller's mapped, writable buffer lines,
        // then DSB. Partial edge lines are cleaned first, so no byte outside
        // `start..end` is lost.
        unsafe {
            if end & mask != 0 {
                core::arch::asm!("dc civac, {}", in(reg) last, options(nostack, preserves_flags));
            }
            let mut line = first;
            if start & mask != 0 {
                core::arch::asm!("dc civac, {}", in(reg) first, options(nostack, preserves_flags));
                line += step;
            }
            while line < last {
                core::arch::asm!("dc ivac, {}", in(reg) line, options(nostack, preserves_flags));
                line += step;
            }
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

pub fn alloc_coherent(len: usize, domain: DomainId) -> Result<DmaBuffer, IoError> {
    alloc_with(len, domain, Coherency::Coherent, None)
}

/// `alloc_coherent` for a device whose coherent DMA mask is `dma_mask`
/// (Linux `dma_set_coherent_mask(dev, dma_mask)` + `dma_alloc_coherent`):
/// every byte of the returned buffer lies at a bus address `<= dma_mask`.
/// A mask no free RAM satisfies is `Err(NoMemory)`, never a buffer above
/// the mask. `dma_mask = u64::MAX` is exactly [`alloc_coherent`].
///
/// NARF hands devices physical addresses (no IOMMU remap on this path),
/// so the bus address is the physical address.
pub fn alloc_coherent_masked(
    len: usize,
    domain: DomainId,
    dma_mask: u64,
) -> Result<DmaBuffer, IoError> {
    let mask = if dma_mask == u64::MAX {
        None
    } else {
        Some(dma_mask)
    };
    alloc_with(len, domain, Coherency::Coherent, mask)
}

pub fn free_coherent(mut buf: DmaBuffer) {
    buf.release();
}

/// Largest single coherent DMA buffer, expressed as a buddy order.
///
/// order 10 = 1024 pages = 4 MiB. This admits one 1280×800 XRGB8888 virtio
/// scanout (and the corresponding transient upload buffer) while retaining
/// the simple single-segment DMA contract used by the existing drivers. It is
/// intentionally not a general VRAM allocator: larger or fragmented 3D
/// resources use the virtio-gpu backing-list path rather than raising this
/// buddy allocation ceiling again.
const MAX_DMA_ORDER: u8 = 10;

fn alloc_with(
    len: usize,
    domain: DomainId,
    coherency: Coherency,
    dma_mask: Option<u64>,
) -> Result<DmaBuffer, IoError> {
    let page = PAGE_SIZE as usize;
    if len == 0 {
        return Err(IoError::NoMemory);
    }
    // Gate for the late per-domain opt-in (`iommu::init`): physical DMA
    // addresses may now be in a device's hands.
    iommu::note_dma_issued();
    // Round the request up to a power-of-two page count and allocate that
    // many PHYSICALLY-CONTIGUOUS frames from the buddy, so a device can DMA
    // the whole buffer through a single (phys, len) descriptor — the block
    // driver reads up to 64 KiB per virtio round-trip instead of one page.
    let pages = len.div_ceil(page);
    let order = pages.next_power_of_two().trailing_zeros() as u8;
    if order > MAX_DMA_ORDER {
        return Err(IoError::NoMemory);
    }
    let alloc_bytes = page << order;

    let frame = match dma_mask {
        None => alloc_pages_on(0, order)?,
        Some(mask) => alloc_pages_below(order, mask)?,
    };
    let phys = frame.start_address();
    if let Some(mask) = dma_mask {
        // Defence in depth: the allocator contract says this cannot
        // happen; a device given such a buffer would DMA elsewhere.
        if phys.raw() + (alloc_bytes as u64 - 1) > mask {
            free_pages(frame, order);
            return Err(IoError::NoMemory);
        }
    }
    // Zero-fill the buffer. `alloc_pages_on` returns recycled frames
    // un-zeroed; drivers that build descriptor rings, completion
    // queues, or any phase-tagged structure on top of the buffer
    // rely on starting from a known-zero state. Without this,
    // stale phase bits / used-ring entries / status words from a
    // previous tenant cause non-deterministic init failures
    // (NVMe identify VID mismatch, virtio control-vq wedge, etc.)
    // depending on which test ran before.
    //
    // SAFETY: `phys` is a freshly allocated page; the kernel
    // accesses it through the per-arch kernel mapping
    // (`kernel_mut_ptr`) — identity on x86_64, TTBR1 high-half on
    // aarch64 — so the write stays valid even when the calling
    // thread is in a user-task TTBR0/CR3 context.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, alloc_bytes);
    }
    Ok(DmaBuffer {
        phys,
        len: alloc_bytes,
        order,
        domain,
        coherency,
        freed: false,
        slot_index: None,
        cpu_base: None,
        pool: None,
        iommu: None,
    })
}

pub struct IommuContext {
    domain: DomainId,
    mappings: AtomicUsize,
}

impl fmt::Debug for IommuContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IommuContext")
            .field("domain", &self.domain)
            .field("mappings", &self.mappings.load(Ordering::Relaxed))
            .finish()
    }
}

impl IommuContext {
    pub const fn new(domain: DomainId) -> Self {
        Self {
            domain,
            mappings: AtomicUsize::new(0),
        }
    }

    pub fn domain(&self) -> DomainId {
        self.domain
    }

    pub fn mapping_count(&self) -> usize {
        self.mappings.load(Ordering::Relaxed)
    }

    /// Translate a buffer's host-physical address into a device-
    /// usable IOVA via the active IOMMU backend. In identity
    /// mode (the only mode active right now) the IOVA equals
    /// the buffer's `phys`. The `fixed_iova` argument is
    /// retained as a hint for future per-domain modes that may
    /// honour caller-chosen virtual addresses; identity mode
    /// ignores it.
    pub fn map(&self, buf: &DmaBuffer, fixed_iova: u64) -> Result<u64, IoError> {
        if buf.domain() != self.domain {
            return Err(IoError::DomainMismatch);
        }
        let iova = match iommu::mode() {
            iommu::IommuMode::Disabled => fixed_iova.max(buf.phys.as_u64()),
            iommu::IommuMode::Identity => iommu::map_phys(buf.phys.as_u64())?,
            iommu::IommuMode::PerDomain => return Err(IoError::NotMapped),
        };
        self.mappings.fetch_add(1, Ordering::Relaxed);
        Ok(iova)
    }

    pub fn unmap(&self, iova: u64, _len: usize) -> Result<(), IoError> {
        let prev = self.mappings.fetch_sub(1, Ordering::Relaxed);
        if prev == 0 {
            self.mappings.fetch_add(1, Ordering::Relaxed); // restore
            return Err(IoError::NotMapped);
        }
        // Identity / disabled paths don't actually touch
        // hardware; per-domain mode walks the table.
        let _ = iommu::unmap_iova(iova)?;
        Ok(())
    }
}

pub fn p2p_map(_src: &DmaBuffer, _dst_device: DomainId) -> Result<u64, IoError> {
    Err(IoError::NotMapped)
}
